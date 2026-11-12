# frozen_string_literal: true

require 'json'

module PWN
  module SDR
    module Decoder
      # LoRa (Semtech CSS) raw PHY payload decoder and separate detector.
      # .decode supports SF7-12, CR4/5..4/8, explicit/implicit headers, optional
      # payload CRC, LDRO and normal/inverted IQ at sample_rate >= BW.
      # Raw payload bytes only: no LoRaWAN decryption or clock-drift tracking.
      # The following preamble-only description applies to .detect.
      #
      # I/Q resampled so fs = BW (default 125 kHz), one complex sample per
      # chirp step. For each SF ∈ 7..12: dechirp with a reference
      # down-chirp (DSP.cmul + PWN::FFI::FFTW.cfft), find ≥6 consecutive
      # symbols whose FFT-argmax bin is identical (preamble), then read
      # the two sync-word symbols and two SFD down-chirps. Emits
      # {sf:, bw_hz:, sync_word:, preamble_len:, cfo_bins:}. This is
      # preamble/sync metadata only, not LoRa payload decoding.
      module LoRa
        DEFAULT_BW = 125_000
        SF_RANGE   = (7..12)
        # Public LoRaWAN sync = 0x34; private/Meshtastic default = 0x12.
        KNOWN_SYNC = { 0x34 => 'LoRaWAN', 0x12 => 'private/RadioLib' }.freeze

        # Streaming CSS dechirp demod for Base.run_iq.
        class DemodIQ
          def initialize(rate:, bw: DEFAULT_BW)
            @rate = rate.to_f
            @bw   = bw.to_i
            @buf  = []
            @dchirp = {}
            @seen = {}
          end

          def feed_iq(samples, rate: nil, &emit)
            @rate = rate.to_f if rate
            @input ||= []
            @input.concat(samples)
            window = [(@rate * 0.001).round, 1].max * 2
            process_window(@input.shift(window), &emit) while @input.length >= window
          end

          def process_window(samples, &)
            r = PWN::SDR::Decoder::DSP.resample_iq(
              iq: samples, src_rate: @rate, dst_rate: @bw
            )
            @buf.concat(r)
            SF_RANGE.each { |sf| try_sf(sf, &) if block_given? }
            max = ((1 << 12) * 20) * 2
            @buf.shift(@buf.length - max) if @buf.length > max
          end

          private

          def down_chirp(sf)
            @dchirp[sf] ||= begin
              n = 1 << sf
              iq = Array.new(n * 2)
              n.times do |k|
                # base up-chirp φ(k) = π·k·(k/N − 1); down-chirp = conj.
                ph = Math::PI * k * ((k.to_f / n) - 1.0)
                iq[k * 2]       = Math.cos(ph)
                iq[(k * 2) + 1] = -Math.sin(ph)
              end
              iq
            end
          end

          def demod_symbol(iq, sf)
            n  = 1 << sf
            dc = down_chirp(sf)
            de = PWN::SDR::Decoder::DSP.cmul(a: iq, b: dc)
            mag = PWN::SDR::Decoder::DSP.cfft_mag(iq: de, n: n, shift: false)
            pk_i = mag.each_with_index.max_by(&:first).last
            [pk_i, mag[pk_i], mag.sum / mag.length]
          end

          def try_sf(sf)
            n = 1 << sf
            need = n * 12 * 2 # ≥ 8 preamble + 2 sync + 2.25 SFD
            return if @buf.length < need

            # coarse alignment: try 8 phase offsets across first symbol
            best_off = 0
            best_run = 0
            best_bin = nil
            (0...n).step([n / 8, 1].max) do |off|
              bins = []
              10.times do |s|
                seg = @buf[(off + (s * n)) * 2, n * 2]
                break if seg.nil? || seg.length < n * 2

                bin, peak, floor = demod_symbol(seg, sf)
                break unless peak.positive? && peak > floor * 6

                bins << bin
              end
              # longest run of equal bins
              run = 1
              cur = 1
              (1...bins.length).each do |i|
                if ((bins[i] - bins[i - 1]) % n).zero?
                  cur += 1
                  run = cur if cur > run
                else
                  cur = 1
                end
              end
              if run > best_run
                best_run = run
                best_off = off
                best_bin = bins.group_by { |x| x }.max_by { |_, v| v.length }&.first
              end
            end
            return unless best_run >= 6 && best_bin

            # sync symbols follow preamble; walk forward until bin changes
            i = best_off
            i += n while ((demod_symbol(@buf[i * 2, n * 2], sf).first - best_bin) % n).zero? && i < (@buf.length / 2) - (4 * n)
            s1 = demod_symbol(@buf[i * 2, n * 2], sf).first
            s2 = demod_symbol(@buf[(i + n) * 2, n * 2], sf).first
            # sync word nibble encoding (× 2^(SF-4)); recover both nibbles.
            div = 1 << (sf - 4)
            n1 = (((s1 - best_bin) % n) / div) & 0xF
            n2 = (((s2 - best_bin) % n) / div) & 0xF
            sync = (n1 << 4) | n2
            key = "SF#{sf}:#{format('%02X', sync)}"
            unless @seen[key]
              @seen[key] = true
              yield(
                protocol: 'LoRa', event: 'preamble', modulation: 'CSS',
                capability: 'preamble-only', decoded: false,
                sf: sf, bw_hz: @bw, preamble_len: best_run,
                cfo_bins: best_bin, sync_word: format('0x%02X', sync),
                sync_name: KNOWN_SYNC[sync],
                summary: "LoRa SF#{sf}/BW#{@bw / 1000}k sync=0x#{format('%02X', sync)}#{" (#{KNOWN_SYNC[sync]})" if KNOWN_SYNC[sync]} preamble=#{best_run}"
              )
            end
            @buf.shift((i + (2 * n)) * 2)
          end
        end

        # Raw PHY receive path. Coding equations adapted from MIT LoRaPHY,
        # commit 4fddd9a7b47682781c663608bfc4f196e4bf656d (Xu et al.,
        # ACM TOSN 2022, doi:10.1145/3546869). Full attribution/license:
        # documentation/LoRaPHY-LICENSE.txt. Independent gr-lora_sdr vectors:
        # spec/fixtures/sdr/lora/README.md.
        # SF7-12 with explicit or configured implicit headers, optional CRC,
        # LDRO and inverted IQ; no fractional CFO or clock-drift tracking.
        # Keep acquisition and packet state together across arbitrary IQ chunks.
        class PayloadIQ # rubocop:disable Metrics/ClassLength
          def initialize(rate:, bw:, sf:, sync_word: 0x12, implicit_header: false, payload_length: nil, cr: 1, crc: true, ldro: nil, invert_iq: false) # rubocop:disable Metrics/ParameterLists
            raise ArgumentError, 'LoRa requires SF7-12, BW125/250/500k and finite sample_rate >= BW' unless sf.is_a?(Integer) && SF_RANGE.cover?(sf) && [125_000, 250_000, 500_000].include?(bw) && rate.is_a?(Numeric) && rate.finite? && rate >= bw
            raise ArgumentError, 'Implicit LoRa requires payload_length 0..255 and cr 1..4' if implicit_header && (!payload_length.is_a?(Integer) || !(0..255).cover?(payload_length) || !(1..4).cover?(cr))

            @implicit = implicit_header
            @length = payload_length
            @cr = cr
            @crc = crc
            @ldro = ldro.nil? ? (1 << sf).fdiv(bw) > 0.016 : ldro
            @invert = invert_iq

            @rate = rate
            @bw = bw
            @sf = sf
            raise ArgumentError, 'LoRa sync_word must be an integer byte' unless sync_word.is_a?(Integer) && (0..255).cover?(sync_word)

            @sync = sync_word
            @n = 1 << sf
            @buf = []
            @scan = 8 * @n
            @reference = Array.new(@n) do |k|
              phase = Math::PI * k * ((k.to_f / @n) - 1)
              Complex(Math.cos(phase), Math.sin(phase))
            end
          end

          def feed_iq(samples, rate: nil, &block)
            raise ArgumentError, 'LoRa sample rate changed' if rate && rate != @rate

            @buf.concat(resample_input(samples))
            loop do
              if @packet
                break unless receive_packet(&block)
              else
                break if @scan + (3 * @n) > @buf.length / 2

                acquire
                @scan += @n / 2 unless @packet
                # Bounded acquisition history, preserving six upchirps and sync.
                if !@packet && @scan > 24 * @n
                  removed = @scan - (8 * @n)
                  @buf.shift(removed * 2)
                  @scan -= removed
                end
              end
            end
          end

          private

          # Windowed-sinc conversion carries both sample history and the exact
          # rational output clock across transport chunks. It introduces lookahead,
          # not synthetic packet tails: incomplete input never becomes a full frame.
          def resample_input(samples)
            return samples if @rate == @bw

            @resample_buf ||= []
            @resample_origin ||= 0
            @resample_clock ||= 0
            @resample_buf.concat(samples)
            step = @rate.to_r / @bw
            radius = (16 * step).ceil
            numerator = step.numerator
            denominator = step.denominator
            native = PWN::SDR::Decoder::DSP.native && PWN::FFI::Volk.available?
            output = []
            while (@resample_clock / denominator) + radius < @resample_origin + (@resample_buf.length / 2)
              center, remainder = @resample_clock.divmod(denominator)
              @taps ||= {}
              key = ((remainder * 1024) + (denominator / 2)) / denominator
              taps = @taps[key] ||= begin
                values = (-radius..radius).map do |j|
                  x = (j - key.fdiv(1024)) / step.to_f
                  sinc = x.abs < 1e-12 ? 1.0 : Math.sin(Math::PI * x) / (Math::PI * x)
                  sinc * (0.5 + (0.5 * Math.cos(Math::PI * x / 17)))
                end
                total = values.sum
                values.map { |v| v / total }
              end
              real = imag = 0.0
              first = center - radius - @resample_origin
              if first >= 0 && native
                @dot ||= ::FFI::Function.new(:void, %i[pointer pointer pointer uint], PWN::FFI::Volk.volk_32f_x2_dot_prod_32f)
                native_input ||= ::FFI::MemoryPointer.new(:float, @resample_buf.length).tap { |ptr| ptr.write_array_of_float(@resample_buf) }
                @native_taps ||= {}
                tap_ptr = @native_taps[key] ||= begin
                  values = taps.flat_map { |tap| [tap, 0.0] }[0...-1]
                  ::FFI::MemoryPointer.new(:float, values.length).tap { |ptr| ptr.write_array_of_float(values) }
                end
                @dot_result ||= ::FFI::MemoryPointer.new(:float, 1)
                @dot.call(@dot_result, native_input + (first * 8), tap_ptr, (taps.length * 2) - 1)
                real = @dot_result.read_float
                @dot.call(@dot_result, native_input + (first * 8) + 4, tap_ptr, (taps.length * 2) - 1)
                imag = @dot_result.read_float
              else
                taps.each_with_index do |tap, j|
                  index = first + j
                  next if index.negative?

                  real += @resample_buf[index * 2] * tap
                  imag += @resample_buf[(index * 2) + 1] * tap
                end
              end
              output << real << imag
              @resample_clock += numerator
            end
            remove = [(@resample_clock / denominator) - radius - @resample_origin, 0].max
            @resample_buf.shift(remove * 2)
            @resample_origin += remove
            output
          end

          def peak(start, down: false)
            return [0, 0.0] if start.negative? || start + @n > @buf.length / 2

            mixed = Array.new(@n * 2)
            @n.times do |k|
              value = Complex(@buf[(start + k) * 2], @buf[((start + k) * 2) + 1] * (@invert ? -1 : 1))
              value *= down ? @reference[k] : @reference[k].conj
              mixed[k * 2] = value.real
              mixed[(k * 2) + 1] = value.imag
            end
            mag = PWN::SDR::Decoder::DSP.cfft_mag(iq: mixed, n: @n, shift: false)
            bin = mag.each_index.max_by { |i| mag[i] }
            energy = mag.sum { |v| v * v }
            [bin, energy.positive? ? (mag[bin]**2) / energy : 0.0]
          end

          def acquire
            down, quality = peak(@scan, down: true)
            return if quality < 0.45

            up, quality = peak(@scan - (4 * @n))
            return if quality < 0.45

            timing = ((up - down) % @n) / 2
            [timing, timing + (@n / 2)].each do |offset|
              sfd = @scan - offset
              next if sfd < 8 * @n

              cfo, q = peak(sfd - (3 * @n))
              next if q < 0.7
              next unless (3..8).all? do |i|
                b, p = peak(sfd - (i * @n))
                b == cfo && p > 0.7
              end
              next unless [sfd, sfd + @n].all? do |i|
                b, p = peak(i, down: true)
                b == cfo && p > 0.7
              end
              next unless [@sync >> 4, @sync & 15].each_with_index.all? do |nibble, i|
                b, p = peak(sfd - ((2 - i) * @n))
                (b - cfo) % @n == nibble * 8 && p > 0.7
              end

              @packet = { start: sfd + (9 * @n / 4), cfo: cfo }
              break
            end
          end

          def receive_packet
            return false if @packet[:finish] && @packet[:finish] > @buf.length / 2

            start = @packet[:start]
            return false if start + (8 * @n) > @buf.length / 2

            header = decode_block(symbols(start, 8), @sf - 2, 8, reduced: true)
            return discard_packet! unless header

            length = (header[0] << 4) | header[1]
            cr = header[2] >> 1
            crc = header[2] & 1
            check_bits = [0xF00, 0x8E1, 0x49A, 0x257, 0x12F].map do |mask|
              (((header[0] << 8) | (header[1] << 4) | header[2]) & mask).digits(2).sum & 1
            end
            check = check_bits.reduce(0) { |a, b| (a << 1) | b }
            return discard_packet! unless @implicit || ((1..4).cover?(cr) && check == (((header[3] & 1) << 4) | header[4]))

            if @implicit
              length = @length
              cr = @cr
              crc = (@crc ? 1 : 0)
            end

            width = @sf - (@ldro ? 2 : 0)
            blocks = [((2 * length) - @sf + 7 + (4 * crc) - (@implicit ? 5 : 0)).fdiv(width).ceil, 0].max
            count = 8 + (blocks * (cr + 4))
            @packet[:finish] = start + (count * @n)
            return false if @packet[:finish] > @buf.length / 2

            nibbles = @implicit ? header : header.drop(5)
            blocks.times do |i|
              block = decode_block(symbols(start + ((8 + (i * (cr + 4))) * @n), cr + 4), width, cr + 4, reduced: @ldro)
              return discard_packet! unless block

              nibbles.concat(block)
            end
            bytes = nibbles.each_slice(2).filter_map { |a, b| a | (b << 4) if b }
            return discard_packet! if bytes.length < length + (2 * crc)

            lfsr = 255
            payload = bytes.first(length).map do |byte|
              value = byte ^ lfsr
              feedback = [7, 5, 4, 3].reduce(0) { |acc, bit| acc ^ ((lfsr >> bit) & 1) }
              lfsr = ((lfsr << 1) | feedback) & 255
              value
            end
            expected = payload_crc(payload)
            if crc.zero? || bytes[length, 2] == [expected & 255, expected >> 8]
              yield protocol: 'LoRa', event: 'packet', capability: 'raw-phy', decoded: true,
                    payload_hex: payload.pack('C*').unpack1('H*'), payload_length: length,
                    crc_valid: crc == 1 ? true : nil, header_valid: @implicit ? nil : true, sf: @sf, bw_hz: @bw,
                    crc_present: crc == 1, implicit_header: @implicit, ldro: @ldro, invert_iq: @invert,
                    coding_rate: "4/#{cr + 4}", sync_word: format('0x%02X', @sync),
                    cfo_bins: @packet[:cfo], summary: "LoRa SF#{@sf} #{length} bytes #{crc == 1 ? 'CRC valid' : 'without payload CRC'}"
            end
            @buf.shift((start + (count * @n)) * 2)
            @scan = 8 * @n
            @packet = nil
            true
          end

          def discard_packet!
            @packet = nil
            @scan += @n / 2
          end

          def symbols(start, count)
            Array.new(count) do |i|
              bin, quality = peak(start + (i * @n))
              quality > 0.45 ? (bin - @packet[:cfo]) % @n : nil
            end
          end

          def decode_block(symbols, width, bits, reduced: false)
            return if symbols.any?(&:nil?)

            gray = symbols.map do |symbol|
              value = reduced ? symbol / 4 : (symbol - 1) % @n
              value ^ (value >> 1)
            end
            Array.new(width) do |row|
              word = gray.each_with_index.reduce(0) { |acc, (symbol, column)| acc | (((symbol >> ((row - column) % width)) & 1) << column) }
              distances = (0..15).map { |value| [(codeword(value, bits) ^ word).digits(2).sum, value] }.sort
              return nil if distances[0][0] > (bits >= 7 ? 1 : 0) || distances[0][0] == distances[1][0]

              distances[0][1]
            end
          end

          def codeword(value, bits)
            parity = ->(positions) { positions.reduce(0) { |acc, i| acc ^ ((value >> i) & 1) } }
            return value | (parity.call([0, 1, 2, 3]) << 4) if bits == 5

            result = value | (parity.call([0, 1, 2]) << 4) | (parity.call([1, 2, 3]) << 5)
            result |= parity.call([0, 1, 3]) << 6 if bits >= 7
            result |= parity.call([0, 2, 3]) << 7 if bits == 8
            result
          end

          def payload_crc(payload)
            return 0 if payload.empty?
            return payload[0] if payload.length == 1

            crc = 0
            payload[0...-2].each do |byte|
              crc ^= byte << 8
              8.times { crc = ((crc << 1) ^ (crc[15] == 1 ? 0x1021 : 0)) & 0xFFFF }
            end
            crc ^ (payload[-2] << 8) ^ payload[-1]
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::LoRa.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        # Realtime options forwarded to Base: on_frame (Hash callback), output
        # (writable IO), interactive (default true), duration (seconds), stop
        # (callable), queue_size (bounded chunks), log_file (path or false).
        public_class_method def self.decode(opts = {})
          mode = opts[:mode] || :css
          raise ArgumentError, 'LoRa supports CSS mode only' unless mode.to_sym == :css

          freq_obj = opts[:freq_obj] || {}
          bw = opts[:bw] || freq_obj[:lora_bw] || DEFAULT_BW
          rate = opts[:sample_rate] || freq_obj[:iq_rate] || bw
          sf = opts[:sf] || 7
          demod = PayloadIQ.new(rate: rate, bw: bw, sf: sf, sync_word: opts[:sync_word] || 0x12,
                                implicit_header: opts.fetch(:implicit_header, false), payload_length: opts[:payload_length],
                                cr: opts.fetch(:cr, 1), crc: opts.fetch(:crc, true), ldro: opts[:ldro], invert_iq: opts.fetch(:invert_iq, false))
          PWN::SDR::Decoder::Base.run_iq(
            **opts, freq_obj: freq_obj, protocol: 'LoRa', sample_rate: rate, demod: demod, fallback: :raise,
                    note: 'Raw LoRa PHY: SF7-12, explicit/implicit headers, optional CRC, LDRO, normal/inverted IQ.',
                    describe: proc { |frame| { modulation: 'CSS', sf: frame[:sf], crc_valid: frame[:crc_valid] } }
          )
        end

        public_class_method def self.detect(opts = {})
          freq_obj = opts[:freq_obj]
          bw   = (opts[:bw] || freq_obj[:lora_bw] || DEFAULT_BW).to_i
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || (bw * 4)).to_i
          PWN::SDR::Decoder::Base.run_iq(
            **opts,
            freq_obj: freq_obj,
            protocol: 'LoRa',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, bw: bw),
            note: 'CSS 125–500 kHz — I/Q→resample_iq(fs=BW)→dechirp+FFTW per SF→preamble/sync-word.',
            describe: proc { |b| { modulation: 'CSS', bw_khz_assumed: bw / 1000, sf_estimate: b[:sf] } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          h = begin
            JSON.parse(line, symbolize_names: true)
          rescue StandardError
            { unparsed: line }
          end
          out = { protocol: 'LoRa' }.merge(h)
          bits = []
          bits << "SF#{out[:sf]}" if out[:sf]
          bits << "BW#{out[:bw]}" if out[:bw]
          bits << "sync=#{out[:sync_word]}" if out[:sync_word]
          bits << out[:payload].to_s[0, 40] if out[:payload]
          out[:summary] = bits.empty? ? line[0, 120] : bits.join(' ')
          out
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # .decode: raw PHY SF7-12, CR4/5..4/8, explicit/implicit headers.
            # Optional CRC, LDRO, inverted IQ, fs>=BW; no clock drift tracking.
            # Output is raw payload_hex, NOT decrypted LoRaWAN application data.
            # .detect retains CSS preamble/sync acquisition, never decoded payload.
            #{self}.detect(freq_obj: 'required', bw: 'optional bandwidth Hz',
                           source: 'optional IQ input', on_frame: 'optional callback')

            # Run decode and return its result
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq',
              on_frame: 'optional - callback receiving each emitted Hash',
              output: 'optional - writable IO (default stdout)',
              interactive: 'optional - false disables ENTER input',
              duration: 'optional - finite seconds to run',
              stop: 'optional - callable returning true to stop',
              queue_size: 'optional - bounded pending chunks (default 8)',
              log_file: 'optional - JSONL path or false to disable logging',
              mode: 'optional - :css only, the default supported PHY mode',
              implicit_header: 'optional - false (default) or true with payload_length/cr/crc configured',
              invert_iq: 'optional - conjugate received IQ (default false)',
              ldro: 'optional - true/false; default auto when symbol duration exceeds 16ms',
              crc: 'optional - implicit-mode CRC presence (default true); explicit header is authoritative',
              payload_length: 'optional - integer byte count 0..255; required for implicit mode',
              cr: 'optional - implicit-mode coding rate 1..4 for 4/5..4/8 (default 1)',
              sf: 'optional - integer 7..12 (default 7)',
              sync_word: 'optional - integer byte (default 0x12; LoRaWAN 0x34)',
              iq_format: 'optional - cu8 (default), cs8 or cs16 for Base source',
              bw: 'optional - 125000 (default), 250000 or 500000; sample_rate must be >= BW',
              sample_rate: 'optional - sample rate value consumed by #decode',
              source: 'optional - source value consumed by #decode',
              file: 'optional - filesystem path'
            )

            # Run parse line and return its result
            #{self}.parse_line(
              line: 'optional - line value consumed by #parse_line'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
