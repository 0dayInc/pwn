# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby FLEX™ pager decoder.
      #
      # FLEX is Motorola's synchronous paging protocol running at 1600,
      # 3200 or 6400 bps in 2- or 4-level FSK. GQRX's NBFM discriminator
      # audio (48 kHz UDP tap) is NRZ-sliced at 1600 baud (2-FSK mode),
      # locked onto the Sync-1 A-word (bit-sync 0xAAAA + A1 = 0x78F3), then
      # each 1.875 s frame's 88 × 32-bit BCH(31,21) codewords are walked to
      # recover Frame-Info, Address and Vector/Message words. Alphanumeric
      # (7-bit ASCII, 3 chars per 21-bit payload) and numeric (BCD) message
      # bodies are extracted. No `multimon-ng`, no `sox` — 100 % Ruby.
      #
      # Limitation: 3200/6400 bps 4-FSK modes require raw discriminator
      # amplitude quantisation into four levels; only frame/cycle/capcode
      # metadata (not message body) is emitted for those speeds.
      module Flex
        BS1     = 0xAAAA
        A1      = 0x78F3 # 1600 / 2-FSK Sync-1 A-word
        A_TABLE = {
          0x870C => [1600, 2], 0x78F3 => [1600, 2],
          0xB068 => [3200, 2], 0x4F97 => [3200, 2],
          0x7B18 => [3200, 4], 0x84E7 => [3200, 4],
          0xDEA0 => [6400, 4], 0x215F => [6400, 4]
        }.freeze
        NUM_TABLE = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '/', 'U', ' ', '-', ']', '['].freeze

        # Streaming FLEX demodulator fed by Base.run_native.
        class Demod
          def initialize(rate: 48_000)
            @rate  = rate
            @buf   = []
            @inv   = nil
            @carry = []
          end

          def feed(samples, &)
            @buf.concat(samples)
            max = (@rate * 4).to_i
            @buf.shift(@buf.length - max) if @buf.length > max
            return if @buf.length < (@rate * 2) # need ≥1 frame

            try_lock if @inv.nil?
            return if @inv.nil?

            bits = PWN::SDR::Decoder::DSP.nrz_slice(samples: @buf, rate: @rate, baud: 1600, invert: @inv)
            @buf.clear
            bits = @carry + bits
            @carry = Flex.decode_bits(bits: bits, &)
          end

          private

          def try_lock
            @inv = [false, true].find do |inv|
              bits = PWN::SDR::Decoder::DSP.nrz_slice(samples: @buf, rate: @rate, baud: 1600, invert: inv)
              PWN::SDR::Decoder::DSP.find_sync(bits: bits, pattern: (BS1 << 16) | A1, width: 32, max_err: 3)
            end
          end
        end

        # Supported Method Parameters::
        # carry = PWN::SDR::Decoder::Flex.decode_bits(bits: [...]) { |msg| ... }

        public_class_method def self.decode_bits(opts = {})
          bits = opts[:bits] || []
          i = 0
          loop do
            # Sync-1 = 16-bit BS1 + 16-bit A + 16-bit B (=~A) + 16-bit ~A
            idx = PWN::SDR::Decoder::DSP.find_sync(bits: bits, pattern: BS1, width: 16, max_err: 1, from: i)
            break unless idx
            break if idx + 144 > bits.length

            a_word = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[idx + 16, 16])
            speed  = A_TABLE[a_word]
            unless speed
              i = idx + 1
              next
            end
            # Frame Info Word follows Sync-1 (32-bit BCH codeword)
            fiw   = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[idx + 64, 32])
            cycle = (fiw >> 4) & 0x0F
            frame = (fiw >> 8) & 0x7F
            block0 = idx + 64 + 32 + 16 # after FIW + Sync-2 marker
            frame_bits = 1600 * 2 # ≈ one FLEX frame @ 1600 bps (upper bound)
            avail = [bits.length - block0, frame_bits].min
            words = []
            (avail / 32).times do |w|
              words << PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[block0 + (w * 32), 32])
            end
            emit_frame(words: words, cycle: cycle, frame: frame, speed: speed) { |m| yield m if block_given? }
            i = block0 + avail
          end
          tail_from = [bits.length - 3200, 0].max
          bits[tail_from..] || []
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Flex.emit_frame(words:, cycle:, frame:, speed:) { |msg| ... }

        public_class_method def self.emit_frame(opts = {})
          words = opts[:words] || []
          cycle = opts[:cycle]
          frame = opts[:frame]
          speed = opts[:speed] || [1600, 2]
          return if words.empty?

          # Block Info Word (word 0): a = address-start, v = vector-start
          biw     = words[0]
          a_start = (biw >> 8) & 0x3F
          v_start = (biw >> 2) & 0x3F
          v_start = a_start + 1 if v_start <= a_start
          addr_words = words[a_start...v_start] || []
          addr_words.each_with_index do |aw, k|
            next if aw.nil? || aw.zero?

            capcode = (aw >> 11) & 0x1FFFFF
            vec     = words[v_start + k]
            type    = vec ? ((vec >> 4) & 0x7) : nil
            mstart  = vec ? ((vec >> 7)  & 0x7F) : nil
            mlen    = vec ? ((vec >> 14) & 0x7F) : 0
            mwords  = mstart && mlen.positive? ? (words[mstart, mlen] || []) : []
            body, tname =
              case type
              when 5 then [alpha_decode(words: mwords), 'ALN']
              when 3 then [numeric_decode(words: mwords), 'NUM']
              when 0, nil then [nil, 'TON']
              else [hex_decode(words: mwords), 'BIN']
              end
            out = {
              protocol: 'FLEX', speed: "#{speed[0]}/#{speed[1]}",
              cycle: cycle, frame: frame,
              capcode: capcode.to_s.rjust(9, '0'),
              type: tname, type_payload: body
            }.compact
            out[:summary] = "FLEX RIC=#{out[:capcode]} #{tname}: #{body}"[0, 160]
            yield out if block_given?
          end
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::Flex.alpha_decode(words: [Integer, ...])

        public_class_method def self.alpha_decode(opts = {})
          words = opts[:words] || []
          out = +''
          words.each do |w|
            payload = (w >> 11) & 0x1FFFFF
            3.times do |c|
              ch = (payload >> (c * 7)) & 0x7F
              next if ch < 0x20 || ch == 0x7F

              out << ch.chr
            end
          end
          out.strip
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::Flex.numeric_decode(words: [Integer, ...])

        public_class_method def self.numeric_decode(opts = {})
          words = opts[:words] || []
          out = +''
          words.each do |w|
            payload = (w >> 11) & 0x1FFFFF
            5.times { |d| out << NUM_TABLE[(payload >> (d * 4)) & 0xF] }
          end
          out.strip
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::Flex.hex_decode(words: [Integer, ...])

        public_class_method def self.hex_decode(opts = {})
          words = opts[:words] || []
          words.map { |w| format('%08X', w & 0xFFFFFFFF) }.join(' ')
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Flex.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_native(
            freq_obj: freq_obj,
            protocol: 'FLEX',
            demod: Demod.new
          )
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (ruby-native, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.decode_bits(bits: [0,1,...]) { |msg| ... }
            #{self}.alpha_decode(words: [Integer, ...])
            #{self}.numeric_decode(words: [Integer, ...])

            NOTE: Set GQRX to Narrow FM (~15 kHz). 1600 bps 2-FSK is fully
                  decoded; 3200/6400 4-FSK emit frame/capcode metadata only.

            #{self}.authors
          "
        end
      end
    end
  end
end
