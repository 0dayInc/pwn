# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # DSP primitives shared by every PWN::SDR::Decoder::* module.
      #
      # Default path is pure Ruby operating on Array<Float> samples
      # normalised to -1.0..1.0 (48 kHz s16le mono from GQRX UDP — no
      # `sox` / `multimon-ng` / `minimodem` dependency).
      #
      # When the matching system library is present the hot paths
      # transparently accelerate via PWN::FFI::{Volk,Liquid,FFTW}:
      #
      #   unpack_s16le  → PWN::FFI::Volk   (SIMD s16→f32 convert)
      #   unpack_cs16le → pure / Volk path (interleaved I/Q s16 → f32)
      #   unpack_cu8    → pure path (RTL-SDR u8 I/Q → f32)
      #   resample      → PWN::FFI::Liquid (msresamp multi-stage)
      #   dc_block      → PWN::FFI::Liquid (firfilt DC blocker)
      #   rms_dbfs      → PWN::FFI::Volk   (accumulate of squares)
      #   mag_sq / fm_demod_iq → true-air I/Q paths for Base.run_iq
      #
      # Each accelerated method falls back to the pure-Ruby body when
      # the backend is missing or raises, so decoders never require a
      # native library at install time. Force pure Ruby for testing with
      #   PWN::SDR::Decoder::DSP.native = false
      module DSP
        @native = true

        class << self
          attr_accessor :native
        end
        TWO_PI = Math::PI * 2

        # ITA2 / Baudot 5-bit → ASCII (LTRS + FIGS shift tables). Index = code.
        BAUDOT_LTRS = [
          "\0", 'E', "\n", 'A', ' ', 'S', 'I', 'U',
          "\r", 'D', 'R', 'J', 'N', 'F', 'C', 'K',
          'T',  'Z', 'L',  'W', 'H', 'Y', 'P', 'Q',
          'O',  'B', 'G',  nil, 'M', 'X', 'V', nil
        ].freeze

        BAUDOT_FIGS = [
          "\0", '3', "\n", '-', ' ', "'", '8', '7',
          "\r", '$', '4',  "\a", ',', '!', ':', '(',
          '5',  '+', ')',  '2', '#', '6', '0', '1',
          '9',  '?', '&',  nil, '.', '/', ';', nil
        ].freeze

        # International Morse Code (dit='.', dah='-') → ASCII.
        MORSE_TABLE = {
          '.-' => 'A', '-...' => 'B', '-.-.' => 'C', '-..' => 'D', '.' => 'E',
          '..-.' => 'F', '--.' => 'G', '....' => 'H', '..' => 'I', '.---' => 'J',
          '-.-' => 'K', '.-..' => 'L', '--' => 'M', '-.' => 'N', '---' => 'O',
          '.--.' => 'P', '--.-' => 'Q', '.-.' => 'R', '...' => 'S', '-' => 'T',
          '..-' => 'U', '...-' => 'V', '.--' => 'W', '-..-' => 'X', '-.--' => 'Y',
          '--..' => 'Z', '-----' => '0', '.----' => '1', '..---' => '2',
          '...--' => '3', '....-' => '4', '.....' => '5', '-....' => '6',
          '--...' => '7', '---..' => '8', '----.' => '9', '.-.-.-' => '.',
          '--..--' => ',', '..--..' => '?', '-..-.' => '/', '-....-' => '-',
          '-.--.' => '(', '-.--.-' => ')', '.-...' => '&', '---...' => ':',
          '-...-' => '=', '.-.-.' => '+', '.--.-.' => '@'
        }.freeze

        # Supported Method Parameters::
        # samples = PWN::SDR::Decoder::DSP.unpack_s16le(
        #   data: 'required - raw String of little-endian signed 16-bit PCM'
        # )

        public_class_method def self.unpack_s16le(opts = {})
          data = opts[:data].to_s
          if native && PWN::FFI.available?(mod: :Volk)
            begin
              return PWN::FFI::Volk.unpack_s16le(data: data)
            rescue StandardError
              # fall through to pure Ruby
            end
          end
          norm = 1.0 / 32_768.0
          data.unpack('s<*').map { |v| v * norm }
        end

        # Supported Method Parameters::
        # out = PWN::SDR::Decoder::DSP.resample(
        #   samples: 'required - Array<Float>',
        #   src_rate: 'required - input sample rate (Hz)',
        #   dst_rate: 'required - output sample rate (Hz)'
        # )

        public_class_method def self.resample(opts = {})
          samples  = opts[:samples]
          src_rate = opts[:src_rate].to_f
          dst_rate = opts[:dst_rate].to_f
          return samples.dup if (src_rate - dst_rate).abs < 1e-6

          if native && PWN::FFI.available?(mod: :Liquid)
            begin
              # liquid rate = output/input
              return PWN::FFI::Liquid.resample(
                samples: samples,
                rate: dst_rate / src_rate
              )
            rescue StandardError
              # fall through to pure Ruby
            end
          end

          ratio = src_rate / dst_rate
          out_len = (samples.length / ratio).floor
          out = Array.new(out_len)
          i = 0
          while i < out_len
            pos  = i * ratio
            idx  = pos.floor
            frac = pos - idx
            a = samples[idx] || 0.0
            b = samples[idx + 1] || a
            out[i] = a + ((b - a) * frac)
            i += 1
          end
          out
        end

        # Supported Method Parameters::
        # power = PWN::SDR::Decoder::DSP.goertzel(
        #   samples: 'required - Array<Float>',
        #   rate:    'required - sample rate (Hz)',
        #   freq:    'required - target tone frequency (Hz)'
        # )

        public_class_method def self.goertzel(opts = {})
          samples = opts[:samples]
          rate    = opts[:rate].to_f
          freq    = opts[:freq].to_f
          n       = samples.length
          return 0.0 if n.zero?

          k     = (0.5 + ((n * freq) / rate)).floor
          w     = (TWO_PI * k) / n
          coeff = 2.0 * Math.cos(w)
          s1 = 0.0
          s2 = 0.0
          samples.each do |x|
            s0 = x + (coeff * s1) - s2
            s2 = s1
            s1 = s0
          end
          ((s1 * s1) + (s2 * s2) - (coeff * s1 * s2)) / n
        end

        # Supported Method Parameters::
        # env = PWN::SDR::Decoder::DSP.envelope(
        #   samples: 'required - Array<Float>',
        #   window:  'optional - moving-average window in samples (default 32)'
        # )

        public_class_method def self.envelope(opts = {})
          samples = opts[:samples]
          window  = (opts[:window] || 32).to_i
          window  = 1 if window < 1
          acc = 0.0
          buf = Array.new(window, 0.0)
          out = Array.new(samples.length)
          samples.each_with_index do |x, i|
            v = x.abs
            slot = i % window
            acc += v - buf[slot]
            buf[slot] = v
            out[i] = acc / window
          end
          out
        end

        # Supported Method Parameters::
        # y = PWN::SDR::Decoder::DSP.dc_block(
        #   samples: 'required - Array<Float>',
        #   alpha:   'optional - pole (default 0.995)'
        # )

        public_class_method def self.dc_block(opts = {})
          samples = opts[:samples]
          # Prefer liquid FIR DC blocker when caller asks for it (m:) or when
          # alpha is the default AND liquid is available — otherwise keep the
          # classic single-pole IIR so call sites that pass a custom alpha
          # stay bit-identical to pure Ruby.
          if native && opts[:m] && PWN::FFI.available?(mod: :Liquid)
            begin
              return PWN::FFI::Liquid.dc_block(
                samples: samples,
                m: opts[:m],
                as_db: opts[:as_db] || 60.0
              )
            rescue StandardError
              # fall through
            end
          end

          alpha  = (opts[:alpha] || 0.995).to_f
          y_prev = 0.0
          x_prev = 0.0
          samples.map do |x|
            y = x - x_prev + (alpha * y_prev)
            x_prev = x
            y_prev = y
            y
          end
        end

        # Supported Method Parameters::
        # bits = PWN::SDR::Decoder::DSP.nrz_slice(
        #   samples: 'required - Array<Float> (post-FM-discriminator baseband)',
        #   rate:    'required - sample rate (Hz)',
        #   baud:    'required - symbol rate',
        #   invert:  'optional - flip bit polarity (default false)'
        # )
        # Simple mid-bit sampler with zero-crossing resync. Returns Array<0|1>.

        public_class_method def self.nrz_slice(opts = {})
          samples = opts[:samples]
          rate    = opts[:rate].to_f
          baud    = opts[:baud].to_f
          invert  = opts[:invert]
          spb     = rate / baud
          return [] if spb < 2.0 || samples.empty?

          # DC-block then low-pass via short moving average (~1/4 symbol).
          lp_win = [(spb / 4.0).round, 1].max
          filt   = envelope_signed(samples: dc_block(samples: samples), window: lp_win)

          bits  = []
          phase = spb / 2.0
          prev  = filt.first.to_f
          filt.each do |v|
            # zero-crossing → resync to mid-symbol
            phase = spb / 2.0 if (prev.negative? && v >= 0) || (prev.positive? && v.negative?)
            phase -= 1.0
            if phase <= 0
              b = v.negative? ? 0 : 1
              b ^= 1 if invert
              bits << b
              phase += spb
            end
            prev = v
          end
          bits
        end

        # Signed moving average (like envelope but keeps sign).
        # Supported Method Parameters::
        # y = PWN::SDR::Decoder::DSP.envelope_signed(samples:, window:)

        public_class_method def self.envelope_signed(opts = {})
          samples = opts[:samples]
          window  = (opts[:window] || 8).to_i
          window  = 1 if window < 1
          acc = 0.0
          buf = Array.new(window, 0.0)
          out = Array.new(samples.length)
          samples.each_with_index do |x, i|
            slot = i % window
            acc += x - buf[slot]
            buf[slot] = x
            out[i] = acc / window
          end
          out
        end

        # Supported Method Parameters::
        # bits = PWN::SDR::Decoder::DSP.fsk_slice(
        #   samples: 'required - Array<Float>',
        #   rate:    'required - sample rate (Hz)',
        #   baud:    'required - symbol rate',
        #   mark_hz: 'required - mark tone (bit=1)',
        #   space_hz:'required - space tone (bit=0)'
        # )
        # Non-coherent 2-FSK: per-symbol Goertzel on mark/space, pick the winner.

        public_class_method def self.fsk_slice(opts = {})
          samples  = opts[:samples]
          rate     = opts[:rate].to_f
          baud     = opts[:baud].to_f
          mark_hz  = opts[:mark_hz].to_f
          space_hz = opts[:space_hz].to_f
          spb      = rate / baud
          nsym     = (samples.length / spb).floor
          bits     = Array.new(nsym)
          i = 0
          while i < nsym
            a = (i * spb).floor
            b = ((i + 1) * spb).floor
            win = samples[a...b]
            pm = goertzel(samples: win, rate: rate, freq: mark_hz)
            ps = goertzel(samples: win, rate: rate, freq: space_hz)
            bits[i] = pm >= ps ? 1 : 0
            i += 1
          end
          bits
        end

        # Supported Method Parameters::
        # idx = PWN::SDR::Decoder::DSP.find_sync(
        #   bits:    'required - Array<0|1>',
        #   pattern: 'required - Array<0|1> or Integer (MSB-first)',
        #   width:   'optional - bit-width when pattern is Integer',
        #   max_err: 'optional - allowed bit errors (default 0)',
        #   from:    'optional - start index (default 0)'
        # )

        public_class_method def self.find_sync(opts = {})
          bits    = opts[:bits]
          pattern = opts[:pattern]
          width   = opts[:width]
          max_err = (opts[:max_err] || 0).to_i
          from    = (opts[:from] || 0).to_i
          pat = if pattern.is_a?(Integer)
                  w = width || pattern.bit_length
                  Array.new(w) { |i| (pattern >> (w - 1 - i)) & 1 }
                else
                  pattern
                end
          plen = pat.length
          upto = bits.length - plen
          i = from
          while i <= upto
            err = 0
            j = 0
            while j < plen
              err += 1 if bits[i + j] != pat[j]
              break if err > max_err

              j += 1
            end
            return i if err <= max_err

            i += 1
          end
          nil
        end

        # Supported Method Parameters::
        # int = PWN::SDR::Decoder::DSP.bits_to_int(bits: [1,0,1,...])

        public_class_method def self.bits_to_int(opts = {})
          bits = opts[:bits]
          v = 0
          bits.each { |b| v = (v << 1) | (b & 1) }
          v
        end

        # Supported Method Parameters::
        # ok = PWN::SDR::Decoder::DSP.even_parity_ok?(word: Integer, width: 32)

        public_class_method def self.even_parity_ok?(opts = {})
          word  = opts[:word].to_i
          width = (opts[:width] || 32).to_i
          p = 0
          width.times { |i| p ^= (word >> i) & 1 }
          p.zero?
        end

        # BCH(31,21) syndrome — generator poly 0b11101101001 (0x769).
        # Used by POCSAG and FLEX codewords (bits 31..1 are BCH, bit 0 parity).
        # Supported Method Parameters::
        # syn = PWN::SDR::Decoder::DSP.bch_31_21_syndrome(word: Integer)

        public_class_method def self.bch_31_21_syndrome(opts = {})
          word = (opts[:word].to_i >> 1) & 0x7FFFFFFF
          gen  = 0x769
          reg  = word
          30.downto(10) do |i|
            reg ^= (gen << (i - 10)) if (reg >> i).odd?
          end
          reg & 0x3FF
        end

        # Supported Method Parameters::
        # txt = PWN::SDR::Decoder::DSP.baudot_decode(bits: Array<0|1>)
        # 5-bit ITA2 with LTRS(31)/FIGS(27) shift, LSB-first per character.

        public_class_method def self.baudot_decode(opts = {})
          bits = opts[:bits]
          figs = false
          out  = +''
          bits.each_slice(5) do |ch|
            next if ch.length < 5

            code = ch.each_with_index.sum { |b, i| b << i }
            case code
            when 31 then figs = false
            when 27 then figs = true
            else
              tbl = figs ? BAUDOT_FIGS : BAUDOT_LTRS
              c = tbl[code]
              out << c if c
            end
          end
          out
        end

        # Supported Method Parameters::
        # dbfs = PWN::SDR::Decoder::DSP.rms_dbfs(samples: Array<Float>)

        public_class_method def self.rms_dbfs(opts = {})
          samples = opts[:samples]
          return -120.0 if samples.nil? || samples.empty?

          if native && PWN::FFI.available?(mod: :Volk) && samples.length >= 64
            begin
              # Σ x² via volk: scale-square in Ruby is still the bottleneck for
              # tiny buffers so keep the pure-Ruby path under 64 samples.
              sq = samples.map { |v| v * v }
              ms = PWN::FFI::Volk.accumulate(samples: sq) / samples.length
              return -120.0 if ms <= 0

              return 10.0 * Math.log10(ms)
            rescue StandardError
              # fall through
            end
          end

          ms = samples.sum { |v| v * v } / samples.length
          return -120.0 if ms <= 0

          10.0 * Math.log10(ms)
        end

        # ── True-air I/Q primitives (used by Base.run_iq) ─────────────────

        # Supported Method Parameters::
        # iq = PWN::SDR::Decoder::DSP.unpack_cs16le(
        #   data: 'required - raw String of interleaved little-endian s16 I/Q'
        # )
        # Returns interleaved Array<Float> [I0,Q0,I1,Q1,…] normalised ±1.0.

        public_class_method def self.unpack_cs16le(opts = {})
          data = opts[:data].to_s
          if native && PWN::FFI.available?(mod: :Volk)
            begin
              return PWN::FFI::Volk.unpack_s16le(data: data)
            rescue StandardError
              # fall through
            end
          end
          norm = 1.0 / 32_768.0
          data.unpack('s<*').map { |v| v * norm }
        end

        # Supported Method Parameters::
        # iq = PWN::SDR::Decoder::DSP.unpack_cu8(
        #   data: 'required - raw String of interleaved u8 I/Q (RTL-SDR)'
        # )
        # Returns interleaved Array<Float> [I0,Q0,…] centred & normalised ±1.0.

        public_class_method def self.unpack_cu8(opts = {})
          data = opts[:data].to_s
          norm = 1.0 / 128.0
          data.unpack('C*').map { |v| (v - 127.5) * norm }
        end

        # Supported Method Parameters::
        # m2 = PWN::SDR::Decoder::DSP.mag_sq(
        #   iq: 'required - interleaved Array<Float> [I0,Q0,I1,Q1,…]'
        # )
        # Returns Array<Float> of I²+Q² per sample (length = iq.length/2).

        public_class_method def self.mag_sq(opts = {})
          iq = opts[:iq]
          n  = iq.length / 2
          out = Array.new(n)
          i = 0
          while i < n
            re = iq[i * 2].to_f
            im = iq[(i * 2) + 1].to_f
            out[i] = (re * re) + (im * im)
            i += 1
          end
          out
        end

        # Supported Method Parameters::
        # audio = PWN::SDR::Decoder::DSP.fm_demod_iq(
        #   iq: 'required - interleaved Array<Float> [I0,Q0,…]',
        #   kf: 'optional - modulation index scale (default 1.0)'
        # )
        # Polar-discriminant FM demod. Prefers PWN::FFI::Liquid.freq_demod
        # when available; otherwise atan2 difference of consecutive samples.

        public_class_method def self.fm_demod_iq(opts = {})
          iq = opts[:iq]
          kf = (opts[:kf] || 1.0).to_f
          n  = iq.length / 2
          return [] if n < 2

          if native && PWN::FFI.available?(mod: :Liquid)
            begin
              return PWN::FFI::Liquid.freq_demod(iq: iq, kf: kf)
            rescue StandardError
              # fall through
            end
          end

          out = Array.new(n - 1)
          prev_re = iq[0].to_f
          prev_im = iq[1].to_f
          i = 1
          while i < n
            re = iq[i * 2].to_f
            im = iq[(i * 2) + 1].to_f
            # arg(z * conj(z_prev)) = atan2 cross/dot
            dot   = (re * prev_re) + (im * prev_im)
            cross = (im * prev_re) - (re * prev_im)
            out[i - 1] = Math.atan2(cross, dot) * kf
            prev_re = re
            prev_im = im
            i += 1
          end
          out
        end

        # Supported Method Parameters::
        # power = PWN::SDR::Decoder::DSP.iq_rms_dbfs(
        #   iq: 'required - interleaved Array<Float> [I0,Q0,…]'
        # )

        public_class_method def self.iq_rms_dbfs(opts = {})
          m2 = mag_sq(iq: opts[:iq])
          return -120.0 if m2.empty?

          ms = m2.sum / m2.length
          return -120.0 if ms <= 0

          10.0 * Math.log10(ms)
        end

        # Correlate a real template against magnitude-squared energy for
        # PPM / OOK preambles. Returns best lag + score.
        # Supported Method Parameters::
        # hit = PWN::SDR::Decoder::DSP.correlate(
        #   samples:  'required - Array<Float>',
        #   template: 'required - Array<Float> (same units)'
        # )
        # → { lag:, score: } or nil

        public_class_method def self.correlate(opts = {})
          samples  = opts[:samples]
          template = opts[:template]
          tlen = template.length
          return nil if tlen.zero? || samples.length < tlen

          best_lag = 0
          best_sc  = -Float::INFINITY
          upto = samples.length - tlen
          i = 0
          while i <= upto
            sc = 0.0
            j = 0
            while j < tlen
              sc += samples[i + j] * template[j]
              j += 1
            end
            if sc > best_sc
              best_sc = sc
              best_lag = i
            end
            i += 1
          end
          { lag: best_lag, score: best_sc }
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (pure-Ruby DSP + optional PWN::FFI acceleration):
            #{self}.native = true|false   # toggle VOLK/liquid/FFTW backends
            #{self}.unpack_s16le(data: raw_bytes)              # → Volk
            #{self}.unpack_cs16le(data: raw_cs16)              # I/Q s16 → f32
            #{self}.unpack_cu8(data: raw_u8)                  # RTL-SDR u8 I/Q
            #{self}.mag_sq(iq:) / #{self}.iq_rms_dbfs(iq:)
            #{self}.fm_demod_iq(iq:, kf: 1.0)                 # → Liquid
            #{self}.correlate(samples:, template:)
            #{self}.resample(samples:, src_rate:, dst_rate:)   # → Liquid
            #{self}.goertzel(samples:, rate:, freq:)
            #{self}.envelope(samples:, window: 32)
            #{self}.envelope_signed(samples:, window: 8)
            #{self}.dc_block(samples:, alpha: 0.995, m: nil)   # → Liquid if m:
            #{self}.nrz_slice(samples:, rate:, baud:, invert: false)
            #{self}.fsk_slice(samples:, rate:, baud:, mark_hz:, space_hz:)
            #{self}.find_sync(bits:, pattern:, width:, max_err: 0, from: 0)
            #{self}.bits_to_int(bits:)
            #{self}.even_parity_ok?(word:, width: 32)
            #{self}.bch_31_21_syndrome(word:)
            #{self}.baudot_decode(bits:)
            #{self}.rms_dbfs(samples:)                         # → Volk (≥64)

            Constants: MORSE_TABLE, BAUDOT_LTRS, BAUDOT_FIGS
            Backends:  PWN::FFI.backends  # { Volk: true, Liquid: true, AdalmPluto: true, … }

            #{self}.authors
          "
        end
      end
    end
  end
end
