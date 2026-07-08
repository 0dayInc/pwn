# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby DSP primitives shared by every PWN::SDR::Decoder::* module.
      #
      # Nothing in here shells out. Everything operates on plain Ruby Arrays
      # of Float samples (normalised -1.0..1.0), so decoders can consume the
      # 48 kHz s16le mono audio that PWN::SDR::GQRX streams over UDP without
      # any external `sox` / `multimon-ng` / `minimodem` / etc dependency.
      #
      # These are intentionally simple, readable, allocation-heavy reference
      # implementations — good enough for ≤48 kHz audio-rate work on a modern
      # CPU. For MHz-rate raw I/Q you would want SIMD/native code, which is
      # out of scope for a pure-Ruby decoder namespace.
      module DSP
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
          alpha   = (opts[:alpha] || 0.995).to_f
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

          ms = samples.sum { |v| v * v } / samples.length
          return -120.0 if ms <= 0

          10.0 * Math.log10(ms)
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (pure-Ruby DSP primitives — no external binaries):
            #{self}.unpack_s16le(data: raw_bytes)
            #{self}.resample(samples:, src_rate:, dst_rate:)
            #{self}.goertzel(samples:, rate:, freq:)
            #{self}.envelope(samples:, window: 32)
            #{self}.envelope_signed(samples:, window: 8)
            #{self}.dc_block(samples:, alpha: 0.995)
            #{self}.nrz_slice(samples:, rate:, baud:, invert: false)
            #{self}.fsk_slice(samples:, rate:, baud:, mark_hz:, space_hz:)
            #{self}.find_sync(bits:, pattern:, width:, max_err: 0, from: 0)
            #{self}.bits_to_int(bits:)
            #{self}.even_parity_ok?(word:, width: 32)
            #{self}.bch_31_21_syndrome(word:)
            #{self}.baudot_decode(bits:)
            #{self}.rms_dbfs(samples:)

            Constants: MORSE_TABLE, BAUDOT_LTRS, BAUDOT_FIGS

            #{self}.authors
          "
        end
      end
    end
  end
end
