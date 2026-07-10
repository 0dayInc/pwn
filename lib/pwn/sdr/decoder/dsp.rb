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
          if native && n >= 64 && PWN::FFI.available?(mod: :Volk)
            begin
              return PWN::FFI::Volk.magnitude_squared(iq: iq)
            rescue StandardError
              # fall through
            end
          end
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

        CA_G2_TAPS = {
          1 => [2, 6], 2 => [3, 7], 3 => [4, 8], 4 => [5, 9], 5 => [1, 9],
          6 => [2, 10], 7 => [1, 8], 8 => [2, 9], 9 => [3, 10], 10 => [2, 3],
          11 => [3, 4], 12 => [5, 6], 13 => [6, 7], 14 => [7, 8], 15 => [8, 9],
          16 => [9, 10], 17 => [1, 4], 18 => [2, 5], 19 => [3, 6], 20 => [4, 7],
          21 => [5, 8], 22 => [6, 9], 23 => [1, 3], 24 => [4, 6], 25 => [5, 7],
          26 => [6, 8], 27 => [7, 9], 28 => [8, 10], 29 => [1, 6], 30 => [2, 7],
          31 => [3, 8], 32 => [4, 9]
        }.freeze

        # ── True-air I/Q chain (all Decoder::* modules) ──────────────────

        # Supported Method Parameters::
        # out = PWN::SDR::Decoder::DSP.resample_iq(
        #   iq: 'required - interleaved [I0,Q0,…] Array<Float>',
        #   src_rate: 'required - Hz', dst_rate: 'required - Hz'
        # )

        public_class_method def self.resample_iq(opts = {})
          iq  = opts[:iq]
          src = opts[:src_rate].to_f
          dst = opts[:dst_rate].to_f
          return iq.dup if (src - dst).abs < 1.0 || iq.empty?

          if native && PWN::FFI.available?(mod: :Liquid)
            begin
              return PWN::FFI::Liquid.resample_iq(iq: iq, rate: dst / src)
            rescue StandardError
              # fall through
            end
          end
          n_in  = iq.length / 2
          ratio = src / dst
          n_out = (n_in / ratio).floor
          out = Array.new(n_out * 2)
          i = 0
          while i < n_out
            pos  = i * ratio
            idx  = pos.floor
            frac = pos - idx
            2.times do |c|
              a = iq[(idx * 2) + c] || 0.0
              b = iq[((idx + 1) * 2) + c] || a
              out[(i * 2) + c] = a + ((b - a) * frac)
            end
            i += 1
          end
          out
        end

        # Supported Method Parameters::
        # out = PWN::SDR::Decoder::DSP.mix_iq(
        #   iq: 'required - interleaved I/Q', rate: 'required - Hz',
        #   freq: 'required - offset Hz to shift DOWN by'
        # )

        public_class_method def self.mix_iq(opts = {})
          iq   = opts[:iq]
          rate = opts[:rate].to_f
          freq = opts[:freq].to_f
          return iq.dup if freq.abs < 1e-3 || iq.empty?

          if native && PWN::FFI.available?(mod: :Liquid)
            begin
              return PWN::FFI::Liquid.mix_down(iq: iq, freq: TWO_PI * freq / rate)
            rescue StandardError
              # fall through
            end
          end
          n = iq.length / 2
          w = TWO_PI * freq / rate
          out = Array.new(n * 2)
          i = 0
          while i < n
            ph = w * i
            c = Math.cos(ph)
            s = Math.sin(ph)
            re = iq[i * 2].to_f
            im = iq[(i * 2) + 1].to_f
            out[i * 2] = (re * c) + (im * s)
            out[(i * 2) + 1] = (im * c) - (re * s)
            i += 1
          end
          out
        end

        # Supported Method Parameters::
        # bits = PWN::SDR::Decoder::DSP.gfsk_slice(
        #   iq: 'required - interleaved I/Q', rate:, baud:,
        #   bt: 'optional - Gaussian BT (default 0.35)', invert: false
        # )
        # GFSK/GMSK/2-FSK: prefer liquid gmskdem at integer sps, else
        # fm_demod_iq → nrz_slice.

        public_class_method def self.gfsk_slice(opts = {})
          iq   = opts[:iq]
          rate = opts[:rate].to_f
          baud = opts[:baud].to_f
          bt   = (opts[:bt] || 0.35).to_f
          inv  = opts[:invert]
          return [] if iq.empty? || baud <= 0

          sps = rate / baud
          if native && PWN::FFI.available?(mod: :Liquid) && sps >= 2.0
            begin
              k = sps.round
              riq = (sps - k).abs < 0.02 ? iq : resample_iq(iq: iq, src_rate: rate, dst_rate: baud * k)
              bits = PWN::FFI::Liquid.gmsk_demod(iq: riq, sps: k, bt: bt)
              return inv ? bits.map { |b| b ^ 1 } : bits
            rescue StandardError
              # fall through
            end
          end
          audio = fm_demod_iq(iq: iq)
          nrz_slice(samples: audio, rate: rate, baud: baud, invert: inv)
        end

        # Supported Method Parameters::
        # dibits = PWN::SDR::Decoder::DSP.slice_4fsk(
        #   samples: 'required - real FM-discriminator baseband',
        #   rate:, baud:
        # )
        # → Array<0..3> per symbol (4-level decision, adaptive thresholds).
        # C4FM/4-GFSK maps +3 → 01, +1 → 00, −1 → 10, −3 → 11 in P25/DMR.

        public_class_method def self.slice_4fsk(opts = {})
          samples = opts[:samples]
          rate    = opts[:rate].to_f
          baud    = opts[:baud].to_f
          spb     = rate / baud
          return [] if spb < 2.0 || samples.empty?

          lp   = envelope_signed(samples: dc_block(samples: samples), window: [(spb / 4.0).round, 1].max)
          nsym = (lp.length / spb).floor
          # sample mid-symbol values, then quantise into 4 levels
          vals = Array.new(nsym) { |i| lp[((i + 0.5) * spb).floor] || 0.0 }
          return [] if vals.empty?

          sorted = vals.sort
          lo = sorted[(nsym * 0.1).floor] || vals.min
          hi = sorted[(nsym * 0.9).floor] || vals.max
          step = (hi - lo) / 3.0
          step = 1e-9 if step.abs < 1e-9
          t_lo = lo + step
          t_hi = hi - step
          vals.map do |v|
            if v >= t_hi then 1        # +3
            elsif v >= 0 then 0        # +1
            elsif v >= t_lo then 2     # −1
            else 3                     # −3
            end
          end
        end

        # Supported Method Parameters::
        # bits = PWN::SDR::Decoder::DSP.manchester_decode(
        #   bits: 'required - Array<0|1> at 2×data rate',
        #   ieee: 'optional - true = 01→1 10→0 (IEEE 802.3), else 10→1 01→0'
        # )

        public_class_method def self.manchester_decode(opts = {})
          bits = opts[:bits]
          ieee = opts[:ieee]
          out  = []
          i = 0
          while i < bits.length - 1
            a = bits[i]
            b = bits[i + 1]
            if a == b
              i += 1 # phase slip — resync on next transition
              next
            end
            out << (ieee ? b : a)
            i += 2
          end
          out
        end

        # Supported Method Parameters::
        # bits = PWN::SDR::Decoder::DSP.diff_decode(bits: Array<0|1>)
        # NRZ-I / DBPSK: output 1 on transition, 0 on hold.

        public_class_method def self.diff_decode(opts = {})
          bits = opts[:bits]
          prev = bits.first || 0
          out  = Array.new(bits.length - 1)
          i = 1
          while i < bits.length
            out[i - 1] = bits[i] == prev ? 0 : 1
            prev = bits[i]
            i += 1
          end
          out
        end

        # Supported Method Parameters::
        # bytes = PWN::SDR::Decoder::DSP.bytes_from_bits(
        #   bits: Array<0|1>, lsb_first: false
        # )

        public_class_method def self.bytes_from_bits(opts = {})
          bits = opts[:bits]
          lsb  = opts[:lsb_first]
          out  = []
          bits.each_slice(8) do |oct|
            next if oct.length < 8

            v = 0
            if lsb
              oct.each_with_index { |b, i| v |= (b & 1) << i }
            else
              oct.each { |b| v = (v << 1) | (b & 1) }
            end
            out << v
          end
          out
        end

        # Supported Method Parameters::
        # crc = PWN::SDR::Decoder::DSP.crc16(
        #   bytes: Array<Integer>, poly: 0x1021, init: 0xFFFF,
        #   refin: false, refout: false, xorout: 0x0000
        # )

        public_class_method def self.crc16(opts = {})
          bytes  = opts[:bytes]
          poly   = (opts[:poly]   || 0x1021).to_i
          crc    = (opts[:init]   || 0xFFFF).to_i
          refin  = opts[:refin]
          refout = opts[:refout]
          xorout = (opts[:xorout] || 0).to_i
          bytes.each do |b|
            b = Integer(format('%08b', b & 0xFF).reverse, 2) if refin
            crc ^= (b & 0xFF) << 8
            8.times do
              crc = crc.anybits?(0x8000) ? ((crc << 1) ^ poly) : (crc << 1)
              crc &= 0xFFFF
            end
          end
          crc = Integer(format('%016b', crc).reverse, 2) if refout
          crc ^ xorout
        end

        # Supported Method Parameters::
        # out = PWN::SDR::Decoder::DSP.whiten_lfsr(
        #   bytes: Array<Integer>, poly: Integer, init: Integer, width: 7
        # )
        # Galois LFSR (MSB-first). BLE: poly 0x11 (x^7+x^4+1), init (ch|0x40).

        public_class_method def self.whiten_lfsr(opts = {})
          bytes = opts[:bytes]
          poly  = opts[:poly].to_i
          reg   = opts[:init].to_i
          w     = (opts[:width] || 7).to_i
          top   = 1 << (w - 1)
          out   = Array.new(bytes.length)
          bytes.each_with_index do |byte, bi|
            v = byte & 0xFF
            8.times do |i|
              msb = reg.anybits?(top) ? 1 : 0
              reg = ((reg << 1) & ((1 << w) - 1))
              reg ^= poly if msb == 1
              v ^= (msb << i)
            end
            out[bi] = v
          end
          out
        end

        # Supported Method Parameters::
        # pulses = PWN::SDR::Decoder::DSP.ook_pulses(
        #   iq: 'required - interleaved I/Q', rate:,
        #   min_us: 'optional - drop shorter pulses (default 20)'
        # )
        # → Array of { level: 0|1, us: Float, samples: Int } run-length list.

        public_class_method def self.ook_pulses(opts = {})
          iq     = opts[:iq]
          rate   = opts[:rate].to_f
          min_us = (opts[:min_us] || 20).to_f
          m2     = mag_sq(iq: iq)
          return [] if m2.length < 32

          # Adaptive threshold: 0.5·(floor + peak) on power domain
          sorted = m2.sort
          floor  = sorted[m2.length / 10] || m2.min
          peak   = sorted[(m2.length * 9) / 10] || m2.max
          thr    = floor + ((peak - floor) * 0.5)
          us_per = 1_000_000.0 / rate
          runs = []
          state = m2.first >= thr ? 1 : 0
          cnt = 0
          m2.each do |v|
            s = v >= thr ? 1 : 0
            if s == state
              cnt += 1
            else
              runs << { level: state, us: cnt * us_per, samples: cnt } if (cnt * us_per) >= min_us
              state = s
              cnt = 1
            end
          end
          runs << { level: state, us: cnt * us_per, samples: cnt } if (cnt * us_per) >= min_us
          runs
        end

        # Supported Method Parameters::
        # mag = PWN::SDR::Decoder::DSP.cfft_mag(
        #   iq: 'required - interleaved I/Q', n: 'optional - FFT size',
        #   shift: 'optional - fftshift so DC is centred (default true)'
        # )

        public_class_method def self.cfft_mag(opts = {})
          iq = opts[:iq]
          n  = (opts[:n] || (iq.length / 2)).to_i
          sh = opts.fetch(:shift, true)
          bins =
            if native && PWN::FFI.available?(mod: :FFTW)
              begin
                PWN::FFI::FFTW.cfft(iq: iq, n: n)
              rescue StandardError
                dft_naive(iq: iq, n: n)
              end
            else
              dft_naive(iq: iq, n: n)
            end
          mag = bins.map { |re, im| Math.sqrt((re * re) + (im * im)) }
          sh ? mag.rotate(n / 2) : mag
        end

        # Naive O(n²) complex DFT — pure-Ruby fallback for small n.
        # Supported Method Parameters::
        # bins = PWN::SDR::Decoder::DSP.dft_naive(iq:, n:)

        public_class_method def self.dft_naive(opts = {})
          iq = opts[:iq]
          n  = (opts[:n] || (iq.length / 2)).to_i
          n  = [n, 512].min
          Array.new(n) do |k|
            re = 0.0
            im = 0.0
            j = 0
            while j < n
              ph = -TWO_PI * k * j / n
              c = Math.cos(ph)
              s = Math.sin(ph)
              xr = iq[j * 2].to_f
              xi = iq[(j * 2) + 1].to_f
              re += (xr * c) - (xi * s)
              im += (xr * s) + (xi * c)
              j += 1
            end
            [re, im]
          end
        end

        # Supported Method Parameters::
        # zc = PWN::SDR::Decoder::DSP.zadoff_chu(root:, n: 63)
        # Returns interleaved [I0,Q0,…] Array<Float>. LTE PSS uses roots 25/29/34.

        public_class_method def self.zadoff_chu(opts = {})
          u = opts[:root].to_i
          n = (opts[:n] || 63).to_i
          out = Array.new(n * 2)
          n.times do |k|
            ph = -Math::PI * u * k * (k + 1) / n
            out[k * 2]       = Math.cos(ph)
            out[(k * 2) + 1] = Math.sin(ph)
          end
          out
        end

        # Supported Method Parameters::
        # chips = PWN::SDR::Decoder::DSP.ca_code(prn: 1..32)
        # Returns Array<Float> of ±1.0 length 1023 (GPS L1 C/A Gold code).

        public_class_method def self.ca_code(opts = {})
          prn  = opts[:prn].to_i
          taps = CA_G2_TAPS[prn]
          raise "ERROR: PRN #{prn} unsupported" unless taps

          g1 = Array.new(10, 1)
          g2 = Array.new(10, 1)
          out = Array.new(1023)
          1023.times do |i|
            g2i = g2[taps[0] - 1] ^ g2[taps[1] - 1]
            out[i] = (g1[9] ^ g2i) == 1 ? -1.0 : 1.0
            fb1 = g1[2] ^ g1[9]
            fb2 = g2[1] ^ g2[2] ^ g2[5] ^ g2[7] ^ g2[8] ^ g2[9]
            g1.unshift(fb1)
            g1.pop
            g2.unshift(fb2)
            g2.pop
          end
          out
        end

        # Supported Method Parameters::
        # out = PWN::SDR::Decoder::DSP.cmul(a: [I,Q,…], b: [I,Q,…], conj_b: false)
        # Element-wise complex multiply (interleaved). Used for
        # correlation / dechirp: X = A · conj(B).

        public_class_method def self.cmul(opts = {})
          a = opts[:a]
          b = opts[:b]
          cj = opts[:conj_b]
          n  = [a.length, b.length].min / 2
          out = Array.new(n * 2)
          i = 0
          while i < n
            ar = a[i * 2].to_f
            ai = a[(i * 2) + 1].to_f
            br = b[i * 2].to_f
            bi = b[(i * 2) + 1].to_f
            bi = -bi if cj
            out[i * 2]       = (ar * br) - (ai * bi)
            out[(i * 2) + 1] = (ar * bi) + (ai * br)
            i += 1
          end
          out
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
#{self}.resample_iq(iq:, src_rate:, dst_rate:)     # → Liquid crcf
#{self}.mix_iq(iq:, rate:, freq:)                  # → Liquid nco
#{self}.gfsk_slice(iq:, rate:, baud:, bt: 0.35)    # → Liquid gmskdem
#{self}.slice_4fsk(samples:, rate:, baud:)         # C4FM/4-GFSK
#{self}.manchester_decode(bits:, ieee: false)
#{self}.diff_decode(bits:)
#{self}.bytes_from_bits(bits:, lsb_first: false)
#{self}.crc16(bytes:, poly: 0x1021, init: 0xFFFF)
#{self}.whiten_lfsr(bytes:, poly:, init:, width: 7)
#{self}.ook_pulses(iq:, rate:, min_us: 20)
#{self}.cfft_mag(iq:, n:, shift: true)             # → FFTW
#{self}.cmul(a:, b:, conj_b: false)
#{self}.zadoff_chu(root:, n: 63)                   # LTE PSS
#{self}.ca_code(prn: 1..32)                        # GPS L1 C/A

            Constants: MORSE_TABLE, BAUDOT_LTRS, BAUDOT_FIGS
            Backends:  PWN::FFI.backends  # { Volk: true, Liquid: true, AdalmPluto: true, … }

            #{self}.authors
          "
        end
      end
    end
  end
end
