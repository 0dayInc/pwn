# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # GPS L1 C/A (1575.42 MHz) true-air acquisition.
      #
      # Parallel-code-phase search: 1 ms of I/Q resampled to 2.046 Msps
      # (2 samp/chip), FFT-correlated (via PWN::FFI::FFTW.cfft) against
      # each PRN 1..32 Gold code across ±5 kHz Doppler in 500 Hz steps.
      # Emits {prn:, doppler_hz:, code_phase_chips:, cn0_db_hz:} for every
      # satellite whose peak/next-peak ratio clears threshold — the same
      # cold-start acquisition every GNSS receiver runs, no gnss-sdr binary.
      module GPS
        CHIP_RATE   = 1_023_000
        ACQ_RATE    = 2_046_000 # 2 samp/chip → 2046-point FFT
        DOPP_RANGE  = 5000
        DOPP_STEP   = 500
        ACQ_THRESH  = 2.5 # peak / mean ratio

        # Streaming L1 C/A acquisition demod for Base.run_iq.
        class DemodIQ
          def initialize(rate:)
            @rate  = rate.to_f
            @buf   = []
            @seen  = {}
            @codes = {}
          end

          def feed_iq(samples, rate: nil)
            @rate = rate.to_f if rate
            @buf.concat(samples)
            need = (@rate / 1000.0 * 2).ceil * 2 # 1 ms complex + headroom
            return if @buf.length < need * 2

            ms = PWN::SDR::Decoder::DSP.resample_iq(
              iq: @buf.shift(need * 2), src_rate: @rate, dst_rate: ACQ_RATE
            )[0, 2046 * 2]
            return if ms.nil? || ms.length < 2046 * 2

            hits = acquire(ms)
            hits.each do |h|
              key = "PRN#{h[:prn]}"
              next if @seen[key] && (@seen[key] - h[:cn0_db_hz]).abs < 1.5

              @seen[key] = h[:cn0_db_hz]
              yield h
            end
          end

          private

          def code_fft(prn)
            @codes[prn] ||= begin
              chips = PWN::SDR::Decoder::DSP.ca_code(prn: prn)
              # upsample to 2 samp/chip, complex (Q=0)
              iq = Array.new(2046 * 2, 0.0)
              2046.times { |i| iq[i * 2] = chips[i / 2] }
              PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: iq, n: 2046) : PWN::SDR::Decoder::DSP.dft_naive(iq: iq, n: 2046)
            end
          end

          def acquire(ms_iq)
            out = []
            (1..32).each do |prn|
              cf = code_fft(prn)
              best = { peak: 0.0, dopp: 0, code: 0, floor: 1.0 }
              (-DOPP_RANGE..DOPP_RANGE).step(DOPP_STEP) do |fd|
                mixed = PWN::SDR::Decoder::DSP.mix_iq(iq: ms_iq, rate: ACQ_RATE, freq: fd)
                sig_f = PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: mixed, n: 2046) : PWN::SDR::Decoder::DSP.dft_naive(iq: mixed, n: 2046)
                # X = FFT(sig) · conj(FFT(code)); corr = |IFFT(X)|
                x_iq = Array.new(2046 * 2)
                2046.times do |k|
                  ar, ai = sig_f[k]
                  br, bi = cf[k]
                  x_iq[k * 2]       = (ar * br) + (ai * bi)
                  x_iq[(k * 2) + 1] = (ai * br) - (ar * bi)
                end
                corr = PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: x_iq, n: 2046, sign: :backward) : PWN::SDR::Decoder::DSP.dft_naive(iq: x_iq, n: 2046)
                mag = corr.map { |re, im| (re * re) + (im * im) }
                pk_i = mag.each_with_index.max_by(&:first).last
                pk   = mag[pk_i]
                # exclude ±2 chips around peak for floor estimate
                floor = (mag.sum - mag[[pk_i - 4, 0].max, 9].sum) / (mag.length - 9)
                best = { peak: pk, floor: floor, dopp: fd, code: pk_i } if pk / floor > best[:peak] / [best[:floor], 1e-12].max
              end
              ratio = best[:peak] / [best[:floor], 1e-12].max
              next unless ratio >= ACQ_THRESH

              cn0 = 10.0 * Math.log10(ratio * 1000.0) # 1 ms coherent
              out << {
                protocol: 'GPS', event: 'acquisition', modulation: 'BPSK/DSSS',
                prn: prn, doppler_hz: best[:dopp],
                code_phase_chips: (best[:code] / 2.0).round(1),
                peak_to_floor: ratio.round(2), cn0_db_hz: cn0.round(1),
                summary: "GPS PRN#{prn} acquired: Doppler=#{best[:dopp]}Hz code=#{(best[:code] / 2.0).round(1)} C/N0≈#{cn0.round(1)}dB-Hz"
              }
            end
            out
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GPS.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_048_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: 'GPS-L1CA',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: 'BPSK/DSSS 1.023 Mcps — I/Q→FFT parallel-code-phase acquisition (PWN::FFI::FFTW) → PRN/Doppler/C-N0.',
            describe: proc { |_b| { modulation: 'BPSK/DSSS', chip_rate: CHIP_RATE } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'GPS' }
          out[:prn]  = ::Regexp.last_match(1) if line =~ /PRN[ =]?(\d{1,2})/
          out[:cn0]  = ::Regexp.last_match(1) if line =~ /CN0[ =]?([\d.]+)/i
          out[:lat]  = ::Regexp.last_match(1) if line =~ /Lat(?:itude)?\s*=\s*(-?[\d.]+)/i
          out[:lon]  = ::Regexp.last_match(1) if line =~ /Long(?:itude)?\s*=\s*(-?[\d.]+)/i
          out[:alt]  = ::Regexp.last_match(1) if line =~ /Height\s*=\s*(-?[\d.]+)/i
          out[:nmea] = line if line.start_with?('$G')
          out[:summary] = out[:lat] ? "GPS FIX #{out[:lat]},#{out[:lon]}" : "GPS PRN#{out[:prn]} CN0=#{out[:cn0]}"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE (true-air I/Q via PWN::FFI + detector fallback):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq',
              source:   'optional - :auto|:rtlsdr|:adalm_pluto|:file',
              file:     'optional - .cu8/.cs16 capture (≥2.048 Msps)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
