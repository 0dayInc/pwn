# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # True-air + detector-fallback decoder for GPS.
      # Prefers PWN::FFI I/Q (RTL-SDR / ADALM-Pluto / HackRF / capture file)
      # via Base.run_iq; degrades to Base.run_detector with no hardware.
      module GPS
        # Streaming I/Q energy/burst demod for Base.run_iq.
        class DemodIQ
          def initialize(rate:, protocol:, modulation:, extra: {})
            @rate = rate.to_f
            @protocol = protocol
            @modulation = modulation
            @extra = extra
            @floor = nil
            @in_burst = false
            @burst_t0 = nil
            @peak = -200.0
            @burst_n = 0
            @threshold = (extra[:threshold] || 8.0).to_f
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            m2 = PWN::SDR::Decoder::DSP.mag_sq(iq: samples)
            hop = [(@rate / 1000.0).round, 1].max
            i = 0
            while i < m2.length
              win = m2[i, hop]
              break if win.nil? || win.empty?

              ms = win.sum / win.length
              lvl = ms.positive? ? (10.0 * Math.log10(ms)) : -120.0
              @floor = @floor.nil? ? lvl : ((@floor * 0.98) + (lvl * 0.02))
              delta = lvl - @floor
              if delta >= @threshold
                unless @in_burst
                  @in_burst = true
                  @burst_t0 = Time.now
                  @peak = lvl
                end
                @peak = lvl if lvl > @peak
              elsif @in_burst
                @in_burst = false
                @burst_n += 1
                dur_ms = ((Time.now - @burst_t0) * 1000).round
                msg = {
                  protocol: @protocol, event: 'burst', source: 'iq',
                  burst_no: @burst_n, peak_dbfs: @peak.round(1),
                  floor_dbfs: @floor.round(1), delta_db: (@peak - @floor).round(1),
                  duration_ms: dur_ms, modulation: @modulation,
                  sample_rate: @rate.to_i
                }.merge(@extra.except(:threshold))
                # protocol-specific enrichment
                msg.merge!(self.class.enrich(msg)) if self.class.respond_to?(:enrich)
                msg[:summary] = format(
                  '%<p>s IQ-burst #%<n>d peak=%<pk>+.1f dBFS Δ=%<d>.1f dB dur=%<ms>d ms',
                  p: @protocol, n: @burst_n, pk: @peak, d: @peak - @floor, ms: dur_ms
                )
                yield msg if block_given?
              end
              i += hop
            end
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GPS.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]

          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_048_000).to_i
          proto = 'GPS'
          demod = DemodIQ.new(
            rate: rate, protocol: proto, modulation: 'BPSK/DSSS',
            extra: { threshold: 3.0 }
          )
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: demod,
            threshold: 3.0,
            note: 'BPSK/DSSS 1.023 Mcps — true-air I/Q path reports composite L1 energy; PRN acquisition is layered on FFTW when available.',
            describe: proc { |_b| { modulation: 'BPSK/DSSS', chip_rate: 1_023_000 } }
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
          out[:utc]  = ::Regexp.last_match(1) if line =~ /UTC\s*=?\s*([\d:.-]+T?[\d:.]*)/
          out[:nmea] = line if line.start_with?('$G')
          out[:summary] = if out[:lat]
                            "GPS FIX #{out[:lat]},#{out[:lon]} alt=#{out[:alt]}m"
                          elsif out[:prn]
                            "GPS PRN#{out[:prn]} CN0=#{out[:cn0]}"
                          else
                            "GPS #{line[0, 100]}"
                          end
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
              file:     'optional - .cu8/.cs16 capture'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
