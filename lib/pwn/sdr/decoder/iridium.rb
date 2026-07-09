# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # True-air + detector-fallback decoder for Iridium.
      # Prefers PWN::FFI I/Q (RTL-SDR / ADALM-Pluto / HackRF / capture file)
      # via Base.run_iq; degrades to Base.run_detector with no hardware.
      module Iridium
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
        # PWN::SDR::Decoder::Iridium.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]

          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_000_000).to_i
          proto = 'IRIDIUM'
          demod = DemodIQ.new(
            rate: rate, protocol: proto, modulation: 'DE-QPSK',
            extra: { threshold: 7.0 }
          )
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: demod,
            threshold: 7.0,
            note: '25 kbit/s DE-QPSK — true-air I/Q path reports burst timing/energy.',
            describe: proc { |b| { modulation: 'DE-QPSK', symbol_rate: 25_000, classification: b[:duration_ms] < 10 ? 'simplex-burst' : 'duplex-frame' } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'IRIDIUM' }
          out[:frame_type] = ::Regexp.last_match(1) if line =~ /^([A-Z]{3}):/
          out[:sat]        = ::Regexp.last_match(1) if line =~ /sat:(\d+)/
          out[:beam]       = ::Regexp.last_match(1) if line =~ /beam:(\d+)/
          out[:pos]        = ::Regexp.last_match(1) if line =~ /pos=\(([^)]+)\)/
          out[:ra_id]      = ::Regexp.last_match(1) if line =~ /ric:(\d+)/
          out[:summary]    = "IRIDIUM #{out[:frame_type]} sat=#{out[:sat]} beam=#{out[:beam]}"
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
