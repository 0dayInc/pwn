# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # True-air + detector-fallback decoder for RFID.
      # Prefers PWN::FFI I/Q (RTL-SDR / ADALM-Pluto / HackRF / capture file)
      # via Base.run_iq; degrades to Base.run_detector with no hardware.
      module RFID
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
        # PWN::SDR::Decoder::RFID.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          band = if hz < 1_000_000 then 'LF'
                 elsif hz.between?(13_000_000, 14_000_000) then 'HF'
                 else 'UHF'
                 end

          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_000_000).to_i
          proto = "RFID-#{band}"
          demod = DemodIQ.new(
            rate: rate, protocol: proto, modulation: 'ASK/load-mod',
            extra: { threshold: 6.0 }
          )
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: demod,
            threshold: 6.0,
            note: 'True-air I/Q path reports reader-carrier and tag-backscatter bursts by band.',
            describe: proc { |b| { band: b[:band], modulation: 'ASK/load-mod', classification: b[:classification] } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'RFID' }
          out[:uid]  = ::Regexp.last_match(1).delete(' ') if line =~ /UID[:=]?\s*((?:[0-9A-Fa-f]{2}\s*){4,10})/
          out[:epc]  = ::Regexp.last_match(1) if line =~ /EPC[:=]?\s*([0-9A-Fa-f]+)/
          out[:atqa] = ::Regexp.last_match(1) if line =~ /ATQA[:=]?\s*([0-9A-Fa-f ]+)/
          out[:sak]  = ::Regexp.last_match(1) if line =~ /SAK[:=]?\s*([0-9A-Fa-f]+)/
          out[:tag]  = ::Regexp.last_match(1) if line =~ /(EM4\w+|HID\w*|Mifare\w*|NTAG\w*|ISO\s?\d+)/i
          out[:summary] = "RFID #{out[:tag]} UID=#{out[:uid] || out[:epc]}".squeeze(' ')
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
