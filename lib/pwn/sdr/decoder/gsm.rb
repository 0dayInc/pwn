# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # GSM (2G) true-air BCCH/CCCH activity decoder.
      module GSM
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
            @carry = []
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            m2 = PWN::SDR::Decoder::DSP.mag_sq(iq: samples)
            # process in ~1 ms hops
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
                }.merge(@extra)
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
        # PWN::SDR::Decoder::GSM.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 1_000_000).to_i
          proto = 'GSM'
          extra = {}
          describe = proc { |b| { modulation: 'GMSK', symbol_rate: 270_833, tdma_frames: (b[:duration_ms] / 4.615).round, classification: (b[:duration_ms] / 4.615) > 10 ? 'BCCH/CCCH-continuous' : 'RACH/paging-burst' } }
          demod = DemodIQ.new(
            rate: rate, protocol: proto, modulation: 'GMSK',
            extra: { threshold: 5.0 }.merge(extra)
          )
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: demod,
            threshold: 5.0,
            note: '270.833 kbit/s GMSK — true-air path streams I/Q from RTL-SDR/Pluto and characterises TDMA burst duty; full Viterbi/BCCH SI decode is layered on Liquid when available.',
            describe: describe
          )
        end

        TSHARK_FIELDS = %w[
          frame.time gsmtap.arfcn gsmtap.chan_type gsm_a.imsi gsm_a.tmsi
          e212.mcc e212.mnc gsm_a.lac gsm_a.bssmap.cell_ci gsm_a.dtap.msg_rr_type
        ].freeze

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          f = line.split('|', -1)
          out = {
            protocol: 'GSM', frame_time: f[0], arfcn: f[1], chan_type: f[2],
            imsi: f[3], tmsi: f[4], mcc: f[5], mnc: f[6], lac: f[7],
            cell_id: f[8], rr_msg_type: f[9]
          }.reject { |_, v| v.to_s.empty? }
          if out[:imsi].to_s.length.between?(14, 16)
            out[:imsi_mcc]  = out[:imsi][0, 3]
            out[:imsi_mnc]  = out[:imsi][3, 3]
            out[:imsi_msin] = out[:imsi][6..]
          end
          bits = []
          bits << "ARFCN=#{out[:arfcn]}" if out[:arfcn]
          bits << "MCC/MNC=#{out[:mcc]}/#{out[:mnc]}" if out[:mcc]
          bits << "LAC=#{out[:lac]} CI=#{out[:cell_id]}" if out[:lac]
          bits << "IMSI=#{out[:imsi]}" if out[:imsi]
          bits << "TMSI=#{out[:tmsi]}" if out[:tmsi]
          out[:summary] = "GSM #{bits.join(' ')}".strip
          out
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
