# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby GSM (2G) BCCH activity detector.
      #
      # GSM is 270.833 kbit/s GMSK across a 200 kHz channel — physically
      # unrecoverable from a 48 kHz demodulated-audio tap and too fast for
      # interpreted Ruby to demodulate from raw I/Q in real time. Rather
      # than shell out to `grgsm_livemon_headless` + `tshark`, this module
      # runs Base.run_detector to characterise BCCH/CCCH burst structure
      # (577 μs slots × 8 = 4.615 ms TDMA frame) natively. `parse_line` is
      # retained for offline GSMTAP-tshark pipe-delimited analysis.
      module GSM
        TSHARK_FIELDS = %w[
          frame.time gsmtap.arfcn gsmtap.chan_type gsm_a.imsi gsm_a.tmsi
          e212.mcc e212.mnc gsm_a.lac gsm_a.bssmap.cell_ci gsm_a.dtap.msg_rr_type
        ].freeze

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GSM.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'GSM',
            note: '270.833 kbit/s GMSK exceeds audio-tap Nyquist; native mode reports TDMA burst duty/energy only. Feed captured GSMTAP-tshark fields to .parse_line for MCC/MNC/LAC/CI/IMSI.',
            threshold: 5.0,
            describe: proc { |b|
              frames = (b[:duration_ms] / 4.615).round
              { modulation: 'GMSK', symbol_rate: 270_833, tdma_frames: frames, classification: frames > 10 ? 'BCCH/CCCH-continuous' : 'RACH/paging-burst' }
            }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GSM.parse_line(line: 'ts|arfcn|chan|imsi|tmsi|mcc|mnc|lac|ci|rr')

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

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: 'ts|arfcn|chan|imsi|tmsi|mcc|mnc|lac|ci|rr')

            #{self}.authors
          "
        end
      end
    end
  end
end
