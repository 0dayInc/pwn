# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # GSM (2G) broadcast-channel decoder.
      #
      # GSM is 270.833 kbit/s GMSK — it CANNOT be recovered from GQRX's 48 kHz
      # demodulated-audio UDP tap. This module therefore drives the SDR
      # directly via `grgsm_livemon_headless` (from gr-gsm) which publishes
      # decoded Um bursts as GSMTAP on udp/4729, then reads them back with
      # `tshark` for structured field extraction (MCC/MNC/LAC/CI/ARFCN, paging
      # IMSIs/TMSIs, System Information messages, etc.).
      #
      # Interface matches PWN::SDR::Decoder::Flex / ::RDS so the GQRX
      # dispatcher (`decoder: :gsm`) works uniformly.
      module GSM
        # Supported Method Parameters::
        # PWN::SDR::Decoder::GSM.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz   = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          gain = (freq_obj[:rf_gain] || 40).to_s.to_f

          tshark_fields = %w[
            frame.time
            gsmtap.arfcn
            gsmtap.chan_type
            gsm_a.imsi
            gsm_a.tmsi
            e212.mcc
            e212.mnc
            gsm_a.lac
            gsm_a.bssmap.cell_ci
            gsm_a.dtap.msg_rr_type
          ]

          direct_cmd = "sh -c 'grgsm_livemon_headless -f #{hz} -g #{gain} >/dev/null 2>&1 & " \
                       'LMPID=$!; trap "kill $LMPID 2>/dev/null" EXIT; sleep 2; ' \
                       'tshark -i lo -l -Y gsmtap -T fields -E separator=\| ' \
                       "#{tshark_fields.map { |f| "-e #{f}" }.join(' ')}'"

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'GSM',
            required_bins: %w[grgsm_livemon_headless tshark],
            direct_cmd: direct_cmd,
            line_match: /\S/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GSM.parse_line(line: 'ts|arfcn|chan|imsi|tmsi|mcc|mnc|lac|ci|rr')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          f = line.split('|', -1)
          out = {
            protocol: 'GSM',
            arfcn: f[1],
            chan_type: f[2],
            imsi: f[3],
            tmsi: f[4],
            mcc: f[5],
            mnc: f[6],
            lac: f[7],
            cell_id: f[8],
            rr_msg_type: f[9]
          }.reject { |_, v| v.to_s.empty? }

          if out[:imsi].to_s.length.between?(14, 16)
            out[:imsi_mcc]  = out[:imsi][0, 3]
            out[:imsi_mnc]  = out[:imsi][3, 3]
            out[:imsi_msin] = out[:imsi][6..]
          end

          summary_bits = []
          summary_bits << "ARFCN=#{out[:arfcn]}" if out[:arfcn]
          summary_bits << "MCC/MNC=#{out[:mcc]}/#{out[:mnc]}" if out[:mcc]
          summary_bits << "LAC=#{out[:lac]} CI=#{out[:cell_id]}" if out[:lac]
          summary_bits << "IMSI=#{out[:imsi]}" if out[:imsi]
          summary_bits << "TMSI=#{out[:tmsi]}" if out[:tmsi]
          out[:summary] = "GSM #{summary_bits.join(' ')}".strip
          out
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: Requires `grgsm_livemon_headless` (gr-gsm) and `tshark`.
                  GSM cannot be decoded from GQRX's 48 kHz audio tap; this
                  module drives the SDR directly and reads GSMTAP on lo:4729.

            #{self}.parse_line(line: 'ts|arfcn|chan|imsi|tmsi|mcc|mnc|lac|ci|rr')

            #{self}.authors
          "
        end
      end
    end
  end
end
