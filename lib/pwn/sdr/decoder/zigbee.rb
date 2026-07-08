# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # IEEE 802.15.4 / ZigBee decoder for the 2.405–2.480 GHz allocation.
      # 250 kbit/s O-QPSK requires raw I/Q; this drives KillerBee's `zbdump`
      # (with any supported adapter — CC2531, ApiMote, RZUSB, HackRF via
      # gr-ieee802-15-4) or falls back to `whsniff` piped through `tshark`
      # for structured PAN/src/dst/cmd extraction.
      module ZigBee
        TSHARK_FIELDS = %w[
          frame.time_relative
          wpan.src16
          wpan.dst16
          wpan.src64
          wpan.dst64
          wpan.dst_pan
          wpan.frame_type
          zbee_nwk.cmd.id
          wpan.seq_no
        ].freeze

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ZigBee.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          # 802.15.4 ch11..26 → 2405 + 5*(ch-11) MHz
          ch = (((hz - 2_405_000_000) / 5_000_000.0).round + 11).clamp(11, 26)

          tshark = ['tshark', '-r', '-', '-l', '-T', 'fields', '-E', 'separator=|']
          TSHARK_FIELDS.each { |f| tshark.push('-e', f) }

          inner = "whsniff -c #{ch} 2>/dev/null | #{Shellwords.join(tshark)}"
          direct_cmd = "bash -c #{Shellwords.escape(inner)}"

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'ZigBee',
            required_bins: %w[whsniff tshark],
            direct_cmd: direct_cmd,
            line_match: /\S/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ZigBee.parse_line(line: 't|src16|dst16|src64|dst64|pan|type|cmd|seq')

        public_class_method def self.parse_line(opts = {})
          f = opts[:line].to_s.split('|', -1)
          out = {
            protocol: 'ZigBee',
            src16: f[1], dst16: f[2],
            src64: f[3], dst64: f[4],
            pan_id: f[5], frame_type: f[6],
            nwk_cmd: f[7], seq: f[8]
          }.reject { |_, v| v.to_s.empty? }
          out[:summary] = "ZigBee PAN=#{out[:pan_id]} #{out[:src16] || out[:src64]}→#{out[:dst16] || out[:dst64]} type=#{out[:frame_type]}"
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

            NOTE: Requires `whsniff` (CC2531) or KillerBee, plus `tshark`.
                  Channel is derived from freq_obj[:freq] (11–26).

            #{self}.parse_line(line: '0.1|0x0001|0xffff||||0x01||42')

            #{self}.authors
          "
        end
      end
    end
  end
end
