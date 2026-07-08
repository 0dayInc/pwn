# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby IEEE 802.15.4 / ZigBee activity detector.
      #
      # 250 kbit/s O-QPSK across 2 MHz channels — native mode reports
      # per-channel packet bursts and derives channel 11–26 from
      # freq_obj. `parse_line` retained for offline pipe-delimited
      # analysis.
      module ZigBee
        TSHARK_FIELDS = %w[
          frame.time_relative wpan.src16 wpan.dst16 wpan.src64 wpan.dst64
          wpan.dst_pan wpan.frame_type zbee_nwk.cmd.id wpan.seq_no
        ].freeze

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ZigBee.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          ch = (((hz - 2_405_000_000) / 5_000_000.0).round + 11).clamp(11, 26)
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'ZigBee',
            note: '250 kbit/s O-QPSK — native mode reports 802.15.4 packet bursts only.',
            threshold: 8.0,
            describe: proc { |b|
              octets = (b[:duration_ms] * 250 / 8).round
              { modulation: 'O-QPSK', channel: ch, est_octets: octets, classification: octets < 20 ? 'ACK/beacon' : 'data-frame' }
            }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ZigBee.parse_line(line: 't|src16|dst16|src64|dst64|pan|type|cmd|seq')

        public_class_method def self.parse_line(opts = {})
          f = opts[:line].to_s.split('|', -1)
          out = {
            protocol: 'ZigBee', src16: f[1], dst16: f[2], src64: f[3], dst64: f[4],
            pan_id: f[5], frame_type: f[6], nwk_cmd: f[7], seq: f[8]
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
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: '0.1|0x0001|0xffff||||0x01||42')

            #{self}.authors
          "
        end
      end
    end
  end
end
