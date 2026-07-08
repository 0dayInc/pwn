# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby Bluetooth Classic (BR/EDR) & BLE activity detector.
      #
      # 1 Mbit/s GFSK with 79 (BR/EDR) or 40 (BLE) FHSS channels — native
      # mode reports per-channel hop bursts and derives channel index from
      # freq_obj. `parse_line` retained for offline text analysis.
      module Bluetooth
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Bluetooth.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz  = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          ble = freq_obj[:ble] || freq_obj[:mode].to_s.casecmp('ble').zero?
          ch  = ble ? ((hz - 2_402_000_000) / 2_000_000).clamp(0, 39) : ((hz - 2_402_000_000) / 1_000_000).clamp(0, 78)
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: ble ? 'BLE' : 'BT-BR/EDR',
            note: '1 Mbit/s GFSK FHSS — native mode reports single-channel hop bursts only.',
            threshold: 9.0,
            describe: proc { |b|
              { modulation: 'GFSK', channel: ch, hop_slots: (b[:duration_ms] / 0.625).round, classification: ble && [37, 38, 39].include?(ch) ? 'BLE-advertising' : 'data-hop' }
            }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Bluetooth.parse_line(line: 'systime=... LAP=9e8b33 ...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'Bluetooth' }
          out[:lap]      = ::Regexp.last_match(1) if line =~ /LAP[=: ]([0-9a-fA-F]{6})/
          out[:uap]      = ::Regexp.last_match(1) if line =~ /UAP[=: ]([0-9a-fA-F]{2})/
          out[:bd_addr]  = ::Regexp.last_match(1) if line =~ /(?:AdvA|BD_ADDR)[=: ]([0-9a-fA-F:]{12,17})/
          out[:pdu_type] = ::Regexp.last_match(1) if line =~ /\b(ADV_\w+|SCAN_\w+|CONNECT_REQ)\b/
          out[:channel]  = ::Regexp.last_match(1) if line =~ /ch[=: ]?(\d{1,2})\b/i
          out[:rssi]     = ::Regexp.last_match(1) if line =~ /rssi[=: ]?(-?\d+)/i
          out[:summary]  = "BT #{out.values_at(:pdu_type, :bd_addr, :lap).compact.join(' ')}".strip
          out.compact
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

            #{self}.parse_line(line: 'systime=... ch=37 LAP=9e8b33 ...')

            #{self}.authors
          "
        end
      end
    end
  end
end
