# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # Bluetooth Classic (BR/EDR) & BLE advertising decoder for 2.402–2.480 GHz.
      #
      # 1 Mbit/s GFSK with 79 (BR/EDR) or 40 (BLE) FHSS channels cannot be
      # recovered from GQRX audio. This module drives an Ubertooth One via
      # `ubertooth-rx` (LAP/UAP discovery) or `ubertooth-btle -f -p` (BLE
      # advertising follow) directly and structures each output line.
      module Bluetooth
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Bluetooth.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          ble = freq_obj[:ble] || freq_obj[:mode].to_s.casecmp('ble').zero?
          direct_cmd = ble ? 'ubertooth-btle -f -p' : 'ubertooth-rx -z'

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: ble ? 'BLE' : 'BT-BR/EDR',
            required_bins: [ble ? 'ubertooth-btle' : 'ubertooth-rx'],
            direct_cmd: direct_cmd,
            line_match: /(LAP|AdvA|ADV_|SCAN_|BD_ADDR|systime)/i,
            parser: proc { |line| parse_line(line: line) }
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
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: Requires an Ubertooth One and `ubertooth-rx` /
                  `ubertooth-btle`. Set freq_obj[:ble] = true for BLE mode.

            #{self}.parse_line(line: 'systime=... ch=37 LAP=9e8b33 ...')

            #{self}.authors
          "
        end
      end
    end
  end
end
