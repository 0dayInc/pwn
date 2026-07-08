# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # 802.11 (WiFi) beacon/probe decoder for the 2.4 / 5 / 6 GHz bands.
      #
      # 20+ MHz OFDM cannot be recovered from a general-purpose SDR at
      # bit-level in real time, so this module drives an existing monitor-mode
      # NIC via `tshark` (or `airodump-ng`) instead — freq_obj[:mon_iface]
      # selects the interface, freq_obj[:freq] is mapped to a WLAN channel.
      module WiFi
        TSHARK_FIELDS = %w[
          frame.time_relative
          wlan.fc.type_subtype
          wlan.bssid
          wlan.sa
          wlan.da
          wlan_radio.channel
          wlan_radio.signal_dbm
          wlan.ssid
        ].freeze

        # Supported Method Parameters::
        # PWN::SDR::Decoder::WiFi.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          iface = (freq_obj[:mon_iface] || 'wlan0mon').to_s
          hz    = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          mhz   = (hz / 1_000_000.0).round

          tshark = ['tshark', '-i', iface, '-I', '-l', '-n',
                    '-Y', 'wlan.fc.type == 0',
                    '-T', 'fields', '-E', 'separator=|']
          TSHARK_FIELDS.each { |f| tshark.push('-e', f) }

          inner = "iw dev #{Shellwords.escape(iface)} set freq #{mhz} 2>/dev/null; " \
                  "exec #{Shellwords.join(tshark)}"
          direct_cmd = "bash -c #{Shellwords.escape(inner)}"

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'WiFi-802.11',
            required_bins: %w[tshark iw],
            direct_cmd: direct_cmd,
            line_match: /\S/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::WiFi.parse_line(line: 't|subtype|bssid|sa|da|ch|rssi|ssid')

        public_class_method def self.parse_line(opts = {})
          f = opts[:line].to_s.split('|', -1)
          out = {
            protocol: 'WiFi',
            subtype: f[1], bssid: f[2], sa: f[3], da: f[4],
            channel: f[5], rssi_dbm: f[6], ssid: f[7]
          }.reject { |_, v| v.to_s.empty? }
          out[:summary] = "WiFi ch#{out[:channel]} #{out[:bssid]} '#{out[:ssid]}' #{out[:rssi_dbm]}dBm"
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

            NOTE: Requires a monitor-mode WLAN interface (freq_obj[:mon_iface],
                  default 'wlan0mon'), `iw`, and `tshark`. General SDRs cannot
                  demodulate 802.11 OFDM in real time.

            #{self}.parse_line(line: '0.1|8|aa:bb:..|aa:bb:..|ff:ff:..|6|-42|linksys')

            #{self}.authors
          "
        end
      end
    end
  end
end
