# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby 802.11 (WiFi) activity detector.
      #
      # 20+ MHz OFDM cannot be demodulated in interpreted Ruby in real
      # time. Native mode reports channel occupancy/duty and maps
      # freq_obj to a WLAN channel number. `parse_line` retained for
      # offline pipe-delimited tshark-fields analysis.
      module WiFi
        TSHARK_FIELDS = %w[
          frame.time_relative wlan.fc.type_subtype wlan.bssid wlan.sa
          wlan.da wlan_radio.channel wlan_radio.signal_dbm wlan.ssid
        ].freeze

        # Supported Method Parameters::
        # PWN::SDR::Decoder::WiFi.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz  = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          mhz = (hz / 1_000_000.0).round
          ch  = case mhz
                when 2412..2472 then ((mhz - 2412) / 5) + 1
                when 2484       then 14
                when 5000..5900 then (mhz - 5000) / 5
                else 0
                end
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'WiFi-802.11',
            note: '20+ MHz OFDM — native mode reports channel occupancy/duty only.',
            threshold: 6.0,
            describe: proc { |b| { modulation: 'OFDM', channel: ch, mhz: mhz, airtime_ms: b[:duration_ms] } }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::WiFi.parse_line(line: 't|subtype|bssid|sa|da|ch|rssi|ssid')

        public_class_method def self.parse_line(opts = {})
          f = opts[:line].to_s.split('|', -1)
          out = {
            protocol: 'WiFi', subtype: f[1], bssid: f[2], sa: f[3], da: f[4],
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
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: '0.1|8|aa:bb:..|aa:bb:..|ff:ff:..|6|-42|linksys')

            #{self}.authors
          "
        end
      end
    end
  end
end
