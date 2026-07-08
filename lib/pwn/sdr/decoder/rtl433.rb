# frozen_string_literal: true

require 'json'

module PWN
  module SDR
    module Decoder
      # Pure-Ruby ISM/keyfob/sensor activity detector for the 315 / 390 /
      # 433.92 / 868 / 915 MHz device zoo.
      #
      # The upstream `rtl_433` binary carries ~250 device-specific protocol
      # dissectors; re-implementing that library is out of scope. This
      # module instead characterises OOK/ASK/FSK bursts natively (count,
      # duration, gap, peak dBFS) — enough to fingerprint a keyfob press,
      # a periodic weather-station beacon, or a TPMS chirp — without
      # invoking any external binary. `parse_line` still accepts rtl_433
      # `-F json` output for offline analysis.
      module RTL433
        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTL433.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'ISM-433',
            note: 'Native OOK/FSK burst characteriser (no rtl_433 binary). Feed captured `rtl_433 -F json` lines to .parse_line for per-device decode.',
            threshold: 10.0,
            describe: proc { |b|
              kind = if b[:duration_ms] < 20 then 'keyfob/OOK-short'
                     elsif b[:duration_ms] < 120 then 'sensor/OOK-packet'
                     else 'FSK-continuous'
                     end
              { modulation: 'OOK/ASK/FSK', classification: kind }
            }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTL433.parse_line(line: '{"time":"...","model":"..."}')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          h = begin
            JSON.parse(line, symbolize_names: true)
          rescue StandardError
            { unparsed: line }
          end
          out = { protocol: 'RTL433' }.merge(h)
          bits = []
          bits << out[:model].to_s if out[:model]
          bits << "id=#{out[:id]}" if out[:id]
          bits << "ch=#{out[:channel]}" if out[:channel]
          bits << "code=#{out[:code]}" if out[:code]
          bits << "cmd=#{out[:cmd] || out[:button]}" if out[:cmd] || out[:button]
          bits << "temp=#{out[:temperature_C]}C" if out[:temperature_C]
          bits << "rssi=#{out[:rssi]}" if out[:rssi]
          out[:summary] = bits.empty? ? line[0, 120] : bits.join(' ')
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

            #{self}.parse_line(line: '{\"model\":\"Acurite-Tower\",\"id\":1234,...}')

            #{self}.authors
          "
        end
      end
    end
  end
end
