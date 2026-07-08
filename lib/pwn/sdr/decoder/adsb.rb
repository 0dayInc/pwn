# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # ADS-B (Automatic Dependent Surveillance – Broadcast) decoder for
      # aircraft transponder squitters on 1090 MHz (Mode-S / ES) and 978 MHz
      # (UAT). 2 Mbit/s PPM cannot be recovered from GQRX audio, so this
      # module drives `dump1090` (or `dump978-fa`) directly against the SDR
      # and structures each SBS-1/BaseStation CSV line it emits on stdout.
      module ADSB
        SBS_FIELDS = %i[
          msg_type tx_type session_id aircraft_id icao24 flight_id
          date_gen time_gen date_log time_log callsign altitude_ft
          ground_speed_kt track_deg lat lon vertical_rate_fpm squawk
          alert emergency spi on_ground
        ].freeze

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ADSB.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz   = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          gain = (freq_obj[:rf_gain] || 40).to_s.to_f
          uat  = hz.between?(977_000_000, 979_000_000)

          direct_cmd =
            if uat && PWN::SDR::Decoder::Base.bin_available?(bin: 'dump978-fa')
              "bash -c #{Shellwords.escape("dump978-fa --sdr driver=rtlsdr --sdr-gain #{gain} --raw-stdout 2>/dev/null | uat2text")}"
            elsif PWN::SDR::Decoder::Base.bin_available?(bin: 'dump1090-fa')
              "dump1090-fa --device-type rtlsdr --gain #{gain} --net-sbs-stdout --quiet"
            else
              "dump1090 --gain #{gain} --net-sbs-stdout --quiet"
            end

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: uat ? 'ADSB-UAT978' : 'ADSB-1090ES',
            required_bins: uat ? %w[dump978-fa uat2text] : %w[dump1090],
            direct_cmd: direct_cmd,
            line_match: /^(MSG,|-|\+)/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ADSB.parse_line(line: 'MSG,3,1,1,ABCDEF,...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          return { protocol: 'ADSB-UAT', summary: line.strip } unless line.start_with?('MSG,')

          f   = line.split(',', -1)
          out = { protocol: 'ADSB' }
          SBS_FIELDS.each_with_index { |k, i| out[k] = f[i] unless f[i].to_s.empty? }

          bits = []
          bits << "ICAO=#{out[:icao24]}" if out[:icao24]
          bits << "CS=#{out[:callsign].to_s.strip}" if out[:callsign]
          bits << "ALT=#{out[:altitude_ft]}ft" if out[:altitude_ft]
          bits << "POS=#{out[:lat]},#{out[:lon]}" if out[:lat] && out[:lon]
          bits << "GS=#{out[:ground_speed_kt]}kt" if out[:ground_speed_kt]
          bits << "SQK=#{out[:squawk]}" if out[:squawk]
          out[:summary] = "ADSB #{bits.join(' ')}".strip
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

            NOTE: Requires `dump1090` (1090 MHz Mode-S/ES) or
                  `dump978-fa` + `uat2text` (978 MHz UAT). Owns the SDR
                  directly — set freq_obj[:sdr_args] if GQRX has device 0.

            #{self}.parse_line(line: 'MSG,3,1,1,ABCDEF,1,...')

            #{self}.authors
          "
        end
      end
    end
  end
end
