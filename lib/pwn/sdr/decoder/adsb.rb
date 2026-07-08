# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby ADS-B (1090 MHz Mode-S / 978 MHz UAT) activity detector.
      #
      # Mode-S Extended Squitter is 2 Mbit/s PPM with 8/120 μs frames on a
      # 2 MHz-wide channel — physically unrecoverable from GQRX's 48 kHz
      # demodulated-audio tap. Rather than shell out to `dump1090`, this
      # module runs Base.run_detector to characterise squitter density
      # (bursts/sec, peak dBFS, floor) natively in Ruby. `parse_line` is
      # retained for offline SBS-1 CSV analysis.
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
          hz  = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          uat = hz.between?(977_000_000, 979_000_000)
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: uat ? 'ADSB-UAT978' : 'ADSB-1090ES',
            note: '2 Mbit/s PPM squitters exceed the 48 kHz audio-tap Nyquist limit; native mode reports squitter-burst density only. Feed captured SBS-1 CSV to .parse_line for full field decode.',
            describe: proc { |b| { modulation: 'PPM', frame_len_us: 120, classification: b[:duration_ms] < 5 ? 'squitter' : 'interrogation-train' } }
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
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: 'MSG,3,1,1,ABCDEF,1,...')

            #{self}.authors
          "
        end
      end
    end
  end
end
