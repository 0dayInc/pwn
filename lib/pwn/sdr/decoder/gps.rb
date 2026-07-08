# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby GNSS / GPS L1-C/A activity detector.
      #
      # 1.023 Mcps BPSK/DSSS spread across 2 MHz — acquisition/tracking of
      # 32 PRNs in real time is not feasible in interpreted Ruby. Native
      # mode reports L1 carrier presence / C/N₀ proxy only. `parse_line`
      # retained for offline gnss-sdr / NMEA text analysis.
      module GPS
        # Supported Method Parameters::
        # PWN::SDR::Decoder::GPS.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'GPS',
            note: 'BPSK/DSSS 1.023 Mcps below thermal noise — native mode reports composite L1 energy only.',
            threshold: 3.0,
            describe: proc { |_b| { modulation: 'BPSK/DSSS', chip_rate: 1_023_000 } }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GPS.parse_line(line: 'Position at ... Lat = 32.7 [deg] ...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'GPS' }
          out[:prn]  = ::Regexp.last_match(1) if line =~ /PRN[ =]?(\d{1,2})/
          out[:cn0]  = ::Regexp.last_match(1) if line =~ /CN0[ =]?([\d.]+)/i
          out[:lat]  = ::Regexp.last_match(1) if line =~ /Lat(?:itude)?\s*=\s*(-?[\d.]+)/i
          out[:lon]  = ::Regexp.last_match(1) if line =~ /Long(?:itude)?\s*=\s*(-?[\d.]+)/i
          out[:alt]  = ::Regexp.last_match(1) if line =~ /Height\s*=\s*(-?[\d.]+)/i
          out[:utc]  = ::Regexp.last_match(1) if line =~ /UTC\s*=?\s*([\d:.-]+T?[\d:.]*)/
          out[:nmea] = line if line.start_with?('$G')
          out[:summary] = if out[:lat]
                            "GPS FIX #{out[:lat]},#{out[:lon]} alt=#{out[:alt]}m"
                          elsif out[:prn]
                            "GPS PRN#{out[:prn]} CN0=#{out[:cn0]}"
                          else
                            "GPS #{line[0, 100]}"
                          end
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

            #{self}.parse_line(line: 'Position ... Lat = 32.7 Long = -97.1 Height = 210')

            #{self}.authors
          "
        end
      end
    end
  end
end
