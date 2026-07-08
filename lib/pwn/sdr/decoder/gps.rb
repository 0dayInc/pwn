# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # GNSS / GPS L1-C/A (1575.42 MHz) & L2C (1227.60 MHz) decoder. BPSK/DSSS
      # at 1.023 / 10.23 Mcps needs raw I/Q, so this drives `gnss-sdr` (or
      # `rtl_gps`) directly and structures the PVT / NMEA lines it emits
      # (satellite PRNs acquired, C/N0, computed position fix, UTC time).
      module GPS
        # Supported Method Parameters::
        # PWN::SDR::Decoder::GPS.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          conf = (freq_obj[:gnss_conf] || '/usr/share/gnss-sdr/conf/gnss-sdr_GPS_L1_rtlsdr_realtime.conf').to_s
          direct_cmd = "gnss-sdr --config_file=#{Shellwords.escape(conf)}"

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'GPS',
            required_bins: %w[gnss-sdr],
            direct_cmd: direct_cmd,
            line_match: /(PVT|Position|PRN|Tracking|\$G[PN])/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GPS.parse_line(line: 'Position at ... Lat = 32.7 [deg], Long = -97.1 ...')

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
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: Requires `gnss-sdr` and an active-antenna-biased front end.
                  Override the receiver config via freq_obj[:gnss_conf].

            #{self}.parse_line(line: 'Position ... Lat = 32.7 Long = -97.1 Height = 210')

            #{self}.authors
          "
        end
      end
    end
  end
end
