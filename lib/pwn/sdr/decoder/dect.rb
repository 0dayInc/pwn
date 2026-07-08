# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # DECT (Digital Enhanced Cordless Telecommunications) decoder for the
      # 1.880–1.900 GHz (EU) / 1.920–1.930 GHz (US DECT-6.0) allocation.
      # 1.152 Mbit/s GFSK across 10 TDMA carriers requires raw I/Q; this
      # module drives gr-dect2's `dect_cli` (or the `re-DECTed` toolkit)
      # directly and structures each RFPI/PP scan line.
      module DECT
        # Supported Method Parameters::
        # PWN::SDR::Decoder::DECT.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          # DECT carriers are 1.728 MHz apart; ch0 = 1 897.344 MHz (EU).
          ch = ((1_897_344_000 - hz) / 1_728_000.0).round.clamp(0, 9)

          direct_cmd =
            if PWN::SDR::Decoder::Base.bin_available?(bin: 'dect_cli')
              "dect_cli -s #{ch}"
            else
              "dectrx -c #{ch}"
            end

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'DECT',
            required_bins: %w[dect_cli],
            direct_cmd: direct_cmd,
            line_match: /(RFPI|FP|PP|slot|carrier|RSSI)/i,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::DECT.parse_line(line: 'RFPI: 01 23 45 67 89 slot 4 carrier 3 RSSI -55')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'DECT' }
          out[:rfpi]    = ::Regexp.last_match(1).delete(' ') if line =~ /RFPI[:=]?\s*((?:[0-9A-Fa-f]{2}\s*){5})/
          out[:slot]    = ::Regexp.last_match(1) if line =~ /slot\s*(\d+)/i
          out[:carrier] = ::Regexp.last_match(1) if line =~ /carrier\s*(\d+)/i
          out[:rssi]    = ::Regexp.last_match(1) if line =~ /RSSI[:=]?\s*(-?\d+)/i
          out[:role]    = ::Regexp.last_match(1) if line =~ /\b(FP|PP)\b/
          out[:summary] = "DECT RFPI=#{out[:rfpi]} slot=#{out[:slot]} carrier=#{out[:carrier]}"
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

            NOTE: Requires gr-dect2's `dect_cli` (or re-DECTed `dectrx`).
                  Owns the SDR directly.

            #{self}.parse_line(line: 'RFPI: 01 23 45 67 89 slot 4 carrier 3')

            #{self}.authors
          "
        end
      end
    end
  end
end
