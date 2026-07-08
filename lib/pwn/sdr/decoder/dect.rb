# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby DECT (1.88–1.90 GHz EU / 1.92–1.93 GHz US) activity detector.
      #
      # 1.152 Mbit/s GFSK across 10 TDMA carriers — native mode reports
      # slot bursts (417 μs) and derives carrier index from freq_obj.
      # `parse_line` retained for offline text analysis.
      module DECT
        # Supported Method Parameters::
        # PWN::SDR::Decoder::DECT.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          ch = ((1_897_344_000 - hz) / 1_728_000.0).round.clamp(0, 9)
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'DECT',
            note: '1.152 Mbit/s GFSK 24-slot TDMA — native mode reports slot bursts and carrier index.',
            threshold: 7.0,
            describe: proc { |b|
              slots = (b[:duration_ms] / 0.417).round
              { modulation: 'GFSK', carrier: ch, tdma_slots: slots, classification: slots >= 24 ? 'FP-beacon-frame' : 'PP-burst' }
            }
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
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: 'RFPI: 01 23 45 67 89 slot 4 carrier 3')

            #{self}.authors
          "
        end
      end
    end
  end
end
