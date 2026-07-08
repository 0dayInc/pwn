# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby RFID activity detector for LF (125/134 kHz), HF
      # (13.56 MHz) and UHF (860–960 MHz EPC Gen2).
      #
      # Near-field ASK/load-modulation on LF/HF requires an inductive
      # coupler (not an SDR antenna); UHF backscatter is 40–640 kbps ASK.
      # Native mode reports reader-carrier presence and tag-response
      # bursts by band. `parse_line` retained for offline text analysis.
      module RFID
        # Supported Method Parameters::
        # PWN::SDR::Decoder::RFID.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          band = if hz < 1_000_000 then 'LF'
                 elsif hz.between?(13_000_000, 14_000_000) then 'HF'
                 else 'UHF'
                 end
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: "RFID-#{band}",
            note: 'Native mode reports reader-carrier and tag-backscatter bursts by band.',
            threshold: 6.0,
            describe: proc { |b|
              kind = case band
                     when 'LF'  then b[:duration_ms] > 100 ? 'reader-CW' : 'EM4x/HID-response'
                     when 'HF'  then b[:duration_ms] > 5   ? 'ISO14443-REQA/frame' : 'ISO15693-slot'
                     else            b[:duration_ms] > 20  ? 'reader-Query' : 'EPC-backscatter'
                     end
              { band: band, modulation: 'ASK/load-mod', classification: kind }
            }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RFID.parse_line(line: 'UID: 04 A1 B2 C3 D4 E5 F6')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'RFID' }
          out[:uid]  = ::Regexp.last_match(1).delete(' ') if line =~ /UID[:=]?\s*((?:[0-9A-Fa-f]{2}\s*){4,10})/
          out[:epc]  = ::Regexp.last_match(1) if line =~ /EPC[:=]?\s*([0-9A-Fa-f]+)/
          out[:atqa] = ::Regexp.last_match(1) if line =~ /ATQA[:=]?\s*([0-9A-Fa-f ]+)/
          out[:sak]  = ::Regexp.last_match(1) if line =~ /SAK[:=]?\s*([0-9A-Fa-f]+)/
          out[:tag]  = ::Regexp.last_match(1) if line =~ /(EM4\w+|HID\w*|Mifare\w*|NTAG\w*|ISO\s?\d+)/i
          out[:summary] = "RFID #{out[:tag]} UID=#{out[:uid] || out[:epc]}".squeeze(' ')
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

            #{self}.parse_line(line: 'UID: 04 A1 B2 C3 D4 E5 F6  SAK: 08  Mifare Classic 1K')

            #{self}.authors
          "
        end
      end
    end
  end
end
