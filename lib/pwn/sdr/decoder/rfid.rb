# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # RFID decoder covering LF (125/134 kHz), HF (13.56 MHz) and UHF
      # (860–960 MHz EPC Gen2). Near-field ASK/load-modulation is not
      # recoverable from GQRX audio, so this drives a Proxmark3 (LF/HF) via
      # `pm3 -c '...'` or `nfc-list` (HF), and `rtl_433` in flex/analyzer mode
      # for UHF backscatter — whichever tool is present.
      module RFID
        # Supported Method Parameters::
        # PWN::SDR::Decoder::RFID.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])

          direct_cmd, bins, proto =
            if hz < 1_000_000
              ["pm3 -c 'lf search'", %w[pm3], 'RFID-LF']
            elsif hz.between?(13_000_000, 14_000_000)
              if PWN::SDR::Decoder::Base.bin_available?(bin: 'pm3')
                ["pm3 -c 'hf search'", %w[pm3], 'RFID-HF']
              else
                ['nfc-list -v', %w[nfc-list], 'RFID-HF']
              end
            else
              ["rtl_433 -f #{hz} -A -F json", %w[rtl_433], 'RFID-UHF']
            end

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: proto,
            required_bins: bins,
            direct_cmd: direct_cmd,
            line_match: /(UID|EPC|TAG|ATQA|SAK|EM4|HID|ISO|Chipset|"model")/i,
            parser: proc { |line| parse_line(line: line) }
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
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: LF/HF need a Proxmark3 (`pm3`) or libnfc reader; UHF uses
                  `rtl_433 -A`. Band chosen automatically from freq_obj[:freq].

            #{self}.parse_line(line: 'UID: 04 A1 B2 C3 D4 E5 F6  SAK: 08  Mifare Classic 1K')

            #{self}.authors
          "
        end
      end
    end
  end
end
