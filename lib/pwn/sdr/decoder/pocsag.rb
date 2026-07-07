# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # POCSAG (CCIR Radiopaging Code No. 1) decoder for pager networks.
      #
      # Pipeline: GQRX UDP audio → sox 48k→22.05k → multimon-ng POCSAG512/1200/2400.
      #
      # multimon-ng emits lines of the form:
      #   POCSAG1200: Address:  123456  Function: 3  Alpha:   FIRE ALARM ZONE 4
      #   POCSAG512:  Address:  000042  Function: 0  Numeric: 5551234
      #   POCSAG2400: Address:  987654  Function: 1  Skyper:  ...
      #   POCSAG1200: Address:  123456  Function: 2  Alpha:   <partial><EOT>
      #
      # This module parses those into { protocol, baud, address, function,
      # function_desc, type, type_desc, message } and JSON-logs each page.
      module POCSAG
        FUNCTION_DESC = {
          0 => 'Numeric (Tone/A)',
          1 => 'Tone only (B)',
          2 => 'Tone only (C)',
          3 => 'Alphanumeric (D)'
        }.freeze

        TYPE_DESC = {
          'Alpha' => 'Alphanumeric text (7-bit ASCII)',
          'Numeric' => 'Numeric-only (BCD)',
          'Skyper' => 'Skyper network encoded',
          'Tone' => 'Tone-only alert (no message body)'
        }.freeze

        # Supported Method Parameters::
        # PWN::SDR::Decoder::POCSAG.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'POCSAG',
            required_bins: %w[sox multimon-ng],
            decode_cmd: 'multimon-ng -q -t raw -e -u -p ' \
                        '-a POCSAG512 -a POCSAG1200 -a POCSAG2400 -f auto -',
            line_match: /^POCSAG(?:512|1200|2400):/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::POCSAG.parse_line(line: 'POCSAG1200: Address: ...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'POCSAG' }

          if (m = line.match(/^POCSAG(\d+):/))
            out[:baud] = m[1].to_i
          end
          if (m = line.match(/Address:\s*(\d+)/i))
            out[:address] = m[1].to_i
            out[:capcode] = m[1]
          end
          if (m = line.match(/Function:\s*(\d+)/i))
            fn = m[1].to_i
            out[:function]      = fn
            out[:function_desc] = FUNCTION_DESC[fn] || 'Unknown'
          end
          if (m = line.match(/\b(Alpha|Numeric|Skyper|Tone):\s*(.*)$/i))
            type = m[1].capitalize
            out[:type]      = type
            out[:type_desc] = TYPE_DESC[type] || 'Unknown'
            out[:message]   = m[2].to_s.gsub(/<[A-Z]{2,3}>/, '').strip
          end
          out[:summary] = "POCSAG#{out[:baud]} RIC=#{out[:capcode]} F#{out[:function]} #{out[:type]}: #{out[:message]}"
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

            #{self}.parse_line(line: 'POCSAG1200: Address: 123456 Function: 3 Alpha: HELLO')

            #{self}.authors
          "
        end
      end
    end
  end
end
