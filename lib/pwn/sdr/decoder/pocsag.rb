# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # POCSAG (CCIR Radiopaging Code No. 1) decoder for pager networks.
      #
      # Pipeline (identical shape to PWN::SDR::Decoder::Flex):
      #   GQRX 48 kHz s16le UDP audio → sox → 22 050 Hz → multimon-ng.
      #
      # multimon-ng emits lines of the form:
      #   POCSAG1200: Address:  123456  Function: 3  Alpha:   FIRE ALARM ZONE 4
      #   POCSAG512:  Address:  000042  Function: 0  Numeric: 5551234
      #   POCSAG2400: Address:  987654  Function: 1  Skyper:  ...
      #   POCSAG1200: Address:  123456  Function: 2  Alpha:   <partial><EOT>
      #
      # Each line is parsed into { protocol, baud, address/capcode, function,
      # function_desc, type, type_desc, message } and JSON-logged.
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

          # -e  hide empty messages
          # -u  heuristically prune unlikely decodes (cuts BCH false-positives)
          # -p  emit partially received messages (still useful intel)
          # -f alpha  force Alpha framing when function bits are ambiguous —
          #           mirrors the behaviour operators expect from Flex ALN.
          decode_cmd = 'multimon-ng -q -t raw -e -u -p -f alpha ' \
                       '-a POCSAG512 -a POCSAG1200 -a POCSAG2400 -'

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'POCSAG',
            required_bins: %w[sox multimon-ng],
            decode_cmd: decode_cmd,
            line_match: /^POCSAG(?:512|1200|2400):/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::POCSAG.parse_line(line: 'POCSAG1200: Address: ...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'POCSAG', raw_inspected: line.inspect }

          if (m = line.match(/^POCSAG(\d+):/))
            out[:baud] = m[1].to_i
          end
          if (m = line.match(/Address:\s*(\d+)/i))
            out[:address] = m[1].to_i
            out[:capcode] = m[1].rjust(7, '0')
          end
          if (m = line.match(/Function:\s*(\d+)/i))
            fn = m[1].to_i
            out[:function]      = fn
            out[:function_desc] = FUNCTION_DESC[fn] || 'Unknown'
          end
          if (m = line.match(/\b(Alpha|Numeric|Skyper|Tone):\s*(.*)$/i))
            type = m[1].capitalize
            out[:type]         = type
            out[:type_desc]    = TYPE_DESC[type] || 'Unknown'
            out[:type_payload] = m[2].to_s.gsub(/<[A-Z]{2,4}>/, '').strip
            out[:message]      = out[:type_payload]
          end

          bits = []
          bits << "POCSAG#{out[:baud]}" if out[:baud]
          bits << "RIC=#{out[:capcode]}" if out[:capcode]
          bits << "F#{out[:function]}(#{out[:function_desc]})" if out[:function]
          bits << "#{out[:type]}: #{out[:message]}" if out[:type]
          out[:summary] = bits.join(' ')
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
