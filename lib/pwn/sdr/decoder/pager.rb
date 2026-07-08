# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Combined pager decoder for the mixed-protocol `pager_all` band plan.
      #
      # Runs multimon-ng with FLEX + FLEX_NEXT + POCSAG512/1200/2400 enabled
      # simultaneously and dispatches each output line to the appropriate
      # per-protocol parser (::Flex-style or ::POCSAG.parse_line).
      module Pager
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Pager.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]

          decode_cmd = 'multimon-ng -q -t raw -e -u -p ' \
                       '-a FLEX -a FLEX_NEXT ' \
                       '-a POCSAG512 -a POCSAG1200 -a POCSAG2400 -'

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'PAGER',
            required_bins: %w[sox multimon-ng],
            decode_cmd: decode_cmd,
            line_match: /^(FLEX|POCSAG)/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Pager.parse_line(line: 'FLEX|... or POCSAG1200: ...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          return PWN::SDR::Decoder::POCSAG.parse_line(line: line) if line.start_with?('POCSAG')

          # FLEX / FLEX_NEXT — pipe- or space-delimited (see ::Flex for format).
          delim  = line.start_with?('FLEX: ') ? ' ' : '|'
          parts  = line.split(delim)
          proto  = line.start_with?('FLEX_NEXT') ? 'FLEX_NEXT' : 'FLEX'
          types  = %w[ALN BIN HEX NUM TON TONE UNK]
          t_idx  = parts.index { |p| types.include?(p) }
          out    = { protocol: proto, raw_inspected: line.inspect }
          out[:capcode]      = parts.find { |p| p.match?(/^\[?\d{7,10}\]?$/) }
          out[:type]         = t_idx ? parts[t_idx] : nil
          out[:type_payload] = t_idx ? parts[(t_idx + 1)..].join(delim) : nil
          out[:summary]      = "#{proto} RIC=#{out[:capcode]} #{out[:type]}: #{out[:type_payload]}"
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

            #{self}.parse_line(line: 'FLEX|3200|...|ALN|MESSAGE')

            #{self}.authors
          "
        end
      end
    end
  end
end
