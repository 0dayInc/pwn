# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # CW / Morse decoder for the amateur CW sub-bands (cw20/cw40/cw80,
      # amateur_30m). GQRX's CW demodulator produces a ~700 Hz sidetone in the
      # 48 kHz UDP audio stream; multimon-ng's MORSE_CW demod recovers the
      # dit/dah timing and prints decoded characters one line at a time.
      module Morse
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Morse.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'MORSE-CW',
            required_bins: %w[sox multimon-ng],
            decode_cmd: 'multimon-ng -q -t raw -a MORSE_CW -',
            line_match: /\S/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Morse.parse_line(line: 'CQ CQ DE W1AW')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s.gsub(/^MORSE(?:_CW)?:\s*/i, '').strip
          out  = { protocol: 'MORSE-CW', text: line }
          if (m = line.match(/\b([A-Z0-9]{1,3}\d[A-Z]{1,4})\b/))
            out[:callsign] = m[1]
          end
          out[:summary] = "CW #{line}"[0, 120]
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

            #{self}.parse_line(line: 'CQ CQ DE W1AW W1AW K')

            #{self}.authors
          "
        end
      end
    end
  end
end
