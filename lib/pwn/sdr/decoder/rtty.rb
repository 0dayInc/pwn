# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # RTTY (Radioteletype, ITA2/Baudot) decoder for the amateur RTTY
      # sub-bands (rtty20/rtty40/rtty80). GQRX supplies FM-demodulated audio
      # containing the classic 170 Hz-shift 45.45-baud mark/space tones;
      # `minimodem` recovers the 5-bit Baudot stream and prints ASCII.
      module RTTY
        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTTY.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]

          # minimodem reads s16le mono from stdin at the rate we hand it; keep
          # sox at 22 050 Hz (Base default) and tell minimodem the same.
          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'RTTY',
            required_bins: %w[sox minimodem],
            decode_cmd: 'minimodem --rx --quiet --rtty -R 22050 -f -',
            line_match: /\S/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTTY.parse_line(line: 'RYRYRY DE W1AW')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s.strip
          out  = { protocol: 'RTTY', text: line }
          if (m = line.match(/\bDE\s+([A-Z0-9]{1,3}\d[A-Z]{1,4})\b/))
            out[:callsign] = m[1]
          end
          out[:summary] = "RTTY #{line}"[0, 120]
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

            #{self}.parse_line(line: 'RYRYRY CQ CQ DE W1AW')

            #{self}.authors
          "
        end
      end
    end
  end
end
