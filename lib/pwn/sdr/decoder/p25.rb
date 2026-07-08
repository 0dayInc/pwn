# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # APCO Project 25 (P25) Phase-1 C4FM decoder for the 700/800 MHz
      # public-safety allocations. GQRX supplies NBFM-discriminator audio via
      # the UDP tap; `dsd` (Digital Speech Decoder) recovers the C4FM symbol
      # stream and prints trunking-control frames (NAC, TGID, RID, DUID, ...).
      module P25
        # Supported Method Parameters::
        # PWN::SDR::Decoder::P25.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]

          # dsd expects 48 kHz s16le on stdin — bypass Base's 22 050 Hz resample
          # by asking for 48 000 (sox becomes a passthrough / format guard).
          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'P25',
            required_bins: %w[sox dsd],
            resample_hz: 48_000,
            decode_cmd: 'dsd -q -i - -o /dev/null -f1',
            line_match: /(NAC|TGID|TG:|RID|src:|P25|Sync:)/i,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::P25.parse_line(line: 'Sync: +P25p1 NAC: 293 src: 1234 tg: 5678')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'P25' }
          out[:nac]       = ::Regexp.last_match(1) if line =~ /NAC:\s*([0-9A-Fa-f]+)/
          out[:talkgroup] = ::Regexp.last_match(1) if line =~ /(?:TGID|tg[: ])\s*(\d+)/i
          out[:radio_id]  = ::Regexp.last_match(1) if line =~ /(?:RID|src[: ])\s*(\d+)/i
          out[:duid]      = ::Regexp.last_match(1) if line =~ /DUID:\s*(\S+)/
          out[:sync]      = ::Regexp.last_match(1) if line =~ /Sync:\s*(\S+)/
          out[:summary]   = "P25 NAC=#{out[:nac]} TG=#{out[:talkgroup]} RID=#{out[:radio_id]}".squeeze(' ')
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

            NOTE: Requires `dsd`. Set GQRX demod to Narrow FM, ~12.5 kHz.

            #{self}.parse_line(line: 'Sync: +P25p1 NAC: 293 src: 1234 tg: 5678')

            #{self}.authors
          "
        end
      end
    end
  end
end
