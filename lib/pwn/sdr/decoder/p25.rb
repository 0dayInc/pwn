# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby APCO Project 25 Phase-1 C4FM activity detector.
      #
      # P25 is 4800 sym/s 4-level FSK with 1/2-rate trellis + RS + IMBE
      # vocoder. Full symbol recovery, deinterleave, FEC and voice decode
      # is out of scope for a portable pure-Ruby implementation; this
      # module instead characterises C4FM keying activity (talkgroup key-
      # ups, control-channel duty cycle) natively via Base.run_detector.
      # `parse_line` is retained for offline dsd-format log analysis.
      module P25
        # Supported Method Parameters::
        # PWN::SDR::Decoder::P25.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'P25',
            note: 'C4FM 4-FSK + trellis/RS/IMBE — native mode reports key-up bursts (duration/peak/duty) only. Feed captured dsd text to .parse_line for NAC/TG/RID.',
            threshold: 6.0,
            describe: proc { |b|
              kind = if b[:duration_ms] > 1500 then 'voice-superframe'
                     elsif b[:duration_ms] > 150 then 'LDU/HDU'
                     else 'TSBK/control'
                     end
              { modulation: 'C4FM', symbol_rate: 4800, classification: kind }
            }
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
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: 'Sync: +P25p1 NAC: 293 src: 1234 tg: 5678')

            #{self}.authors
          "
        end
      end
    end
  end
end
