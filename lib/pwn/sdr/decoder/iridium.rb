# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby Iridium L-band burst detector.
      #
      # Iridium simplex/duplex bursts are 25 kbit/s DE-QPSK across
      # 1616–1626.5 MHz. Native mode reports burst count/duration/energy
      # per channel. `parse_line` retained for offline iridium-toolkit
      # text analysis.
      module Iridium
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Iridium.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'IRIDIUM',
            note: '25 kbit/s DE-QPSK — native mode reports burst timing/energy only.',
            threshold: 7.0,
            describe: proc { |b| { modulation: 'DE-QPSK', symbol_rate: 25_000, classification: b[:duration_ms] < 10 ? 'simplex-burst' : 'duplex-frame' } }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Iridium.parse_line(line: 'IRA: sat:23 beam:14 ...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'IRIDIUM' }
          out[:frame_type] = ::Regexp.last_match(1) if line =~ /^([A-Z]{3}):/
          out[:sat]        = ::Regexp.last_match(1) if line =~ /sat:(\d+)/
          out[:beam]       = ::Regexp.last_match(1) if line =~ /beam:(\d+)/
          out[:pos]        = ::Regexp.last_match(1) if line =~ /pos=\(([^)]+)\)/
          out[:ra_id]      = ::Regexp.last_match(1) if line =~ /ric:(\d+)/
          out[:summary]    = "IRIDIUM #{out[:frame_type]} sat=#{out[:sat]} beam=#{out[:beam]}"
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

            #{self}.parse_line(line: 'IRA: sat:23 beam:14 pos=(+32.1/-097.0) ...')

            #{self}.authors
          "
        end
      end
    end
  end
end
