# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # Iridium L-band (1.616–1.6265 GHz) burst decoder. Drives gr-iridium's
      # `iridium-extractor` against the SDR to demodulate 25 kbit/s DE-QPSK
      # simplex/duplex bursts, then pipes them through iridium-toolkit's
      # `iridium-parser.py` for frame classification (IRA/IBC/IDA/ISY/VOC/...).
      module Iridium
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Iridium.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz       = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          gain     = (freq_obj[:rf_gain] || 40).to_s.to_f
          sdr_args = (freq_obj[:sdr_args] || 'rtl=0').to_s

          inner = "iridium-extractor -D 4 --multi-frame -c #{hz} -r 2000000 " \
                  "-g #{gain} -o - #{Shellwords.escape(sdr_args)} 2>/dev/null " \
                  '| iridium-parser.py --harder /dev/stdin'
          direct_cmd = "bash -c #{Shellwords.escape(inner)}"

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'IRIDIUM',
            required_bins: %w[iridium-extractor iridium-parser.py],
            direct_cmd: direct_cmd,
            line_match: /^(IRA|IBC|IDA|ISY|ITL|MSG|VOC|RAW):/,
            parser: proc { |line| parse_line(line: line) }
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
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: Requires `iridium-extractor` (gr-iridium) and
                  `iridium-parser.py` (iridium-toolkit). Owns the SDR.

            #{self}.parse_line(line: 'IRA: sat:23 beam:14 pos=(+32.1/-097.0) ...')

            #{self}.authors
          "
        end
      end
    end
  end
end
