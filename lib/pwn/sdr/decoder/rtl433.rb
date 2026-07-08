# frozen_string_literal: true

require 'json'
require 'shellwords'

module PWN
  module SDR
    module Decoder
      # Generic ISM/keyfob/sensor decoder backed by `rtl_433`.
      #
      # Covers the OOK/ASK/FSK device zoo on 300–315 / 390 / 433.92 / 868 /
      # 902–928 MHz: car/garage keyfobs, TPMS, weather stations, utility
      # meters, doorbells, alarm PIRs, etc. rtl_433 owns the SDR directly and
      # emits one JSON object per decoded frame (`-F json`), which this module
      # merges verbatim into the freq_obj log line.
      module RTL433
        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTL433.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz       = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          gain     = freq_obj[:rf_gain]
          sdr_args = freq_obj[:sdr_args].to_s

          cmd = ['rtl_433', '-f', hz.to_s, '-F', 'json', '-M', 'level', '-M', 'protocol']
          cmd.push('-g', gain.to_s) if gain
          cmd.push('-d', sdr_args) unless sdr_args.empty?
          direct_cmd = Shellwords.join(cmd)

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'RTL433',
            required_bins: %w[rtl_433],
            direct_cmd: direct_cmd,
            line_match: /^\s*{/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTL433.parse_line(line: '{"time":"...","model":"..."}')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          h = begin
            JSON.parse(line, symbolize_names: true)
          rescue StandardError
            { unparsed: line }
          end
          out = { protocol: 'RTL433' }.merge(h)

          bits = []
          bits << out[:model].to_s if out[:model]
          bits << "id=#{out[:id]}" if out[:id]
          bits << "ch=#{out[:channel]}" if out[:channel]
          bits << "code=#{out[:code]}" if out[:code]
          bits << "cmd=#{out[:cmd] || out[:button]}" if out[:cmd] || out[:button]
          bits << "temp=#{out[:temperature_C]}C" if out[:temperature_C]
          bits << "rssi=#{out[:rssi]}" if out[:rssi]
          out[:summary] = bits.empty? ? line[0, 120] : bits.join(' ')
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

            NOTE: Requires `rtl_433`. Owns the SDR directly (pass
                  freq_obj[:sdr_args] like ':1' or 'driver=hackrf' to select
                  a device other than the one GQRX is holding).

            #{self}.parse_line(line: '{\"model\":\"Acurite-Tower\",\"id\":1234,...}')

            #{self}.authors
          "
        end
      end
    end
  end
end
