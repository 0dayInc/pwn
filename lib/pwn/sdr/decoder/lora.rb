# frozen_string_literal: true

require 'json'
require 'shellwords'

module PWN
  module SDR
    module Decoder
      # LoRa / LoRaWAN CSS decoder for the 433 / 868 / 902–928 MHz ISM
      # allocations. Chirp-spread-spectrum needs raw I/Q, so this drives
      # `rtl_433` (which ships a native LoRa demod, protocol #264) directly.
      # Emits one JSON line per decoded uplink containing SF/BW/CR, DevAddr,
      # FCnt, and raw PHYPayload hex.
      module LoRa
        # Supported Method Parameters::
        # PWN::SDR::Decoder::LoRa.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz       = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          sdr_args = freq_obj[:sdr_args].to_s

          cmd = ['rtl_433', '-f', hz.to_s, '-s', '1024k',
                 '-R', '264', '-F', 'json', '-M', 'level']
          cmd.push('-d', sdr_args) unless sdr_args.empty?

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'LoRa',
            required_bins: %w[rtl_433],
            direct_cmd: Shellwords.join(cmd),
            line_match: /^\s*{/,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::LoRa.parse_line(line: '{"model":"LoRa",...}')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          h = begin
            JSON.parse(line, symbolize_names: true)
          rescue StandardError
            { unparsed: line }
          end
          out = { protocol: 'LoRa' }.merge(h)
          bits = []
          bits << "SF#{out[:sf]}" if out[:sf]
          bits << "BW#{out[:bw]}" if out[:bw]
          bits << "CR#{out[:cr]}" if out[:cr]
          bits << "DevAddr=#{out[:devaddr] || out[:id]}" if out[:devaddr] || out[:id]
          bits << "FCnt=#{out[:fcnt]}" if out[:fcnt]
          bits << "len=#{out[:len] || (out[:data].to_s.length / 2)}" if out[:len] || out[:data]
          out[:summary] = "LoRa #{bits.join(' ')}".strip
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

            NOTE: Requires `rtl_433` >= 23.x (native LoRa demod). Owns SDR.

            #{self}.parse_line(line: '{\"model\":\"LoRa\",\"sf\":7,\"bw\":125,...}')

            #{self}.authors
          "
        end
      end
    end
  end
end
