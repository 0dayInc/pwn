# frozen_string_literal: true

require 'json'

module PWN
  module SDR
    module Decoder
      # Pure-Ruby LoRa / LoRaWAN CSS activity detector.
      #
      # LoRa is chirp-spread-spectrum over 125/250/500 kHz — recoverable
      # only from raw I/Q at ≥250 ksps, not from a 48 kHz audio tap.
      # Native mode reports chirp-burst duration/energy (from which SF
      # can be estimated). `parse_line` retained for offline JSON analysis.
      module LoRa
        # Supported Method Parameters::
        # PWN::SDR::Decoder::LoRa.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'LoRa',
            note: 'CSS over 125–500 kHz — native mode reports chirp bursts and estimates SF from duration.',
            threshold: 8.0,
            describe: proc { |b|
              # Preamble ≈ 8 symbols; T_sym = 2^SF / BW. Assume BW=125k.
              t_sym_ms = b[:duration_ms] / 20.0
              sf_est = t_sym_ms.positive? ? Math.log2(t_sym_ms * 125).round.clamp(6, 12) : nil
              { modulation: 'CSS', bw_khz_assumed: 125, sf_estimate: sf_est }.compact
            }
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
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: '{\"model\":\"LoRa\",\"sf\":7,\"bw\":125,...}')

            #{self}.authors
          "
        end
      end
    end
  end
end
