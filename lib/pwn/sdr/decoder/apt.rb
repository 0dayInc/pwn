# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # NOAA APT (Automatic Picture Transmission) decoder for the 137 MHz
      # polar-orbiting weather satellites (NOAA-15/18/19). APT is a 2400 Hz
      # AM subcarrier inside a 34 kHz-wide FM downlink; GQRX's UDP audio is
      # recorded to a WAV, then handed to `noaa-apt` (or `satdump`) to render
      # the two-channel visible/IR image strip.
      module APT
        # Supported Method Parameters::
        # PWN::SDR::Decoder::APT.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          stamp   = Time.now.strftime('%Y%m%d_%H%M%S')
          wav_out = "/tmp/apt_#{stamp}.wav"
          png_out = "/tmp/apt_#{stamp}.png"

          # Record 11 025 Hz WAV (noaa-apt's native rate) until [ENTER],
          # emitting a heartbeat line per second so the spinner stays live,
          # then decode to PNG on exit.
          inner = 'sox -t raw -e signed-integer -b 16 -r 22050 -c 1 - ' \
                  "-t wav -r 11025 #{Shellwords.escape(wav_out)} & SOXPID=$!; " \
                  'trap "kill $SOXPID 2>/dev/null" EXIT INT TERM; ' \
                  'while kill -0 $SOXPID 2>/dev/null; do ' \
                  "echo APT_REC seconds=$SECONDS file=#{wav_out}; sleep 1; done"

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'NOAA-APT',
            required_bins: %w[sox noaa-apt],
            decode_cmd: "bash -c #{Shellwords.escape(inner)}",
            line_match: /^APT_REC/,
            parser: proc { |line| { protocol: 'NOAA-APT', wav: wav_out, png: png_out, summary: line.strip } }
          )

          return unless File.exist?(wav_out) && File.size(wav_out).positive?

          system('noaa-apt', wav_out, '-o', png_out)

          puts "[*] APT image written: #{png_out}" if File.exist?(png_out)
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

            NOTE: Requires `sox` and `noaa-apt`. Set GQRX to FM, ~34 kHz BW.
                  Records the pass to /tmp/apt_<ts>.wav, decodes to PNG on exit.

            #{self}.authors
          "
        end
      end
    end
  end
end
