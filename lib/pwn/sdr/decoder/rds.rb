# frozen_string_literal: true

require 'json'
require 'tty-spinner'

module PWN
  module SDR
    module Decoder
      # RDS Decoder Module for FM Radio Signals
      module RDS
        # Supported Method Parameters::
        # rds_resp = PWN::SDR::GQRX.decode_rds(
        #   freq_obj: 'required - GQRX socket object returned from #connect method'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          gqrx_sock = freq_obj[:gqrx_sock]

          freq_obj = freq_obj.dup
          freq_obj.delete(:gqrx_sock)
          skip_rds = "\n"
          puts JSON.pretty_generate(freq_obj)
          puts "\n*** FM Radio RDS Decoder ***"
          puts 'Press [ENTER] to continue...'

          # Toggle RDS off and on to reset the decoder
          PWN::SDR::GQRX.gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RDS 0',
            resp_ok: 'RPRT 0'
          )

          PWN::SDR::GQRX.gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RDS 1',
            resp_ok: 'RPRT 0'
          )

          # Spinner setup with dynamic terminal width awareness
          spinner = TTY::Spinner.new(
            '[:spinner] :decoding',
            format: :arrow_pulse,
            clear: true,
            hide_cursor: true
          )

          # Conservative overhead for spinner animation, colors, and spacing
          spinner_overhead = 12
          max_title_length = [TTY::Screen.width - spinner_overhead, 50].max

          initial_title = 'INFO: Decoding FM radio RDS data...'
          initial_title = initial_title[0...max_title_length] if initial_title.length > max_title_length
          spinner.update(title: initial_title)
          spinner.auto_spin

          last_resp = {}

          loop do
            rds_resp = {
              rds_pi: PWN::SDR::GQRX.gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PI').to_s.strip.chomp.delete('.'),
              rds_ps_name: PWN::SDR::GQRX.gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PS_NAME').to_s.strip.chomp,
              rds_radiotext: PWN::SDR::GQRX.gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_RADIOTEXT').to_s.strip.chomp
            }

            # Only update when we have valid new data
            if rds_resp[:rds_pi] != '0000' && rds_resp != last_resp
              # --- Enforce RDS specification bounds and clean formatting ---
              # PI: 16-bit code >>> exactly 4 uppercase hex digits, zero-padded
              rds_pi = rds_resp[:rds_pi].upcase
              rds_pi = rds_pi.rjust(4, '0')[0, 4]

              # PS: exactly 8 ASCII characters (pad short with spaces, truncate long)
              rds_ps = "#{rds_resp[:rds_ps_name]}        "[0, 8]

              # RadioText: strip trailing spaces (stations often pad to clear)
              rds_rt = rds_resp[:rds_radiotext].rstrip

              # Fixed prefix: always exactly 28 characters for predictable layout
              # Breakdown: "PI: " (4) + 4 hex (4) + " | PS: " (7) + 8 chars (8) + " | RT: " (7) = 28
              prefix = "Program ID: #{rds_pi} | Station Name: #{rds_ps} | Radio Txt: "

              # minimum visibility
              available_for_rt = max_title_length - prefix.length
              available_for_rt = [available_for_rt, 10].max

              rt_display = rds_rt
              rt_display = "#{rt_display[0...available_for_rt]}..." if rt_display.length > available_for_rt

              msg = prefix + rt_display
              spinner.update(decoding: msg)
              last_resp = rds_resp.dup
            end

            # Non-blocking check for ENTER key to exit
            if $stdin.wait_readable(0)
              begin
                char = $stdin.read_nonblock(1)
                break if char == skip_rds
              rescue IO::WaitReadable, EOFError
                # No-op
              end
            end

            sleep 0.01
          end
        rescue StandardError => e
          spinner.error('Decoding failed') if defined?(spinner)
          raise e
        ensure
          spinner.stop if defined?(spinner) && spinner
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::Receiver::GQRX.init_freq method'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
