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
          puts '(Press [ENTER] to continue)...'

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

          # Use TTY::Spinner correctly with a dynamic :title token
          spinner = TTY::Spinner.new('[:spinner] :title', format: :arrow_pulse)
          spinner.update(title: 'INFO: Decoding FM radio RDS data...')
          spinner.auto_spin # Background thread handles smooth animation

          last_resp = {}

          loop do
            rds_resp = {
              rds_pi: PWN::SDR::GQRX.gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PI').to_s.strip.chomp,
              rds_ps_name: PWN::SDR::GQRX.gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PS_NAME').to_s.strip.chomp,
              rds_radiotext: PWN::SDR::GQRX.gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_RADIOTEXT').to_s.strip.chomp
            }

            # Only update the displayed message when we have new, complete, valid RDS data
            if rds_resp[:rds_pi] != '0000' && rds_resp != last_resp
              status = "Program ID: #{rds_resp[:rds_pi]} | Station Name: #{rds_resp[:rds_ps_name].ljust(8)} | Radio Text: #{rds_resp[:rds_radiotext]}"
              spinner.update(title: status)
              last_resp = rds_resp.dup
            end

            # Non-blocking check for ENTER key
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
          spinner.stop if spinner
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
