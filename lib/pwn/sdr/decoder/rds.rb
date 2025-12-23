# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # RDS Decoder Module for FM Radio Signals
      module RDS
        # Supported Method Parameters::
        # rds_resp = PWN::SDR::GQRX.decode_rds(
        #   gqrx_sock: 'required - GQRX socket object returned from #connect method'
        # )

        # private_class_method def self.rds(opts = {})
        public_class_method def self.rds(opts = {})
          gqrx_sock = opts[:gqrx_sock]

          # We toggle RDS off and on to reset the decoder
          rds_resp = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RDS 0',
            resp_ok: 'RPRT 0'
          )

          rds_resp = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RDS 1',
            resp_ok: 'RPRT 0'
          )

          rds_resp = {}
          attempts = 0
          max_attempts = 120
          skip_rds = "\n"
          print 'INFO: Decoding FM radio RDS data (Press ENTER to skip)...'
          max_attempts.times do
            attempts += 1
            rds_resp[:rds_pi] = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PI')
            rds_resp[:rds_ps_name] = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PS_NAME')
            rds_resp[:rds_radiotext] = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_RADIOTEXT')

            # Break if ENTER key pressed
            # This is useful if no RDS data is available
            # on the current frequency (e.g. false+)
            break if $stdin.ready? && $stdin.read_nonblock(1) == skip_rds

            break if rds_resp[:rds_pi] != '0000' && !rds_resp[:rds_ps_name].empty? && !rds_resp[:rds_radiotext].empty?

            print '.'
            sleep 0.1
          end
          puts 'complete.'
          rds_resp
        rescue StandardError => e
          raise e
        end

        # Starts the live decoding thread.
        def self.start(opts = {})
          freq_obj = opts[:freq_obj]
          raise ':ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          gqrx_sock = freq_obj[:gqrx_sock]
          freq = freq_obj[:freq]
          bandwidth = freq_obj[:bandwidth].to_i
          record_path = freq_obj[:record_path]

          sleep 0.1 until File.exist?(record_path)

          header = File.binread(record_path, HEADER_SIZE)
          raise 'Invalid WAV header' unless header.start_with?('RIFF') && header.include?('WAVE')

          bytes_read = HEADER_SIZE

          puts "GSM Decoder started for freq: #{freq}, bandwidth: #{bandwidth}"

          Thread.new do
            loop do
              sleep 1
            end
          rescue StandardError => e
            puts "Decoder error: #{e.message}"
          ensure
            cleanup(record_path: record_path)
          end
        end

        # Stops the decoding thread.
        def self.stop(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          decoder_thread = freq_obj[:decoder_thread]
          decoder_thread.kill if decoder_thread.is_a?(Thread)
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
            gsm_decoder_thread = #{self}.start(
              freq_obj: 'required - freq_obj returned from PWN::SDR::Receiver::GQRX.init_freq method'
            )

            # To stop the decoder thread:
            #{self}.stop(
              freq_obj: 'required - freq_obj returned from PWN::SDR::Receiver::GQRX.init_freq method'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
