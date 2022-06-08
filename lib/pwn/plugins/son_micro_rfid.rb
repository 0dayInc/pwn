# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin is used for interacting with a SonMicro
    # SM132 USB RFID Reader / Writer (PCB v3)
    module SonMicroRFID
      # Supported Method Parameters::
      # son_micro_rfid_obj = PWN::Plugins::SonMicroRFID.connect(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)',
      #   baud: 'optional - (defaults to 19_200)',
      #   data_bits: 'optional - (defaults to 8)',
      #   stop_bits: 'optional - (defaults to 1)',
      #   parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none)',
      #   flow_control: 'optional - :none||:hard||:soft (defaults to :none)'
      # )

      public_class_method def self.connect(opts = {})
        # Default Baud Rate for this Device is 19200
        opts[:block_dev] = '/dev/ttyUSB0' unless opts[:block_dev]
        opts[:baud] = 19_200 unless opts[:baud]
        opts[:data_bits] = 8 unless opts[:data_bits]
        opts[:stop_bits] = 1 unless opts[:stop_bits]
        opts[:parity] = :none unless opts[:parity]
        opts[:flow_control] = :none unless opts[:flow_control]
        son_micro_rfid_obj = PWN::Plugins::Serial.connect(opts)
      rescue StandardError => e
        disconnect(son_micro_rfid_obj: son_micro_rfid_obj) unless son_micro_rfid_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      #  cmds = PWN::Plugins::SonMicroRFID.list_cmds
      public_class_method def self.list_cmds
        # Returns an Array of Symbols
        cmds = %i[
          reset
          firmware
          seek_for_tag
          select_tag
          authenticate
          read_block
          write_block
          write_value
          write_four_byte_block
          write_key
          increment
          decrement
          antenna_power
          read_port
          write_port
          halt
          set_baud_rate
          sleep
          poll_buffer
        ]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      #  params = PWN::Plugins::SonMicroRFID.list_params(
      #   cmd: 'required - cmd returned from #list_cmds method',
      # )
      public_class_method def self.list_params(opts = {})
        cmd = opts[:cmd].to_s.scrub.strip.chomp

        case cmd.to_sym
        when :reset
          params = %i[reset_not_implemented]
        when :firmware
          params = %i[firmware_not_implemented]
        when :seek_for_tag
          params = %i[seek_for_tag_no_params_required]
        when :select_tag
          params = %i[select_tag_no_params_required]
        when :authenticate
          params = %i[authenticate_not_implemented]
        when :read_block
          params = %i[read_block_not_implemented]
        when :write_block
          params = %i[write_block_not_implemented]
        when :write_value
          params = %i[write_value_not_implemented]
        when :write_four_byte_block
          params = %i[write_four_byte_block_not_implemented]
        when :write_key
          params = %i[write_key_not_implemented]
        when :increment
          params = %i[increment_not_implemented]
        when :decrement
          params = %i[decrement_not_implemented]
        when :antenna_power
          params = %i[off on reset]
        when :read_port
          params = %i[antenna_power_not_implemented]
        when :write_port
          params = %i[write_port_not_implemented]
        when :halt
          params = %i[halt_not_implemented]
        when :set_baud_rate
          params = %i[set_baud_rate_not_implemented]
        when :sleep
          params = %i[sleep_not_implemented]
        when :poll_buffer
          params = %i[poll_buffer_not_implemented]
        else
          raise "Unsupported Command: #{cmd}.  Supported commands are:\n#{list_cmds}\n\n\n"
        end

        params
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = parse_responses(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      #   cmd_resp: 'required - command response string'
      # )

      private_class_method def self.parse_responses(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        cmd = opts[:cmd].to_s.scrub.strip.chomp

        keep_parsing_responses = true
        next_response_detected = false
        all_cmd_responses = []
        a_cmd_r_len = 0
        last_a_cmd_r_len = 0

        parsed_cmd_resp_arr = []
        bytes_in_cmd_resp = 0
        cmd_resp = ''

        # Parse All Responses and add them to parsed_cmd_resp_arr
        while keep_parsing_responses
          until next_response_detected
            all_cmd_responses = PWN::Plugins::Serial.response(
              serial_obj: son_micro_rfid_obj
            )
            cmd_resp = all_cmd_responses.last
            bytes_in_cmd_resp = cmd_resp.split.length if cmd_resp
            a_cmd_r_len = all_cmd_responses.length

            # Dont proceed until the expected_cmd_resp_byte_len byte appears
            next_response_detected = true if bytes_in_cmd_resp > 3 &&
                                             a_cmd_r_len > last_a_cmd_r_len
          end
          next_response_detected = false
          last_a_cmd_r_len = a_cmd_r_len
          print "\n"

          # Third byte
          expected_cmd_resp_byte_len = cmd_resp.split[2].to_i(16) + 4

          # Fourth byte
          cmd_hex = cmd_resp.split[3]

          while bytes_in_cmd_resp < expected_cmd_resp_byte_len
            all_cmd_responses = PWN::Plugins::Serial.response(
              serial_obj: son_micro_rfid_obj
            )

            cmd_resp = all_cmd_responses.last
            bytes_in_cmd_resp = cmd_resp.split.length
            puts "EXPECTED CMD BYTE LEN: #{expected_cmd_resp_byte_len}"
            puts "LAST CMD BYTE LEN: #{bytes_in_cmd_resp} >>>"
            puts all_cmd_responses
            puts "COMMAND HEX: #{cmd_hex}\n\n\n"
          end

          puts "\nALL CMD RESPS >>>"
          puts "#{all_cmd_responses}\n\n\n"

          parsed_cmd_resp_hash = {}
          parsed_cmd_resp_hash[:raw_resp] = PWN::Plugins::Serial.dump_session_data.inspect
          parsed_cmd_resp_hash[:hex_resp] = cmd_resp
          parsed_cmd_resp_hash[:cmd_hex] = cmd_hex
          parsed_cmd_resp_hash[:cmd_desc] = cmd.to_sym
          resp_code = '?'

          # TODO: Detect EMV
          case cmd_hex
          when '82', '83'
            resp_code = cmd_resp.split[4]
            parsed_cmd_resp_hash[:resp_code_hex] = resp_code
            case resp_code
            when '01'
              parsed_cmd_resp_hash[:resp_code_desc] = :mifare_ultralight
              parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(
                ' '
              )
            when '02'
              parsed_cmd_resp_hash[:resp_code_desc] = :mifare_classic_1k
              parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(
                ' '
              )
            when '03'
              parsed_cmd_resp_hash[:resp_code_desc] = :mifare_classic_4k
              parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(
                ' '
              )
            when '4C'
              parsed_cmd_resp_hash[:resp_code_desc] = :seeking_tag
              parsed_cmd_resp_hash[:tag_id] = :seeking_tag
            when '4E'
              parsed_cmd_resp_hash[:resp_code_desc] = :no_tag_present
              parsed_cmd_resp_hash[:tag_id] = :not_available
            when '55'
              parsed_cmd_resp_hash[:resp_code_desc] = :antenna_off
              parsed_cmd_resp_hash[:tag_id] = :not_available
            when 'FF'
              parsed_cmd_resp_hash[:resp_code_desc] = :unknown_tag_type
              parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(
                ' '
              )
            else
              parsed_cmd_resp_hash[:resp_code_desc] = :unknown_resp_code
              parsed_cmd_resp_hash[:tag_id] = :not_available
            end
          else
            parsed_cmd_resp_hash[:cmd_desc] = :not_available
          end

          keep_parsing_responses = false unless resp_code == '4C'

          parsed_cmd_resp_arr.push(parsed_cmd_resp_hash)
        end

        parsed_cmd_resp_arr
      rescue StandardError => e
        raise e
      ensure
        # Flush Responses for Next Request
        PWN::Plugins::Serial.flush_session_data
      end

      # Supported Method Parameters::
      #  PWN::Plugins::SonMicroRFID.exec(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      #   cmd: 'required - cmd returned from #list_cmds method',
      #   params: 'optional - parameters for specific command returned from #list_params method'
      # )
      public_class_method def self.exec(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        cmd = opts[:cmd].to_s.scrub.strip.chomp
        params = opts[:params].to_s.scrub.strip.chomp

        params_bytes = []

        # Use the Mifare Panel Application to reverse enginner commands.
        case cmd.to_sym
        when :reset
          cmd_bytes = [0xFF, 0x00, 0x01, 0x80, 0x81]
        when :firmware
          cmd_bytes = [0xFF, 0x00, 0x01, 0x81, 0x82]
        when :seek_for_tag
          cmd_bytes = [0xFF, 0x00, 0x01, 0x82, 0x83]
        when :select_tag
          cmd_bytes = [0xFF, 0x00, 0x01, 0x83, 0x84]
        when :authenticate
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x00]
        when :read_block
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x01]
        when :write_block
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x02]
        when :write_value
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x03]
        when :write_four_byte_block
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x04]
        when :write_key
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x05]
        when :increment
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x06]
        when :decrement
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x07]
        when :antenna_power
          cmd_bytes = [0xFF, 0x00, 0x02, 0x90]
          case params.to_sym
          when :off
            params_bytes = [0x00, 0x92]
          when :on
            params_bytes = [0x01, 0x93]
          when :reset
            params_bytes = [0x02, 0x94]
          else
            raise "Unsupported Parameters: #{params} for #{cmd}.  Supported parameters for #{cmd} are:\n#{list_params(cmd: cmd)}\n\n\n"
          end
        when :read_port
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01]
        when :write_port
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x08]
        when :halt
          cmd_bytes = [0xFF, 0x00, 0x01, 0x93, 0x94]
        when :set_baud_rate
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x09]
        when :sleep
          # Last two bytes not correct
          cmd_bytes = [0xFF, 0x00, 0x01, 0x0a]
        when :poll_buffer
          cmd_bytes = [0xFF, 0x00, 0x01, 0xB0, 0xB1]
        else
          raise "Unsupported Command: #{cmd}.  Supported commands are:\n#{list_cmds}\n\n\n"
        end

        # If parameters to a command are set, append them.
        cmd_bytes += params_bytes unless params_bytes.empty?
        # Execute the command.
        PWN::Plugins::Serial.request(
          serial_obj: son_micro_rfid_obj,
          payload: cmd_bytes
        )

        # Parse commands response(s).
        # Return an array of hashes.
        parse_responses(
          son_micro_rfid_obj: son_micro_rfid_obj,
          cmd: cmd.to_sym
        )
      rescue StandardError => e
        raise e
      ensure
        # Flush Responses for Next Request
        PWN::Plugins::Serial.flush_session_data
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.read_card(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.read_card(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        rfid_data = exec(
          son_micro_rfid_obj: son_micro_rfid_obj,
          cmd: :seek_for_tag
        )
        puts rfid_data.inspect

        rfid_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.write_card(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.write_card(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        rfid_data = opts[:rfid_data]
        # TODO: write card
        puts rfid_data.inspect

        rfid_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.backup_card(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.backup_card(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        rfid_data = read_card(son_micro_rfid_obj: son_micro_rfid_obj)
        file = ''
        backup_msg = ''
        loop do
          print 'Enter File Name to Save Backup: '
          file = gets.scrub.chomp.strip
          file_dir = File.dirname(file)
          break if Dir.exist?(file_dir)

          backup_msg = "\n****** ERROR: Directory #{file_dir} for #{file} does not exist ******"
          puts backup_msg
        end
        File.write(file, "#{JSON.pretty_generate(rfid_data)}\n")

        rfid_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.copy_card(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.copy_card(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        rfid_data = read_card(son_micro_rfid_obj: son_micro_rfid_obj)
        write_card(
          son_micro_rfid_obj: son_micro_rfid_obj,
          rfid_data: rfid_data
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.load_card_from_file(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.load_card_from_file(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        file = ''
        restore_msg = ''
        loop do
          print 'Enter File Name to Restore to Card: '
          file = gets.scrub.chomp.strip
          break if File.exist?(file)

          restore_msg = "\n****** ERROR: #{file} does not exist ******"
          puts restore_msg
        end

        rfid_data = JSON.parse(
          File.read(file),
          symbolize_names: true
        )

        # TODO: Save Original Card Contents
        write_card(
          son_micro_rfid_obj: son_micro_rfid_obj,
          rfid_data: rfid_data
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.disconnect(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        PWN::Plugins::Serial.disconnect(
          serial_obj: opts[:son_micro_rfid_obj]
        )
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          son_micro_rfid_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 19_200)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :odd),'
            flow_control: 'optional - :none||:hard||:soft (defaults to :none)'
          )

          cmds = #{self}.list_cmds

          params = #{self}.list_params(
            cmd: 'required - cmd returned from #list_cmds method',
          )

          parsed_cmd_resp_arr = #{self}.exec(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method',
            cmd: 'required - cmd returned from #list_cmds method',
            params: 'optional - parameters for specific command returned from #list_params method'
          )

          #{self}.disconnect(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
