# frozen_string_literal: true

require 'logger'
require 'timeout'

module PWN
  module Plugins
    # This plugin is used for interacting with a SonMicro
    # SM132 USB RFID Reader / Writer (PCB V3) && SM2330-USB Rev.0
    module SonMicroRFID
      # Logger instance for auditing and debugging
      private_class_method def self.logger
        @logger ||= Logger.new('/tmp/pwn-sonmicro_rfid.log')
      end

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
        opts[:block_dev] ||= '/dev/ttyUSB0'
        opts[:baud] ||= 19_200
        opts[:data_bits] ||= 8
        opts[:stop_bits] ||= 1
        opts[:parity] ||= :none
        opts[:flow_control] ||= :none

        logger.info("Connecting to #{opts[:block_dev]} at baud #{opts[:baud]}")
        PWN::Plugins::Serial.connect(opts)
      rescue StandardError => e
        logger.error("Connection failed: #{e.message}")
        disconnect(son_micro_rfid_obj: son_micro_rfid_obj) unless son_micro_rfid_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # cmds = PWN::Plugins::SonMicroRFID.list_cmds
      public_class_method def self.list_cmds
        %i[
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
        logger.error("Error listing commands: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # params = PWN::Plugins::SonMicroRFID.list_params(
      #   cmd: 'required - cmd returned from #list_cmds method'
      # )

      public_class_method def self.list_params(opts = {})
        cmd = opts[:cmd].to_s.scrub.strip.chomp

        case cmd.to_sym
        when :reset
          params = %i[reset_not_implemented]
        when :firmware
          params = %i[firmware_no_params_required]
        when :seek_for_tag
          params = %i[seek_for_tag_no_params_required]
        when :select_tag
          params = %i[select_tag_no_params_required]
        when :authenticate
          params = %i[block key_type key]
        when :read_block
          params = %i[block]
        when :write_block
          params = %i[block data]
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
          params = %i[read_port_not_implemented]
        when :write_port
          params = %i[write_port_not_implemented]
        when :halt
          params = %i[halt_no_params_required]
        when :set_baud_rate
          params = %i[set_baud_rate_not_implemented]
        when :sleep
          params = %i[sleep_not_implemented]
        when :poll_buffer
          params = %i[poll_buffer_not_implemented]
        else
          logger.error("Unsupported command: #{cmd}")
          raise "Unsupported Command: #{cmd}. Supported commands are:\n#{list_cmds.join("\n")}\n"
        end

        params
      rescue StandardError => e
        logger.error("Error listing parameters for #{cmd}: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = parse_responses(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method',
      #   cmd: 'required - command symbol'
      # )

      private_class_method def self.parse_responses(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        cmd = opts[:cmd].to_s.scrub.strip.chomp

        Timeout.timeout(5) do
          keep_parsing_responses = true
          next_response_detected = false
          all_cmd_responses = []
          a_cmd_r_len = 0
          last_a_cmd_r_len = 0

          parsed_cmd_resp_arr = []
          bytes_in_cmd_resp = 0
          cmd_resp = ''

          while keep_parsing_responses
            until next_response_detected
              all_cmd_responses = PWN::Plugins::Serial.response(serial_obj: son_micro_rfid_obj)
              cmd_resp = all_cmd_responses.last
              bytes_in_cmd_resp = cmd_resp.split.length if cmd_resp
              a_cmd_r_len = all_cmd_responses.length
              next_response_detected = true if bytes_in_cmd_resp > 3 && a_cmd_r_len > last_a_cmd_r_len
            end
            next_response_detected = false
            last_a_cmd_r_len = a_cmd_r_len

            expected_cmd_resp_byte_len = cmd_resp.split[2].to_i(16) + 4
            cmd_hex = cmd_resp.split[3]

            while bytes_in_cmd_resp < expected_cmd_resp_byte_len
              all_cmd_responses = PWN::Plugins::Serial.response(serial_obj: son_micro_rfid_obj)
              cmd_resp = all_cmd_responses.last
              bytes_in_cmd_resp = cmd_resp.split.length
            end

            parsed_cmd_resp_hash = {}
            parsed_cmd_resp_hash[:cmd_hex] = cmd_hex
            parsed_cmd_resp_hash[:cmd_desc] = cmd.to_sym
            parsed_cmd_resp_hash[:hex_resp] = cmd_resp
            resp_code = cmd_resp.split[4] || '?'
            parsed_cmd_resp_hash[:resp_code_hex] = resp_code

            case cmd_hex
            when '82', '83'
              case resp_code
              when '01'
                parsed_cmd_resp_hash[:resp_code_desc] = :mifare_ultralight
                parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(' ')
              when '02'
                parsed_cmd_resp_hash[:resp_code_desc] = :mifare_classic_1k
                parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(' ')
              when '03'
                parsed_cmd_resp_hash[:resp_code_desc] = :mifare_classic_4k
                parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(' ')
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
                parsed_cmd_resp_hash[:tag_id] = cmd_resp.split[5..-2].join(' ')
              else
                parsed_cmd_resp_hash[:resp_code_desc] = :unknown_resp_code
                parsed_cmd_resp_hash[:tag_id] = :not_available
              end
            when '85' # Assumed for authenticate
              parsed_cmd_resp_hash[:resp_code_desc] = resp_code == '00' ? :auth_success : :auth_failed
            when '86' # Assumed for read_block
              parsed_cmd_resp_hash[:resp_code_desc] = resp_code == '00' ? :read_success : :read_failed
              parsed_cmd_resp_hash[:block_data] = cmd_resp.split[5..-2].join(' ')
            when '87' # Assumed for write_block
              parsed_cmd_resp_hash[:resp_code_desc] = resp_code == '00' ? :write_success : :write_failed
            else
              parsed_cmd_resp_hash[:resp_code_desc] = :unknown_response
            end

            keep_parsing_responses = false unless resp_code == '4C'
            parsed_cmd_resp_arr.push(parsed_cmd_resp_hash)
          end

          parsed_cmd_resp_arr
        end
      rescue Timeout::Error
        logger.error("Device response timed out for command: #{cmd}")
        raise 'ERROR: Device response timed out'
      rescue StandardError => e
        logger.error("Error parsing response for command #{cmd}: #{e.message}")
        raise e
      ensure
        PWN::Plugins::Serial.flush_session_data
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.exec(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method',
      #   cmd: 'required - cmd returned from #list_cmds method',
      #   params: 'optional - parameters for specific command returned from #list_params method'
      # )

      public_class_method def self.exec(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        cmd = opts[:cmd].to_s.scrub.strip.chomp
        params = opts[:params]

        logger.info("Executing command: #{cmd} with params: #{params.inspect}")

        params_bytes = []
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
          raise "Parameters must be a hash with :block, :key_type, :key for #{cmd}" unless params.is_a?(Hash)

          # Placeholder: [block, key_type, key]
          cmd_bytes = [0xFF, 0x00, 0x07, 0x85]
          block = params[:block].to_i
          key_type = params[:key_type] == :key_a ? 0x60 : 0x61
          key = params[:key] || [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
          params_bytes = [block, key_type] + key
        when :read_block
          # Placeholder: [block]
          cmd_bytes = [0xFF, 0x00, 0x02, 0x86]
          params_bytes = [params[:block].to_i] if params.is_a?(Hash) && params[:block]
        when :write_block
          raise "Parameters must be a hash with :block, :data for #{cmd}" unless params.is_a?(Hash) && params[:block] && params[:data]

          # Placeholder: [block, data]
          cmd_bytes = [0xFF, 0x00, 0x06, 0x87] # Adjust length based on data
          block = params[:block].to_i
          data = params[:data].is_a?(Array) ? params[:data] : params[:data].split.map { |b| b.to_i(16) }
          params_bytes = [block] + data
          cmd_bytes[2] = params_bytes.length + 2 # Update length
        when :write_value
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x03]
        when :write_four_byte_block
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x04]
        when :write_key
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x05]
        when :increment
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x06]
        when :decrement
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x07]
        when :antenna_power
          cmd_bytes = [0xFF, 0x00, 0x02, 0x90]
          case params.to_s.to_sym
          when :off
            params_bytes = [0x00, 0x92]
          when :on
            params_bytes = [0x01, 0x93]
          when :reset
            params_bytes = [0x02, 0x94]
          else
            raise "Unsupported Parameters: #{params} for #{cmd}. Supported parameters are:\n#{list_params(cmd: cmd).join("\n")}\n"
          end
        when :read_port
          cmd_bytes = [0xFF, 0x00, 0x01, 0x00, 0x08]
        when :write_port
          cmd_bytes = [0xFF, 0x00, 0x01, 0x08, 0x09]
        when :halt
          cmd_bytes = [0xFF, 0x00, 0x01, 0x93, 0x94]
        when :set_baud_rate
          cmd_bytes = [0xFF, 0x00, 0x01, 0x09, 0x0A]
        when :sleep
          cmd_bytes = [0xFF, 0x00, 0x01, 0x0A, 0x0B]
        when :poll_buffer
          cmd_bytes = [0xFF, 0x00, 0x01, 0xB0, 0xB1]
        else
          logger.error("Unsupported command: #{cmd}")
          raise "Unsupported Command: #{cmd}. Supported commands are:\n#{list_cmds.join("\n")}\n"
        end

        cmd_bytes += params_bytes unless params_bytes.empty?
        PWN::Plugins::Serial.request(
          serial_obj: son_micro_rfid_obj,
          payload: cmd_bytes
        )

        response = parse_responses(
          son_micro_rfid_obj: son_micro_rfid_obj,
          cmd: cmd.to_sym
        )
        logger.info("Response for #{cmd}: #{response.inspect}")
        response
      rescue StandardError => e
        logger.error("Error executing command #{cmd}: #{e.message}")
        raise e
      ensure
        PWN::Plugins::Serial.flush_session_data
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.read_tag(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method',
      #   authn: 'optional - authentication flag (default: false)',
      #   key: 'optional - key for authentication (default: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])'
      # )

      public_class_method def self.read_tag(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        authn = opts[:authn] ||= false
        key = opts[:key] ||= [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

        logger.info('Starting read_tag')

        print 'Reader Activated. Please Scan Tag...'
        exec_resp = exec(
          son_micro_rfid_obj: son_micro_rfid_obj,
          cmd: :seek_for_tag
        )

        rfid_data = exec_resp.last
        logger.info(rfid_data)

        if rfid_data[:resp_code_desc] == :no_tag_present
          logger.error('No RFID tag detected')
          raise 'No RFID tag detected'
        end

        # Read block data (e.g., block 4 for Ultralight, sector 0 block 0 for Classic)
        case rfid_data[:resp_code_desc]
        when :mifare_ultralight
          exec_resp = exec(
            son_micro_rfid_obj: son_micro_rfid_obj,
            cmd: :read_block,
            params: { block: 4 } # Example block
          )
          rfid_data[:block_data] = exec_resp.last[:block_data] if exec_resp.last[:resp_code_desc] == :read_success
        when :mifare_classic_1k, :mifare_classic_4k
          if authn
            exec_resp = exec(
              son_micro_rfid_obj: son_micro_rfid_obj,
              cmd: :authenticate,
              params: { block: 0, key_type: :key_a, key: key }
            )
            if exec_resp.last[:resp_code_desc] == :auth_success
              exec_resp = exec(
                son_micro_rfid_obj: son_micro_rfid_obj,
                cmd: :read_block,
                params: { block: 0 }
              )
              rfid_data[:block_data] = exec_resp.last[:block_data] if exec_resp.last[:resp_code_desc] == :read_success
            else
              logger.error("Authentication failed for #{rfid_data[:resp_code_desc]}")
              raise 'Authentication failed'
            end
          end
        end

        puts "\n#{rfid_data[:resp_code_desc]} >>> Tag ID: #{rfid_data[:tag_id]}"
        puts "Block Data: #{rfid_data[:block_data]}" if rfid_data[:block_data]
        logger.info("Read tag successful: #{rfid_data.inspect}")
        rfid_data
      rescue StandardError => e
        logger.error("Error reading tag: #{e.message}")
        puts "ERROR: Failed to read tag - #{e.message}"
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.write_tag(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method',
      #   rfid_data: 'required - RFID data to write (see #read_tag for structure)',
      #   authn: 'optional - authentication flag (default: false)',
      #   key: 'optional - key for authentication (default: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])'
      # )

      public_class_method def self.write_tag(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        rfid_data = opts[:rfid_data]
        authn = opts[:authn] ||= false
        key = opts[:key] ||= [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        logger.info('Starting write_tag')

        unless rfid_data.is_a?(Hash) && rfid_data[:resp_code_desc] && rfid_data[:tag_id]
          logger.error('Invalid rfid_data: must be a hash with :resp_code_desc and :tag_id')
          raise 'Invalid rfid_data: must be a hash with :resp_code_desc and :tag_id'
        end

        puts "\nWriting to tag with Tag ID: #{rfid_data[:tag_id]}"
        print 'This will overwrite the tag. Continue? [y/N]: '
        unless gets.chomp.strip.upcase == 'Y'
          logger.info('Write cancelled by user')
          puts 'Write cancelled.'
          return rfid_data
        end

        # Select tag
        exec_resp = exec(
          son_micro_rfid_obj: son_micro_rfid_obj,
          cmd: :select_tag
        )
        if exec_resp.last[:resp_code_desc] == :no_tag_present
          logger.error('No RFID tag detected for writing')
          raise 'No RFID tag detected for writing'
        end

        # Write block data
        case rfid_data[:resp_code_desc]
        when :mifare_ultralight
          if rfid_data[:block_data]
            data = rfid_data[:block_data].split.map { |b| b.to_i(16) }
            exec_resp = exec(
              son_micro_rfid_obj: son_micro_rfid_obj,
              cmd: :write_block,
              params: { block: 4, data: data }
            )
            unless exec_resp.last[:resp_code_desc] == :write_success
              logger.error('Failed to write block for Ultralight')
              raise 'Failed to write block'
            end
          end
        when :mifare_classic_1k, :mifare_classic_4k
          if authn
            exec_resp = exec(
              son_micro_rfid_obj: son_micro_rfid_obj,
              cmd: :authenticate,
              params: { block: 0, key_type: :key_a, key: key }
            )
            if exec_resp.last[:resp_code_desc] == :auth_success
              if rfid_data[:block_data]
                data = rfid_data[:block_data].split.map { |b| b.to_i(16) }
                exec_resp = exec(
                  son_micro_rfid_obj: son_micro_rfid_obj,
                  cmd: :write_block,
                  params: { block: 0, data: data }
                )
                unless exec_resp.last[:resp_code_desc] == :write_success
                  logger.error('Failed to write block for Classic')
                  raise 'Failed to write block'
                end
              end
            else
              logger.error("Authentication failed for #{rfid_data[:resp_code_desc]}")
              raise 'Authentication failed'
            end
          end
        else
          logger.error("Unsupported tag type: #{rfid_data[:resp_code_desc]}")
          raise "Unsupported tag type: #{rfid_data[:resp_code_desc]}"
        end

        # Verify write by re-reading
        read_data = read_tag(son_micro_rfid_obj: son_micro_rfid_obj)
        if read_data[:block_data] == rfid_data[:block_data]
          puts 'Write verification successful.'
          logger.info('Write verification successful')
        else
          puts 'ERROR: Written data does not match read data.'
          logger.error('Written data does not match read data')
        end

        logger.info("Write tag successful: #{rfid_data.inspect}")
        puts 'Tag written successfully.'
        rfid_data
      rescue StandardError => e
        logger.error("Error writing tag: #{e.message}")
        puts "ERROR: Failed to write tag - #{e.message}"
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.backup_tag(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.backup_tag(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        logger.info('Starting backup_tag')

        rfid_data = read_tag(son_micro_rfid_obj: son_micro_rfid_obj)

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
        logger.info("Backup saved to #{file}")
        puts 'Backup complete.'
        rfid_data
      rescue StandardError => e
        logger.error("Error backing up tag: #{e.message}")
        puts "ERROR: Failed to backup tag - #{e.message}"
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.clone_tag(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.clone_tag(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        logger.info('Starting clone_tag')

        print 'This will overwrite the target tag. Continue? [y/N]: '
        unless gets.chomp.strip.upcase == 'Y'
          logger.info('Copy cancelled by user')
          puts 'Copy cancelled.'
          return nil
        end

        rfid_data = read_tag(son_micro_rfid_obj: son_micro_rfid_obj)
        write_tag(
          son_micro_rfid_obj: son_micro_rfid_obj,
          rfid_data: rfid_data
        )
      rescue StandardError => e
        logger.error("Error copying tag: #{e.message}")
        puts "ERROR: Failed to copy tag - #{e.message}"
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.load_tag_from_file(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.load_tag_from_file(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        logger.info('Starting load_tag_from_file')

        print 'This will overwrite the target tag. Continue? [y/N]: '
        unless gets.chomp.strip.upcase == 'Y'
          logger.info('Load cancelled by user')
          puts 'Load cancelled.'
          return nil
        end

        file = ''
        restore_msg = ''
        loop do
          print 'Enter File Name to Restore to Tag: '
          file = gets.scrub.chomp.strip
          break if File.exist?(file)

          restore_msg = "\n****** ERROR: #{file} does not exist ******"
          puts restore_msg
        end

        rfid_data = JSON.parse(File.read(file), symbolize_names: true)
        write_tag(
          son_micro_rfid_obj: son_micro_rfid_obj,
          rfid_data: rfid_data
        )
      rescue StandardError => e
        logger.error("Error loading tag from file: #{e.message}")
        puts "ERROR: Failed to load tag from file - #{e.message}"
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.update_tag(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.update_tag(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]
        logger.info('Starting update_tag')

        print 'This will modify the tag\'s data. Continue? [y/N]: '
        unless gets.chomp.strip.upcase == 'Y'
          logger.info('Update cancelled by user')
          puts 'Update cancelled.'
          return nil
        end

        rfid_data = read_tag(son_micro_rfid_obj: son_micro_rfid_obj)
        unless rfid_data.is_a?(Hash) && rfid_data[:resp_code_desc] && rfid_data[:tag_id]
          logger.error('Invalid rfid_data structure')
          raise 'Invalid rfid_data structure'
        end

        # Update block data
        block_data = rfid_data[:block_data] || ''
        puts "\nCurrent Block Data: #{block_data}"
        print 'Enter Updated Block Data (hex bytes, space-separated, press Enter to keep original): '
        updated_value = gets.scrub.chomp.strip

        if updated_value.empty?
          puts "Keeping original value: #{block_data}"
          logger.info("Keeping original block data: #{block_data}")
          updated_value = block_data
        else
          # Validate hex bytes
          unless updated_value.match?(/\A([\da-fA-F]{2}\s)*[\da-fA-F]{2}\z/)
            logger.error('Invalid block data: must be hex bytes (e.g., FF 00)')
            raise 'Invalid block data: must be hex bytes (e.g., FF 00)'
          end
          # Validate length based on tag type
          data_bytes = updated_value.split.map { |b| b.to_i(16) }
          max_bytes = rfid_data[:resp_code_desc] == :mifare_ultralight ? 4 : 16
          unless data_bytes.length <= max_bytes
            logger.error("Block data too long: max #{max_bytes} bytes")
            raise "Block data too long: max #{max_bytes} bytes"
          end
          logger.info("Updated block data: #{updated_value}")
        end

        rfid_data[:block_data] = updated_value

        # Confirm changes
        puts "\nUpdated RFID Data:"
        puts "Tag ID: #{rfid_data[:tag_id]}"
        puts "Block Data: #{rfid_data[:block_data]}"
        print 'Confirm writing these changes to the tag? [y/N]: '
        unless gets.chomp.strip.upcase == 'Y'
          logger.info('Update cancelled by user')
          puts 'Update cancelled.'
          return rfid_data
        end

        rfid_data = write_tag(
          son_micro_rfid_obj: son_micro_rfid_obj,
          rfid_data: rfid_data
        )

        logger.info("Update tag successful: #{rfid_data.inspect}")
        puts 'tag updated successfully.'
        rfid_data
      rescue StandardError => e
        logger.error("Error updating tag: #{e.message}")
        puts "ERROR: Failed to update tag - #{e.message}"
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SonMicroRFID.disconnect(
      #   son_micro_rfid_obj: 'required - son_micro_rfid_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        son_micro_rfid_obj = opts[:son_micro_rfid_obj]

        logger.info('Disabling antenna power')
        exec(
          son_micro_rfid_obj: son_micro_rfid_obj,
          cmd: :antenna_power,
          params: :off
        )

        logger.info('Disconnecting from device')

        PWN::Plugins::Serial.disconnect(serial_obj: son_micro_rfid_obj)
      rescue StandardError => e
        logger.error("Error disconnecting: #{e.message}")
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        'AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        '
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          son_micro_rfid_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 19_200)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none)',
            flow_control: 'optional - :none|:hard|:soft (defaults to :none)'
          )

          cmds = #{self}.list_cmds

          params = #{self}.list_params(
            cmd: 'required - cmd returned from #list_cmds method'
          )

          parsed_cmd_resp_arr = #{self}.exec(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method',
            cmd: 'required - cmd returned from #list_cmds method',
            params: 'optional - parameters for specific command returned from #list_params method'
          )

          rfid_data = #{self}.read_tag(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method',
            authn: 'optional - authentication flag (default: false)',
            key: 'optional - key for authentication (default: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])'
          )

          rfid_data = #{self}.write_tag(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method',
            rfid_data: 'required - RFID data to write',
            authn: 'optional - authentication flag (default: false)',
            key: 'optional - key for authentication (default: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])'
          )

          rfid_data = #{self}.backup_tag(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method'
          )

          rfid_data = #{self}.clone_tag(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method'
          )

          rfid_data = #{self}.load_tag_from_file(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method'
          )

          rfid_data = #{self}.update_tag(
            son_micro_rfid_obj: 'required son_micro_rfid_obj returned from #connect method'
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
