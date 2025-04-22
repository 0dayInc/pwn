# frozen_string_literal: true

require 'logger'
require 'timeout'

module PWN
  module Plugins
    # This plugin is used for interacting with a three track
    # MSR206 Magnetic Stripe Reader / Writer
    module MSR206
      # Logger instance for auditing and debugging
      private_class_method def self.logger
        @logger ||= Logger.new('msr206.log')
      end

      # Supported Method Parameters::
      # msr206_obj = PWN::Plugins::MSR206.connect(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)',
      #   baud: 'optional - (defaults to 19200)',
      #   data_bits: 'optional - (defaults to 8)',
      #   stop_bits: 'optional - (defaults to 1)',
      #   parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none),'
      #   flow_control: 'optional - :none|:hard|:soft (defaults to :soft)'
      # )

      public_class_method def self.connect(opts = {})
        opts[:block_dev] ||= '/dev/ttyUSB0'
        opts[:baud] ||= 19_200 # Align with device default
        opts[:data_bits] ||= 8
        opts[:stop_bits] ||= 1
        opts[:parity] ||= :none
        opts[:flow_control] ||= :soft

        logger.info("Connecting to #{opts[:block_dev]} at baud #{opts[:baud]}")
        msr206_obj = PWN::Plugins::Serial.connect(opts)
        set_protocol(msr206_obj: msr206_obj, protocol: :usi0) # Default to USI0
        msr206_obj
      rescue StandardError => e
        logger.error("Connection failed: #{e.message}")
        disconnect(msr206_obj: msr206_obj) unless msr206_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # cmds = PWN::Plugins::MSR206.list_cmds
      public_class_method def self.list_cmds
        %i[
          proto_usi0
          proto_usi1
          version_report
          simulate_power_cycle_warm_reset
          configuration_request
          reproduce_last_command
          resume_transmission_to_host
          pause_transmission_to_host
          abort_command
          red_on
          red_off
          red_flash
          green_on
          green_off
          green_flash
          yellow_on
          yellow_off
          yellow_flash
          arm_to_read
          arm_to_read_w_speed_prompts
          tx_iso_std_data_track1
          tx_iso_std_data_track2
          tx_iso_std_data_track3
          alt_tx_iso_std_data_track1
          alt_tx_iso_std_data_track2
          alt_tx_iso_std_data_track3
          tx_error_data
          tx_custom_data_forward_track1
          tx_custom_data_forward_track2
          tx_custom_data_forward_track3
          tx_passbook_data
          alt_tx_passbook_data
          write_verify
          card_edge_detect
          load_iso_std_data_for_writing_track1
          load_iso_std_data_for_writing_track2
          load_iso_std_data_for_writing_track3
          alt_load_iso_std_data_for_writing_track1
          alt_load_iso_std_data_for_writing_track2
          alt_load_iso_std_data_for_writing_track3
          load_passbook_data_for_writing
          load_custom_data_for_writing_track1
          load_custom_data_for_writing_track2
          load_custom_data_for_writing_track3
          set_write_density
          set_write_density_210_bpi_tracks13
          set_write_density_75_bpi_tracks13
          set_write_density_210_bpi_tracks2
          set_write_density_75_bpi_tracks2
          set_default_write_current
          view_default_write_current
          set_temp_write_current
          view_temp_write_current
          arm_to_write_with_raw
          arm_to_write_no_raw
          arm_to_write_with_raw_speed_prompts
        ]
      rescue StandardError => e
        logger.error("Error listing commands: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = decode(
      #   raw_byte_arr: 'required - raw_byte_arr produced in #parse_responses'
      # )

      private_class_method def self.decode(opts = {})
        raw_byte_arr = opts[:raw_byte_arr]
        parity = opts[:parity] || :none
        parity_not_none = %i[odd even]
        decoded_data_str = ''
        return decoded_data_str unless raw_byte_arr

        raw_byte_arr.first.split.each do |byte_str|
          byte = byte_str.to_i(16)
          # Strip parity bit for odd/even parity
          byte &= 0x7F if parity_not_none.include?(parity)

          case byte_str
          when '1B'
            decoded_data_str += "\e" # ESC character
          when '20'
            decoded_data_str += ' '
          when '21'
            decoded_data_str += '!'
          when '22'
            decoded_data_str += '"'
          when '23'
            decoded_data_str += '#'
          when '24'
            decoded_data_str += '$'
          when '25'
            decoded_data_str += '%'
          when '26'
            decoded_data_str += '&'
          when '27'
            decoded_data_str += "'"
          when '28'
            decoded_data_str += '('
          when '29'
            decoded_data_str += ')'
          when '2A', 'AA'
            decoded_data_str += '*'
          when '2B', 'AB'
            decoded_data_str += '+'
          when '2C', 'AC'
            decoded_data_str += ','
          when '2D', 'AD'
            decoded_data_str += '-'
          when '2E', 'AE'
            decoded_data_str += '.'
          when '2F', 'AF'
            decoded_data_str += '/'
          when '30', 'B0'
            decoded_data_str += '0'
          when '31', 'B1'
            decoded_data_str += '1'
          when '32', 'B2'
            decoded_data_str += '2'
          when '33', 'B3'
            decoded_data_str += '3'
          when '34', 'B4'
            decoded_data_str += '4'
          when '35', 'B5'
            decoded_data_str += '5'
          when '36', 'B6'
            decoded_data_str += '6'
          when '37', 'B7'
            decoded_data_str += '7'
          when '38', 'B8'
            decoded_data_str += '8'
          when '39', 'B9'
            decoded_data_str += '9'
          when '3A', 'BA'
            decoded_data_str += ':'
          when '3B', 'BB'
            decoded_data_str += ';'
          when '3C', 'BC'
            decoded_data_str += '<'
          when '3D', 'BD'
            decoded_data_str += '='
          when '3E', 'BE'
            decoded_data_str += '>'
          when '3F', 'BF'
            decoded_data_str += '?'
          when '40', 'C0'
            decoded_data_str += '@'
          when '41', 'C1'
            decoded_data_str += 'A'
          when '42', 'C2'
            decoded_data_str += 'B'
          when '43', 'C3'
            decoded_data_str += 'C'
          when '44', 'C4'
            decoded_data_str += 'D'
          when '45', 'C5'
            decoded_data_str += 'E'
          when '46', 'C6'
            decoded_data_str += 'F'
          when '47', 'C7'
            decoded_data_str += 'G'
          when '48', 'C8'
            decoded_data_str += 'H'
          when '49', 'C9'
            decoded_data_str += 'I'
          when '4A', 'CA'
            decoded_data_str += 'J'
          when '4B', 'CB'
            decoded_data_str += 'K'
          when '4C', 'CC'
            decoded_data_str += 'L'
          when '4D', 'CD'
            decoded_data_str += 'M'
          when '4E', 'CE'
            decoded_data_str += 'N'
          when '4F', 'CF'
            decoded_data_str += 'O'
          when '50', 'D0'
            decoded_data_str += 'P'
          when '51', 'D1'
            decoded_data_str += 'Q'
          when '52', 'D2'
            decoded_data_str += 'R'
          when '53', 'D3'
            decoded_data_str += 'S'
          when '54', 'D4'
            decoded_data_str += 'T'
          when '55', 'D5'
            decoded_data_str += 'U'
          when '56', 'D6'
            decoded_data_str += 'V'
          when '57', 'D7'
            decoded_data_str += 'W'
          when '58', 'D8'
            decoded_data_str += 'X'
          when '59', 'D9'
            decoded_data_str += 'Y'
          when '5A', 'DA'
            decoded_data_str += 'Z'
          when '5B', 'DB'
            decoded_data_str += '['
          when '5C', 'DC'
            decoded_data_str += '\\'
          when '5D', 'DD'
            decoded_data_str += ']'
          when '5E', 'DE'
            decoded_data_str += '^'
          when '5F', 'DF'
            decoded_data_str += '_'
          when '60', 'E0'
            decoded_data_str += '`'
          when '61', 'E1'
            decoded_data_str += 'a'
          when '62', 'E2'
            decoded_data_str += 'b'
          when '63', 'E3'
            decoded_data_str += 'c'
          when '64', 'E4'
            decoded_data_str += 'd'
          when '65', 'E5'
            decoded_data_str += 'e'
          when '66', 'E6'
            decoded_data_str += 'f'
          when '67', 'E7'
            decoded_data_str += 'g'
          when '68', 'E8'
            decoded_data_str += 'h'
          when '69', 'E9'
            decoded_data_str += 'i'
          when '6A', 'EA'
            decoded_data_str += 'j'
          when '6B', 'EB'
            decoded_data_str += 'k'
          when '6C', 'EC'
            decoded_data_str += 'l'
          when '6D', 'ED'
            decoded_data_str += 'm'
          when '6E', 'EE'
            decoded_data_str += 'n'
          when '6F', 'EF'
            decoded_data_str += 'o'
          when '70', 'F0'
            decoded_data_str += 'p'
          when '71', 'F1'
            decoded_data_str += 'q'
          when '72', 'F2'
            decoded_data_str += 'r'
          when '73', 'F3'
            decoded_data_str += 's'
          when '74', 'F4'
            decoded_data_str += 't'
          when '75', 'F5'
            decoded_data_str += 'u'
          when '76', 'F6'
            decoded_data_str += 'v'
          when '77', 'F7'
            decoded_data_str += 'w'
          when '78', 'F8'
            decoded_data_str += 'x'
          when '79', 'F9'
            decoded_data_str += 'y'
          when '7A', 'FA'
            decoded_data_str += 'z'
          when '7B', 'FB'
            decoded_data_str += '{'
          when '7C', 'FC'
            decoded_data_str += '|'
          when '7D', 'FD'
            decoded_data_str += '}'
          when '7E', 'FE'
            decoded_data_str += '~'
          else
            decoded_data_str += "\u00BF" # Unknown character
          end
        end
        decoded_data_str
      rescue StandardError => e
        logger.error("Error decoding response: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = binary(
      #   raw_byte_arr: 'required - raw_byte_arr produced in #parse_responses'
      # )

      private_class_method def self.binary(opts = {})
        raw_byte_arr = opts[:raw_byte_arr]
        binary_byte_arr = []
        if raw_byte_arr
          raw_byte_arr.first.split.each do |byte_str|
            binary_byte_arr.push([byte_str].pack('H*').unpack1('B*'))
          end
        end
        binary_byte_arr
      rescue StandardError => e
        logger.error("Error converting to binary: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = parse_responses(
      #   cmd_resp: 'required - command response string'
      # )

      private_class_method def self.parse_responses(opts = {})
        msr206_obj = opts[:msr206_obj]
        cmd = opts[:cmd]
        cmd_bytes = opts[:cmd_bytes]

        Timeout.timeout(5) do # 5-second timeout
          keep_parsing_responses = true
          next_response_detected = false
          response = {}
          response[:cmd] = cmd || :na
          response[:cmd_bytes] = cmd_bytes&.map { |b| "0x#{b.to_s(16).rjust(2, '0')}" } || :na

          raw_byte_arr = []
          raw_byte_arr_len = 0
          last_raw_byte_arr_len = 0
          cmd_resp = ''

          while keep_parsing_responses
            until next_response_detected
              last_raw_byte_arr_len = raw_byte_arr_len
              raw_byte_arr = PWN::Plugins::Serial.response(serial_obj: msr206_obj)
              cmd_resp = raw_byte_arr.last
              raw_byte_arr_len = raw_byte_arr.length
              next_response_detected = true if raw_byte_arr_len > last_raw_byte_arr_len
            end

            case cmd_resp
            when '21', 'A1'
              response[:msg] = :invalid_command
            when '28', 'A8'
              response[:msg] = :card_speed_measurement_start
            when '29', 'A9'
              response[:msg] = :card_speed_measurement_end
            when '2A', 'AA'
              response[:msg] = :error
            when '2B', 'AB'
              response[:msg] = :no_data_found
            when '2D', 'AD'
              response[:msg] = :insufficient_leading_zeros_for_custom_writing
            when '2F', 'AF'
              response[:msg] = :first_lsb_char_not_one_for_custom_writing
            when '31', 'B1'
              response[:msg] = :unsuccessful_read_after_write_track1
            when '32', 'B2'
              response[:msg] = :unsuccessful_read_after_write_track2
            when '33', 'B3'
              response[:msg] = :unsuccessful_read_after_write_track3
            when '3A', 'BA'
              response[:msg] = :power_on_report
            when '3E', 'BE'
              response[:msg] = :card_edge_detected
            when '3F', 'BF'
              response[:msg] = :communications_error
            when '5E'
              response[:msg] = :ack_command_completed
            when '7E'
              response[:msg] = :command_not_supported_by_hardware
            else
              response[:msg] = :response
            end

            next_response_detected = false
            last_raw_byte_arr_len = raw_byte_arr_len
            keep_parsing_responses = false
          end

          response[:hex] = raw_byte_arr
          response[:binary] = binary(raw_byte_arr: raw_byte_arr)
          response[:decoded] = decode(raw_byte_arr: raw_byte_arr)
          response
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
      # PWN::Plugins::MSR206.set_protocol(
      #   msr206_obj: 'required - msr206_obj returned from #connect method',
      #   protocol: 'optional - :usi0 or :usi1 (defaults to :usi0)'
      # )

      public_class_method def self.set_protocol(opts = {})
        msr206_obj = opts[:msr206_obj]
        protocol = opts[:protocol] || :usi0
        cmd = protocol == :usi0 ? :proto_usi0 : :proto_usi1
        logger.info("Setting protocol to #{protocol}")
        exec(msr206_obj: msr206_obj, cmd: cmd)
      rescue StandardError => e
        logger.error("Error setting protocol: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.exec(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      #   cmd: 'required - cmd returned from #list_cmds method',
      #   params: 'optional - parameters for specific command returned from #list_params method'
      # )

      public_class_method def self.exec(opts = {})
        msr206_obj = opts[:msr206_obj]
        cmd = opts[:cmd].to_s.scrub.strip.chomp
        params = opts[:params]
        raise 'ERROR: params argument must be a byte array (e.g. [0x41]).' if params && !params.instance_of?(Array)

        logger.info("Executing command: #{cmd} with params: #{params.inspect}")

        params_bytes = []
        case cmd.to_sym
        when :proto_usi0
          cmd_bytes = [0x55, 0x53, 0x49, 0x30]
        when :proto_usi1
          cmd_bytes = [0x55, 0x53, 0x49, 0x31]
        when :resume_transmission_to_host
          cmd_bytes = [0x11]
        when :pause_transmission_to_host
          cmd_bytes = [0x13]
        when :abort_command
          cmd_bytes = [0x1B]
        when :configuration_request
          cmd_bytes = [0x23]
        when :reproduce_last_command
          cmd_bytes = [0x25]
        when :card_edge_detect
          cmd_bytes = [0x26]
        when :green_flash
          cmd_bytes = [0x28]
        when :red_flash
          cmd_bytes = [0x29]
        when :version_report
          cmd_bytes = [0x39]
        when :set_write_density
          cmd_bytes = [0x3B]
        when :set_temp_write_current
          cmd_bytes = [0x3C]
        when :view_temp_write_current
          cmd_bytes = [0x3E]
        when :write_verify
          cmd_bytes = [0x3F]
        when :arm_to_write_with_raw
          cmd_bytes = [0x40]
        when :load_iso_std_data_for_writing_track1
          cmd_bytes = [0x41]
        when :load_iso_std_data_for_writing_track2
          cmd_bytes = [0x42]
        when :load_iso_std_data_for_writing_track3
          cmd_bytes = [0x43]
        when :load_custom_data_for_writing_track1
          cmd_bytes = [0x45]
        when :load_custom_data_for_writing_track2
          cmd_bytes = [0x46]
        when :load_custom_data_for_writing_track3
          cmd_bytes = [0x47]
        when :tx_error_data
          cmd_bytes = [0x49]
        when :yellow_on
          cmd_bytes = [0x4B]
        when :green_on
          cmd_bytes = [0x4C]
        when :red_on
          cmd_bytes = [0x4D]
        when :set_write_density_210_bpi_tracks2
          cmd_bytes = [0x4E]
        when :set_write_density_210_bpi_tracks13
          cmd_bytes = [0x4F]
        when :arm_to_read
          cmd_bytes = [0x50]
        when :tx_iso_std_data_track1
          cmd_bytes = [0x51]
        when :tx_iso_std_data_track2
          cmd_bytes = [0x52]
        when :tx_iso_std_data_track3
          cmd_bytes = [0x53]
        when :tx_custom_data_forward_track1
          cmd_bytes = [0x55]
        when :tx_custom_data_forward_track2
          cmd_bytes = [0x56]
        when :tx_custom_data_forward_track3
          cmd_bytes = [0x57]
        when :tx_passbook_data
          cmd_bytes = [0x58]
        when :arm_to_write_no_raw
          cmd_bytes = [0x5A]
        when :set_default_write_current
          cmd_bytes = [0x5B]
        when :view_default_write_current
          cmd_bytes = [0x5D]
        when :alt_load_iso_std_data_for_writing_track1
          cmd_bytes = [0x61]
        when :alt_load_iso_std_data_for_writing_track2
          cmd_bytes = [0x62]
        when :alt_load_iso_std_data_for_writing_track3
          cmd_bytes = [0x63]
        when :load_passbook_data_for_writing
          cmd_bytes = [0x6A]
        when :yellow_off
          cmd_bytes = [0x6B]
        when :green_off
          cmd_bytes = [0x6C]
        when :red_off
          cmd_bytes = [0x6D]
        when :set_write_density_75_bpi_tracks2
          cmd_bytes = [0x6E]
        when :set_write_density_75_bpi_tracks13
          cmd_bytes = [0x6F]
        when :arm_to_read_w_speed_prompts
          cmd_bytes = [0x70]
        when :alt_tx_iso_std_data_track1
          cmd_bytes = [0x71]
        when :alt_tx_iso_std_data_track2
          cmd_bytes = [0x72]
        when :alt_tx_iso_std_data_track3
          cmd_bytes = [0x73]
        when :alt_tx_passbook_data
          cmd_bytes = [0x78]
        when :arm_to_write_with_raw_speed_prompts
          cmd_bytes = [0x7A]
        when :yellow_flash
          cmd_bytes = [0x7C]
        when :simulate_power_cycle_warm_reset
          cmd_bytes = [0x7F]
        else
          logger.error("Unsupported command: #{cmd}")
          raise "Unsupported Command: #{cmd}. Supported commands are:\n#{list_cmds.join("\n")}\n"
        end

        cmd_bytes += params if params
        PWN::Plugins::Serial.request(
          serial_obj: msr206_obj,
          payload: cmd_bytes
        )

        response = parse_responses(
          msr206_obj: msr206_obj,
          cmd: cmd.to_sym,
          cmd_bytes: cmd_bytes
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
      # MSR206.wait_for_swipe(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      #   type: 'required - swipe type :arm_to_read || :arm_to_read_w_speed_prompts || :arm_to_write_no_raw || :arm_to_write_with_raw || :arm_to_write_with_raw_speed_prompts',
      #   encoding: 'required - :iso || :iso_alt || :raw',
      #   track_data: 'optional - track_data to write'
      # )

      private_class_method def self.wait_for_swipe(opts = {})
        msr206_obj = opts[:msr206_obj]
        type = opts[:type].to_s.scrub.strip.chomp.to_sym
        encoding = opts[:encoding].to_s.scrub.strip.chomp.to_sym
        track_data = opts[:track_data]

        logger.info("Waiting for swipe: type=#{type}, encoding=#{encoding}")

        exec_resp = exec(msr206_obj: msr206_obj, cmd: :red_off)
        exec_resp = exec(msr206_obj: msr206_obj, cmd: :yellow_off)
        exec_resp = exec(msr206_obj: msr206_obj, cmd: :green_on)

        track_data_arr = []

        # Check for card edge detection
        exec_resp = exec(msr206_obj: msr206_obj, cmd: :card_edge_detect)
        unless exec_resp[:msg] == :card_edge_detected
          logger.warn('Card not detected')
          puts 'WARNING: Card not detected. Please ensure card is ready.'
        end

        case type
        when :arm_to_read, :arm_to_read_w_speed_prompts
          exec_resp = exec(msr206_obj: msr206_obj, cmd: type)
          logger.info("Arm to read response: #{exec_resp.inspect}")

          print 'Reader Activated. Please Swipe Card...'
          loop do
            exec_resp = parse_responses(msr206_obj: msr206_obj, cmd: type)
            puts exec_resp[:msg]
            break if exec_resp[:msg] == :ack_command_completed
          end

          case encoding
          when :iso
            cmds_arr = %i[
              tx_iso_std_data_track1
              tx_iso_std_data_track2
              tx_iso_std_data_track3
            ]
            cmds_arr.each do |cmd|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              exec_resp = exec(msr206_obj: msr206_obj, cmd: cmd)
              exec_resp[:encoding] = encoding
              puts exec_resp[:decoded]
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          when :iso_alt
            cmds_arr = %i[
              alt_tx_iso_std_data_track1
              alt_tx_iso_std_data_track2
              alt_tx_iso_std_data_track3
            ]
            cmds_arr.each do |cmd|
              params_arr = [0x31, 0x32, 0x33]
              params_arr.each do |param|
                puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
                exec_resp = exec(msr206_obj: msr206_obj, cmd: cmd, params: [param])
                exec_resp[:encoding] = encoding
                exec_resp[:track_format] = [param]
                puts exec_resp[:decoded]
                puts exec_resp.inspect
                track_data_arr.push(exec_resp)
              end
            end
          when :raw
            cmds_arr = %i[
              tx_custom_data_forward_track1
              tx_custom_data_forward_track2
              tx_custom_data_forward_track3
            ]
            cmds_arr.each do |cmd|
              params_arr = [0x33, 0x34, 0x35, 0x36, 0x37]
              params_arr.each do |param|
                puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
                exec_resp = exec(msr206_obj: msr206_obj, cmd: cmd, params: [param])
                exec_resp[:encoding] = encoding
                exec_resp[:track_format] = [param]
                puts exec_resp[:decoded]
                puts exec_resp.inspect
                track_data_arr.push(exec_resp)

                param = [0x5f] + [param]
                exec_resp = exec(msr206_obj: msr206_obj, cmd: cmd, params: param)
                exec_resp[:encoding] = encoding
                exec_resp[:track_format] = param
                puts exec_resp[:decoded]
                puts exec_resp.inspect
                track_data_arr.push(exec_resp)
              end
            end
          else
            logger.error("Unsupported encoding: #{encoding}")
            raise "Unsupported encoding: #{encoding}"
          end

        when :arm_to_write_no_raw, :arm_to_write_with_raw, :arm_to_write_with_raw_speed_prompts
          unless track_data.is_a?(Array) && track_data.all? { |t| t.is_a?(Hash) && t.key?(:decoded) }
            logger.error('Invalid track_data: must be an array of hashes with :decoded key')
            raise 'Invalid track_data: must be an array of hashes with :decoded key'
          end

          case encoding
          when :iso
            cmds_arr = %i[
              load_iso_std_data_for_writing_track1
              load_iso_std_data_for_writing_track2
              load_iso_std_data_for_writing_track3
            ]
            cmds_arr.each_with_index do |cmd, track|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              # next unless track_data[track]&.key?(:decoded) && track_data[track][:decoded]&.strip&.length&.positive?

              this_track = track_data[track][:decoded].chars.map do |c|
                c.unpack1('H*').to_i(16)
              end
              track_eot = [0x04]
              track_payload = this_track + track_eot
              puts track_payload.inspect
              exec_resp = exec(msr206_obj: msr206_obj, cmd: cmd, params: track_payload)
              exec_resp[:encoding] = encoding
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          when :iso_alt
            cmds_arr = %i[
              alt_load_iso_std_data_for_writing_track1
              alt_load_iso_std_data_for_writing_track2
              alt_load_iso_std_data_for_writing_track3
            ]
            cmds_arr.each_with_index do |cmd, track|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              # next unless track_data[track]&.key?(:decoded) && track_data[track][:decoded]&.strip&.length&.positive?

              this_track = track_data[track][:decoded].chars.map do |c|
                c.unpack1('H*').to_i(16)
              end
              track_format = track_data[track][:track_format] || [0x31]
              track_eot = [0x04]
              track_payload = track_format + this_track + track_eot
              puts track_payload.inspect
              exec_resp = exec(msr206_obj: msr206_obj, cmd: cmd, params: track_payload)
              exec_resp[:encoding] = encoding
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          when :raw
            cmds_arr = %i[
              load_custom_data_for_writing_track1
              load_custom_data_for_writing_track2
              load_custom_data_for_writing_track3
            ]
            cmds_arr.each_with_index do |cmd, track|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              # next unless track_data[track]&.key?(:decoded) && track_data[track][:decoded]&.strip&.length&.positive?

              this_track = track_data[track][:decoded].chars.map do |c|
                c.unpack1('H*').to_i(16)
              end
              track_format = track_data[track][:track_format] || [0x33]
              track_eot = [0x04]
              track_payload = track_format + this_track + track_eot
              puts track_payload.inspect
              exec_resp = exec(msr206_obj: msr206_obj, cmd: cmd, params: track_payload)
              exec_resp[:encoding] = encoding
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          else
            logger.error("Unsupported encoding: #{encoding}")
            raise "Unsupported encoding: #{encoding}"
          end

          exec_resp = exec(msr206_obj: msr206_obj, cmd: type)
          logger.info("Arm to write response: #{exec_resp.inspect}")

          print 'Writer Activated. Please Swipe Card...'
          loop do
            exec_resp = parse_responses(msr206_obj: msr206_obj, cmd: type)
            break if exec_resp[:msg] == :ack_command_completed
          end
        else
          logger.error("Unsupported swipe type: #{type}")
          raise "Unsupported type in #wait_for_swipe: #{type}"
        end

        track_data_arr
      rescue StandardError => e
        logger.error("Error in wait_for_swipe: #{e.message}")
        raise e
      ensure
        exec(msr206_obj: msr206_obj, cmd: :green_off)
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.read_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.read_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        logger.info('Starting read_card')

        encoding = :waiting_for_selection
        loop do
          puts "\nENCODING OPTIONS:"
          puts '[(I)SO Standard]'
          puts '[(A)LT ISO Standard]'
          puts '[(R)aw]'
          print 'ENCODING TYPE >>> '
          encoding_choice = gets.scrub.chomp.strip.upcase.to_sym

          case encoding_choice
          when :I
            encoding = :iso
            break
          when :A
            encoding = :iso_alt
            break
          when :R
            encoding = :raw
            break
          end
        end

        track_data = wait_for_swipe(
          msr206_obj: msr206_obj,
          type: :arm_to_read,
          encoding: encoding
        )
        logger.info("Read card successful: #{track_data.inspect}")
        track_data
      rescue StandardError => e
        logger.error("Error reading card: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.backup_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.backup_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        logger.info('Starting backup_card')

        track_data = read_card(msr206_obj: msr206_obj)

        file = ''
        backup_msg = ''
        loop do
          exec(msr206_obj: msr206_obj, cmd: :green_flash) if backup_msg.empty?

          print 'Enter File Name to Save Backup: '
          file = gets.scrub.chomp.strip
          file_dir = File.dirname(file)
          break if Dir.exist?(file_dir)

          backup_msg = "\n****** ERROR: Directory #{file_dir} for #{file} does not exist ******"
          puts backup_msg
          exec(msr206_obj: msr206_obj, cmd: :green_off)
          exec(msr206_obj: msr206_obj, cmd: :yellow_flash)
        end

        File.write(file, "#{JSON.pretty_generate(track_data)}\n")
        exec(msr206_obj: msr206_obj, cmd: :yellow_off)
        logger.info("Backup saved to #{file}")
        puts 'Backup complete.'
        track_data
      rescue StandardError => e
        logger.error("Error backing up card: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.write_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method',
      #   encoding: 'required - :iso || :iso_alt || :raw',
      #   track_data: 'required - track data to write (see #backup_card for structure)'
      # )

      public_class_method def self.write_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        encoding = opts[:encoding].to_s.scrub.strip.chomp.to_sym
        track_data = opts[:track_data]

        logger.info("Starting write_card with encoding: #{encoding}")
        puts 'IN ORDER TO GET BLANK TRACKS, A STRONG MAGNETIC FIELD MUST BE PRESENT TO FIRST WIPE THE CARD TARGETED FOR WRITING.'

        # Set track density
        density = :waiting_for_selection
        loop do
          puts "\nTRACK DENSITY OPTIONS:"
          puts '[(H)igh (210 BPI, Tracks 1 & 3)]'
          puts '[(L)ow (75 BPI, Tracks 1 & 3)]'
          puts '[(T2H)igh (210 BPI, Track 2)]'
          puts '[(T2L)ow (75 BPI, Track 2)]'
          print 'TRACK DENSITY >>> '
          density_choice = gets.scrub.chomp.strip.upcase.to_sym

          case density_choice
          when :H
            exec(msr206_obj: msr206_obj, cmd: :set_write_density_210_bpi_tracks13)
            break
          when :L
            exec(msr206_obj: msr206_obj, cmd: :set_write_density_75_bpi_tracks13)
            break
          when :T2H
            exec(msr206_obj: msr206_obj, cmd: :set_write_density_210_bpi_tracks2)
            break
          when :T2L
            exec(msr206_obj: msr206_obj, cmd: :set_write_density_75_bpi_tracks2)
            break
          end
        end

        # Set coercivity
        coercivity = :waiting_for_selection
        loop do
          puts "\nCOERCIVITY OPTIONS:"
          puts '[(H)igh (Most Often Black Stripe)]'
          puts '[(L)ow (Most Often Brown Stripe)]'
          print 'COERCIVITY LEVEL >>> '
          coercivity_choice = gets.scrub.chomp.strip.upcase.to_sym

          case coercivity_choice
          when :H
            coercivity = [0x32, 0x35, 0x35] # 255 for high coercivity
            break
          when :L
            coercivity = [0x30, 0x33, 0x36] # 36 for low coercivity
            break
          end
        end

        exec(msr206_obj: msr206_obj, cmd: :set_temp_write_current, params: coercivity)

        track_data = wait_for_swipe(
          msr206_obj: msr206_obj,
          type: :arm_to_write_no_raw,
          encoding: encoding,
          track_data: track_data
        )

        # Verify write
        exec_resp = exec(msr206_obj: msr206_obj, cmd: :write_verify)
        if exec_resp[:msg] == :ack_command_completed
          puts 'Write verification successful.'
          logger.info('Write verification successful')
        else
          puts "Write verification failed: #{exec_resp[:msg]}"
          logger.error("Write verification failed: #{exec_resp[:msg]}")
        end

        # Re-read card to confirm
        read_data = read_card(msr206_obj: msr206_obj)
        if read_data.map { |t| t[:decoded] } == track_data.map { |t| t[:decoded] }
          puts 'Card data matches written data.'
          logger.info('Card data matches written data')
        else
          puts 'ERROR: Written data does not match read data.'
          logger.error('Written data does not match read data')
        end

        exec(msr206_obj: msr206_obj, cmd: :simulate_power_cycle_warm_reset)
        track_data
      rescue StandardError => e
        logger.error("Error writing card: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.clone_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.clone_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        logger.info('Starting clone_card')

        track_data = backup_card(msr206_obj: msr206_obj)
        encoding = track_data.first[:encoding] if track_data.length == 3
        write_card(
          msr206_obj: msr206_obj,
          encoding: encoding,
          track_data: track_data
        )
      rescue StandardError => e
        logger.error("Error cloning card: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.load_card_from_file(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.load_card_from_file(opts = {})
        msr206_obj = opts[:msr206_obj]
        logger.info('Starting load_card_from_file')

        file = ''
        restore_msg = ''
        loop do
          exec(msr206_obj: msr206_obj, cmd: :green_flash) if restore_msg.empty?

          print 'Enter File Name to Restore to Card: '
          file = gets.scrub.chomp.strip
          break if File.exist?(file)

          restore_msg = "\n****** ERROR: #{file} does not exist ******"
          puts restore_msg
          exec(msr206_obj: msr206_obj, cmd: :green_off)
          exec(msr206_obj: msr206_obj, cmd: :yellow_flash)
        end

        track_data = JSON.parse(File.read(file), symbolize_names: true)
        exec(msr206_obj: msr206_obj, cmd: :yellow_off)

        encoding = track_data.first[:encoding] || :iso
        write_card(
          msr206_obj: msr206_obj,
          encoding: encoding,
          track_data: track_data
        )
      rescue StandardError => e
        logger.error("Error loading card from file: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.update_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.update_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        logger.info('Starting update_card')

        # Check for card presence
        exec_resp = exec(msr206_obj: msr206_obj, cmd: :card_edge_detect)
        unless exec_resp[:msg] == :card_edge_detected
          logger.error('Card not detected')
          raise 'Card not detected. Please ensure a card is inserted.'
        end

        # Read card to backup
        track_data = backup_card(msr206_obj: msr206_obj)
        unless track_data.is_a?(Array) && track_data.all? { |t| t.is_a?(Hash) && t.key?(:decoded) }
          logger.error('Invalid track data structure')
          raise 'Invalid track data structure'
        end

        # Update each track's decoded value
        track_data.each_with_index do |track, index|
          decoded = track[:decoded]
          puts "\nTrack #{index + 1} Current Value: #{decoded}"
          print 'Enter Updated Value (press Enter to keep original): '
          updated_value = gets.scrub.chomp.strip

          # Retain original value if empty
          if updated_value.empty?
            puts "Keeping original value: #{decoded}"
            logger.info("Track #{index + 1}: Keeping original value: #{decoded}")
            updated_value = decoded
          else
            # Validate input for ISO encoding
            if track[:encoding] == :iso
              max_length = case index
                           when 0 then 79 # Track 1
                           when 1 then 40 # Track 2
                           when 2 then 107 # Track 3
                           end
              unless updated_value.length <= max_length
                logger.error("Track #{index + 1}: Input too long (max #{max_length} characters)")
                raise "Track #{index + 1}: Input too long (max #{max_length} characters)"
              end
              unless updated_value.match?(/\A[ -~]*\z/) # ASCII printable characters only
                logger.error("Track #{index + 1}: Invalid characters for ISO encoding")
                raise "Track #{index + 1}: Invalid characters for ISO encoding"
              end
            end
            logger.info("Track #{index + 1}: Updated value: #{updated_value}")
          end

          track[:decoded] = updated_value
        end

        # Confirm changes
        puts "\nUpdated Track Data:"
        track_data.each_with_index { |t, i| puts "Track #{i + 1}: #{t[:decoded]}" }
        print 'Confirm writing these changes to the card? [y/N]: '
        unless gets.chomp.strip.upcase == 'Y'
          logger.info('Update cancelled by user')
          puts 'Update cancelled.'
          return track_data
        end

        # Write updated data
        encoding = track_data.first[:encoding] || :iso
        track_data = write_card(
          msr206_obj: msr206_obj,
          encoding: encoding,
          track_data: track_data
        )

        logger.info("Update card successful: #{track_data.inspect}")
        puts 'Card updated successfully.'
        track_data
      rescue StandardError => e
        logger.error("Error updating card: #{e.message}")
        puts "ERROR: Failed to update card - #{e.message}"
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.get_config(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.get_config(opts = {})
        msr206_obj = opts[:msr206_obj]
        logger.info('Retrieving configuration')

        exec_resp = exec(msr206_obj: msr206_obj, cmd: :configuration_request)
        config_arr = exec_resp[:binary].first.reverse.chars
        config_hash = {
          track1_read: false,
          track2_read: false,
          track3_read: false,
          track1_write: false,
          track2_write: false,
          track3_write: false,
          not_used: false,
          parity: false
        }

        config_arr.each_with_index do |bit_str, i|
          bit = bit_str.to_i
          config_hash[:track1_read] = true if i.zero? && bit == 1
          config_hash[:track2_read] = true if i == 1 && bit == 1
          config_hash[:track3_read] = true if i == 2 && bit == 1
          config_hash[:not_used] = true if i == 3 && bit == 1
          config_hash[:track3_write] = true if i == 4 && bit == 1
          config_hash[:track2_write] = true if i == 5 && bit == 1
          config_hash[:track1_write] = true if i == 6 && bit == 1
          config_hash[:parity] = true if i == 7 && bit == 1
        end

        logger.info("Configuration: #{config_hash.inspect}")
        config_hash
      rescue StandardError => e
        logger.error("Error getting configuration: #{e.message}")
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.disconnect(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        logger.info('Disconnecting from device')
        PWN::Plugins::Serial.disconnect(serial_obj: opts[:msr206_obj])
      rescue StandardError => e
        logger.error("Error disconnecting: #{e.message}")
        raise e
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
          msr206_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 19200)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional - :even||:odd|:none (defaults to :none)',
            flow_control: 'optional - :none||:hard||:soft (defaults to :soft)'
          )

          #{self}.set_protocol(
            msr206_obj: 'required - msr206_obj returned from #connect method',
            protocol: 'optional - :usi0 or :usi1 (defaults to :usi0)'
          )

          cmds = #{self}.list_cmds

          parsed_cmd_resp_arr = #{self}.exec(
            msr206_obj: 'required msr206_obj returned from #connect method',
            cmd: 'required - cmd returned from #list_cmds method',
            params: 'optional - parameters for specific command'
          )

          track_data = #{self}.read_card(
            msr206_obj: 'required msr206_obj returned from #connect method'
          )

          track_data = #{self}.backup_card(
            msr206_obj: 'required msr206_obj returned from #connect method'
          )

          track_data = #{self}.write_card(
            msr206_obj: 'required msr206_obj returned from #connect method',
            encoding: 'required - :iso || :iso_alt || :raw',
            track_data: 'required - track data to write'
          )

          track_data = #{self}.clone_card(
            msr206_obj: 'required msr206_obj returned from #connect method'
          )

          track_data = #{self}.load_card_from_file(
            msr206_obj: 'required msr206_obj returned from #connect method'
          )

          track_data = #{self}.update_card(
            msr206_obj: 'required msr206_obj returned from #connect method'
          )

          config = #{self}.get_config(
            msr206_obj: 'required msr206_obj returned from #connect method'
          )

          #{self}.disconnect(
            msr206_obj: 'required msr206_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
