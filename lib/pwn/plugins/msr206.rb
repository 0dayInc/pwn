# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin is used for interacting with a three track
    # MSR206 Magnetic Stripe Reader / Writer
    module MSR206
      # Supported Method Parameters::
      # msr206_obj = PWN::Plugins::MSR206.connect(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)',
      #   baud: 'optional - (defaults to 9600)',
      #   data_bits: 'optional - (defaults to 8)',
      #   stop_bits: 'optional - (defaults to 1)',
      #   parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none),'
      #   flow_control: 'optional - :none||:hard||:soft (defaults to :none)'
      # )

      public_class_method def self.connect(opts = {})
        # Default Baud Rate for this Device is 19200
        opts[:block_dev] = '/dev/ttyUSB0' unless opts[:block_dev]
        opts[:baud] = 9_600 unless opts[:baud]
        opts[:data_bits] = 8 unless opts[:data_bits]
        opts[:stop_bits] = 1 unless opts[:stop_bits]
        opts[:parity] = :none unless opts[:parity]
        opts[:flow_control] = :none unless opts[:flow_control]
        msr206_obj = PWN::Plugins::Serial.connect(opts)
      rescue StandardError => e
        disconnect(msr206_obj: msr206_obj) unless msr206_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      #  cmds = PWN::Plugins::MSR206.list_cmds
      public_class_method def self.list_cmds
        # Returns an Array of Symbols
        cmds = %i[
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
        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = decode(
      #   raw_byte_arr: 'required - raw_byte_arr produced in #parse_responses'
      # )

      private_class_method def self.decode(opts = {})
        raw_byte_arr = opts[:raw_byte_arr]

        decoded_data_str = ''
        if raw_byte_arr
          raw_byte_arr.first.split.each do |byte_str|
            case byte_str
            when '1B'
              decoded_data_str += ''
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
              decoded_data_str += "\u00BF"
            end
          end
        end

        decoded_data_str
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = parse_responses(
      #   cmd_resp: 'required - command response string'
      # )

      private_class_method def self.parse_responses(opts = {})
        msr206_obj = opts[:msr206_obj]
        cmd = opts[:cmd]

        keep_parsing_responses = true
        next_response_detected = false
        response = {}
        response[:cmd] = cmd
        response[:cmd] ||= :na

        raw_byte_arr = []
        a_cmd_r_len = 0
        last_a_cmd_r_len = 0

        parsed_cmd_resp_arr = []
        bytes_in_cmd_resp = 0
        cmd_resp = ''

        while keep_parsing_responses
          until next_response_detected
            raw_byte_arr = PWN::Plugins::Serial.response(serial_obj: msr206_obj)
            cmd_resp = raw_byte_arr.last
            bytes_in_cmd_resp = cmd_resp.split.length if cmd_resp
            a_cmd_r_len = raw_byte_arr.length

            next_response_detected = true if a_cmd_r_len > last_a_cmd_r_len
          end

          case cmd_resp
          when '21'
            response[:msg] = :invalid_command
          when '28'
            response[:msg] = :card_speed_measurement_start
          when '29'
            response[:msg] = :card_speed_measurement_end
          when '2A'
            response[:msg] = :error
          when '2B'
            response[:msg] = :no_data_found
          when '2D'
            response[:msg] = :insufficient_leading_zeros_for_custom_writing
          when '2F'
            response[:msg] = :first_lsb_char_not_one_for_custom_writing
          when '3A'
            response[:msg] = :power_on_report
          when '31'
            response[:msg] = :unsuccessful_read_after_write_track1
          when '32'
            response[:msg] = :unsuccessful_read_after_write_track2
          when '33'
            response[:msg] = :unsuccessful_read_after_write_track3
          when '3E'
            response[:msg] = :card_edge_detected
          when '3F'
            response[:msg] = :communications_error
          when '5E'
            response[:msg] = :ack_command_completed
          when '7E'
            response[:msg] = :command_not_supported_by_hardware
          else
            response[:msg] = :na
          end

          next_response_detected = false
          last_a_cmd_r_len = a_cmd_r_len
          keep_parsing_responses = false
        end

        response[:raw] = raw_byte_arr
        response[:decoded] = decode(raw_byte_arr: raw_byte_arr)
        response
      rescue StandardError => e
        raise e
      ensure
        # Flush Responses for Next Request
        PWN::Plugins::Serial.flush_session_data
      end

      # Supported Method Parameters::
      #  PWN::Plugins::MSR206.exec(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      #   cmd: 'required - cmd returned from #list_cmds method',
      #   params: 'optional - parameters for specific command returned from #list_params method'
      # )
      public_class_method def self.exec(opts = {})
        msr206_obj = opts[:msr206_obj]
        cmd = opts[:cmd].to_s.scrub.strip.chomp
        params = opts[:params].to_s.scrub.strip.chomp

        params_bytes = []
        case cmd.to_sym
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
        when :tx_custom_data_forward_track1, :load_custom_data_for_writing_track1
          cmd_bytes = [0x45]
        when :tx_custom_data_forward_track2, :load_custom_data_for_writing_track2
          cmd_bytes = [0x46]
        when :tx_custom_data_forward_track3, :load_custom_data_for_writing_track3
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
          raise "Unsupported Command: #{cmd}.  Supported commands are:\n#{list_cmds}\n\n\n"
        end

        # If parameters to a command are set, append them.
        cmd_bytes += params_bytes unless params_bytes.empty?
        # Execute the command.
        PWN::Plugins::Serial.request(
          serial_obj: msr206_obj,
          payload: cmd_bytes
        )

        # Parse commands response(s).
        # Return an array of hashes.
        parse_responses(
          msr206_obj: msr206_obj,
          cmd: cmd.to_sym
        )
      rescue StandardError => e
        raise e
      ensure
        # Flush Responses for Next Request
        PWN::Plugins::Serial.flush_session_data
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.wait_for_swipe(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.wait_for_swipe(opts = {})
        msr206_obj = opts[:msr206_obj]
        type = opts[:type].to_s.scrub.strip.chomp.to_sym
        types_arr = %i[
          arm_to_read
          arm_to_read_w_speed_prompts
          arm_to_write_no_raw
          arm_to_write_with_raw
          arm_to_write_with_raw_speed_prompts
        ]

        raise "ERROR Unsupported type in #wait_for_swipe - #{type}. Valid types:\n#{types_arr}" unless types_arr.include?(type)

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :red_off
        )

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :yellow_off
        )

        exec_resp = PWN::Plugins::MSR206.exec(
          msr206_obj: msr206_obj,
          cmd: type
        )

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :green_on
        )

        exec_resp = PWN::Plugins::MSR206.exec(
          msr206_obj: msr206_obj,
          cmd: :card_edge_detect
        )

        print 'Ready.  Please Swipe Card Now:'
        loop do
          exec_resp = parse_responses(
            msr206_obj: msr206_obj,
            cmd: :card_edge_detect
          )

          break if exec_resp[:msg] == :ack_command_completed
        end

        puts "*** ISO Track Format: Standard #{'*' * 17}"
        print 'TRACK 1 >>> '
        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :tx_iso_std_data_track1,
          params: [0x31]
        )
        puts exec_resp[:decoded]
        puts exec_resp.inspect

        # print ">> Track 1 (ALT DATA)\n"
        # exec_resp = exec(
        #   msr206_obj: msr206_obj,
        #   cmd: :alt_tx_iso_std_data_track1,
        #   params: [0x31]
        # )
        # puts exec_resp.inspect

        print "\nTRACK 2 >>> "
        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :tx_iso_std_data_track2,
          params: [0x32]
        )
        puts exec_resp[:decoded]
        puts exec_resp.inspect

        # print ">> Track 2 (ALT DATA)\n"
        # exec_resp = exec(
        #   msr206_obj: msr206_obj,
        #   cmd: :alt_tx_iso_std_data_track2,
        #   params: [0x32]
        # )
        # puts exec_resp.inspect

        print "\nTRACK 3 >>> "
        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :tx_iso_std_data_track3,
          params: [0x33]
        )
        puts exec_resp[:decoded]
        puts exec_resp.inspect

        # print ">> Track 3 (ALT DATA)\n"
        # exec_resp = exec(
        #   msr206_obj: msr206_obj,
        #   cmd: :alt_tx_iso_std_data_track3,
        #   params: [0x33]
        # )
        # puts exec_resp.inspect
      rescue StandardError => e
        raise e
      ensure
        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :green_off
        )
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.disconnect(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        PWN::Plugins::Serial.disconnect(
          serial_obj: opts[:msr206_obj]
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
          msr206_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 9600)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none),'
            flow_control: 'optional - :none||:hard||:soft (defaults to :none)'
          )

          cmds = #{self}.list_cmds

          parsed_cmd_resp_arr = #{self}.exec(
            msr206_obj: 'required msr206_obj returned from #connect method',
            cmd: 'required - cmd returned from #list_cmds method',
            params: 'optional - parameters for specific command returned from #list_params method'
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
