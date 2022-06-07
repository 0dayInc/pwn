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
      #   flow_control: 'optional - :none|:hard|:soft (defaults to :soft)'
      # )

      public_class_method def self.connect(opts = {})
        # Default Baud Rate for this Device is 19200
        opts[:block_dev] = '/dev/ttyUSB0' unless opts[:block_dev]
        opts[:baud] = 9_600 unless opts[:baud]
        opts[:data_bits] = 8 unless opts[:data_bits]
        opts[:stop_bits] = 1 unless opts[:stop_bits]
        opts[:parity] = :none unless opts[:parity]
        opts[:flow_control] = :soft unless opts[:flow_control]
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
            # TODO: Different case statements for each parity
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

        keep_parsing_responses = true
        next_response_detected = false
        response = {}
        response[:cmd] = cmd
        response[:cmd] ||= :na

        if cmd_bytes.instance_of?(Array)
          response[:cmd_bytes] = opts[:cmd_bytes].map do |base10_int|
            "0x#{base10_int.to_s(16).rjust(2, '0')}"
          end
        end
        response[:cmd_bytes] ||= :na

        raw_byte_arr = []
        raw_byte_arr_len = 0
        last_raw_byte_arr_len = 0

        parsed_cmd_resp_arr = []
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
        params = opts[:params]
        raise 'ERROR: params argument must be a byte array (e.g. [0x41]).' if params && !params.instance_of?(Array)

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
          raise "Unsupported Command: #{cmd}.  Supported commands are:\n#{list_cmds}\n\n\n"
        end

        # If parameters to a command are set, append them.
        cmd_bytes += params if params
        # Execute the command.
        PWN::Plugins::Serial.request(
          serial_obj: msr206_obj,
          payload: cmd_bytes
        )

        # Parse commands response(s).
        # Return an array of hashes.
        parse_responses(
          msr206_obj: msr206_obj,
          cmd: cmd.to_sym,
          cmd_bytes: cmd_bytes
        )
      rescue StandardError => e
        raise e
      ensure
        # Flush Responses for Next Request
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

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :red_off
        )

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :yellow_off
        )

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :green_on
        )

        track_data_arr = []

        case type
        when :arm_to_read,
             :arm_to_read_w_speed_prompts

          exec_resp = PWN::Plugins::MSR206.exec(
            msr206_obj: msr206_obj,
            cmd: type
          )
          puts exec_resp.inspect

          print 'Ready to Read.  Please Swipe Card Now:'
          loop do
            exec_resp = parse_responses(
              msr206_obj: msr206_obj,
              cmd: type
            )

            puts exec_resp[:msg]
            break if exec_resp[:msg] == :ack_command_completed
          end

          if encoding == :iso
            cmds_arr = %i[
              tx_iso_std_data_track1
              tx_iso_std_data_track2
              tx_iso_std_data_track3
            ]
            cmds_arr.each do |cmd|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              exec_resp = exec(
                msr206_obj: msr206_obj,
                cmd: cmd
              )
              exec_resp[:encoding] = encoding
              puts exec_resp[:decoded]
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          end

          if encoding == :iso_alt
            cmds_arr = %i[
              alt_tx_iso_std_data_track1
              alt_tx_iso_std_data_track2
              alt_tx_iso_std_data_track3
            ]

            cmds_arr.each do |cmd|
              params_arr = [0x31, 0x32, 0x33]
              params_arr.each do |param|
                puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
                exec_resp = exec(
                  msr206_obj: msr206_obj,
                  cmd: cmd,
                  params: [param]
                )
                exec_resp[:encoding] = encoding
                exec_resp[:track_format] = [param]
                puts exec_resp[:decoded]
                puts exec_resp.inspect
                track_data_arr.push(exec_resp)
              end
            end
          end

          if encoding == :raw
            cmds_arr = %i[
              tx_custom_data_forward_track1
              tx_custom_data_forward_track2
              tx_custom_data_forward_track3
            ]

            cmds_arr.each do |cmd|
              params_arr = [0x33, 0x34, 0x35, 0x36, 0x37]
              params_arr.each do |param|
                puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
                # 2 byte command
                exec_resp = exec(
                  msr206_obj: msr206_obj,
                  cmd: cmd,
                  params: [param]
                )
                exec_resp[:encoding] = encoding
                exec_resp[:track_format] = [param]
                puts exec_resp[:decoded]
                puts exec_resp.inspect
                track_data_arr.push(exec_resp)

                # 3 byte command
                param = [0x5f] + [param]
                exec_resp = exec(
                  msr206_obj: msr206_obj,
                  cmd: cmd,
                  params: param
                )
                exec_resp[:encoding] = encoding
                exec_resp[:track_format] = param
                puts exec_resp[:decoded]
                puts exec_resp.inspect
                track_data_arr.push(exec_resp)
              end
            end
          end
        when :arm_to_write_no_raw,
             :arm_to_write_with_raw,
             :arm_to_write_with_raw_speed_prompts

          # TODO: Set Write Density for Tracks Here
          # >>>

          if encoding == :iso
            cmds_arr = %i[
              load_iso_std_data_for_writing_track1
              load_iso_std_data_for_writing_track2
              load_iso_std_data_for_writing_track3
            ]

            # TODO: Get Data by cmd (e.g. load_iso_std_data_for_writing_track1)
            cmds_arr.each_with_index do |cmd, track|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              puts track_data[track][:decoded]
              next if track_data[track][:decoded] == '+'

              this_track = track_data[track][:decoded].chars.map do |c|
                c.unpack1('H*').to_i(16)
              end
              track_eot = [0x04]
              track_payload = this_track + track_eot
              puts track_payload.inspect
              exec_resp = exec(
                msr206_obj: msr206_obj,
                cmd: cmd,
                params: track_payload
              )
              exec_resp[:encoding] = encoding
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          end

          if encoding == :iso_alt
            cmds_arr = %i[
              alt_load_iso_std_data_for_writing_track1
              alt_load_iso_std_data_for_writing_track2
              alt_load_iso_std_data_for_writing_track3
            ]

            # TODO: Get Data by cmd (e.g. alt_load_iso_std_data_for_writing_track1)
            cmds_arr.each_with_index do |cmd, track|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              puts track_data[track][:decoded]
              next if track_data[track][:decoded] == '+'

              this_track = track_data[track][:decoded].chars.map do |c|
                c.unpack1('H*').to_i(16)
              end
              track_format = track_data[track][:track_format]
              track_eot = [0x04]
              track_payload = track_format + this_track + track_eot
              puts track_payload.inspect
              exec_resp = exec(
                msr206_obj: msr206_obj,
                cmd: cmd,
                params: track_payload
              )
              exec_resp[:encoding] = encoding
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          end

          if encoding == :raw
            cmds_arr = %i[
              load_custom_data_for_writing_track1
              load_custom_data_for_writing_track2
              load_custom_data_for_writing_track3
            ]

            # TODO: Get Data by cmd (e.g. load_custom_data_for_writing_track1)
            cmds_arr.each_with_index do |cmd, track|
              puts "\n*** #{cmd.to_s.gsub('_', ' ').upcase} #{'*' * 17}"
              puts track_data[track][:decoded]
              next if track_data[track][:decoded] == '+'

              this_track = track_data[track][:decoded].chars.map do |c|
                c.unpack1('H*').to_i(16)
              end
              track_format = track_data[track][:track_format]
              track_eot = [0x04]
              track_payload = track_format + this_track + track_eot
              puts track_payload.inspect
              exec_resp = exec(
                msr206_obj: msr206_obj,
                cmd: cmd,
                params: track_payload
              )
              exec_resp[:encoding] = encoding
              puts exec_resp.inspect
              track_data_arr.push(exec_resp)
            end
          end

          exec_resp = PWN::Plugins::MSR206.exec(
            msr206_obj: msr206_obj,
            cmd: type
          )
          puts exec_resp.inspect

          print 'Ready to Write.  Please Swipe Card Now:'
          loop do
            exec_resp = parse_responses(
              msr206_obj: msr206_obj,
              cmd: type
            )

            break if exec_resp[:msg] == :ack_command_completed
          end
        else
          raise "ERROR Unsupported type in #wait_for_swipe - #{type}"
        end

        track_data_arr
      rescue StandardError => e
        raise e
      ensure
        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :green_off
        )
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.read_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.read_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        type = opts[:type].to_s.scrub.strip.chomp.to_sym

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

        wait_for_swipe(
          msr206_obj: msr206_obj,
          type: :arm_to_read,
          encoding: encoding
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.backup_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.backup_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        type = opts[:type].to_s.scrub.strip.chomp.to_sym

        # Read Card to Backup
        track_data = read_card(
          msr206_obj: msr206_obj
        )

        file = ''
        backup_msg = ''
        loop do
          if backup_msg.empty?
            exec_resp = exec(
              msr206_obj: msr206_obj,
              cmd: :green_flash
            )
          end

          print 'Enter File Name to Save Backup: '
          file = gets.scrub.chomp.strip
          file_dir = File.dirname(file)
          break if Dir.exist?(file_dir)

          backup_msg = "\n****** ERROR: Directory #{file_dir} for #{file} does not exist ******"
          puts backup_msg
          exec_resp = exec(
            msr206_obj: msr206_obj,
            cmd: :green_off
          )
          exec_resp = exec(
            msr206_obj: msr206_obj,
            cmd: :yellow_flash
          )
        end

        File.write(file, "#{JSON.pretty_generate(track_data)}\n")
        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :yellow_off
        )

        track_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.write_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method',
      #   encoding: 'required - :iso || :alt_iso || :raw',
      #   track_data: 'requred - track data to write (see #backup_card for structure)'
      # )

      public_class_method def self.write_card(opts = {})
        msr206_obj = opts[:msr206_obj]
        encoding = opts[:encoding].to_s.scrub.strip.chomp.to_sym
        track_data = opts[:track_data]

        puts 'IN ORDER TO GET BLANK TRACKS, A STRONG MAGNETIC FIELD MUST BE PRESENT TO FIRST WIPE THE CARD TARGETED FOR WRITING.'
        # puts 'Default Write Current:'
        # exec_resp = exec(
        #   msr206_obj: msr206_obj,
        #   cmd: :view_default_write_current
        # )
        # puts exec_resp.inspect

        # puts 'Temporary Write Current:'
        # exec_resp = exec(
        #   msr206_obj: msr206_obj,
        #   cmd: :view_temp_write_current
        # )
        # puts exec_resp.inspect

        coercivity = :waiting_for_selection
        loop do
          puts "\nCOERCIVITY OPTIONS:"
          puts '[(H)igh (Black Stripe)]'
          puts '[(L)ow (Brown Stripe)]'
          print 'COERCIVITY LEVEL >>> '
          coercivity_choice = gets.scrub.chomp.strip.upcase.to_sym

          # Write Current Settings vs. Media Coercivties
          # Media Coercivity (Oersteds)|Write Current Setting*|Typical Usage
          # 300                        |36                    |Low coercivity
          # 600                        |                      |
          # 1800                       |                      |
          # 3600+                      |255                   |Typical high corcivity

          case coercivity_choice
          when :H
            coercivity = [0x32, 0x35, 0x35]
            break
          when :L
            coercivity = [0x30, 0x33, 0x36]
            break
          end
        end

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :set_temp_write_current,
          params: coercivity
        )

        track_data = wait_for_swipe(
          msr206_obj: msr206_obj,
          type: :arm_to_write_no_raw,
          encoding: encoding,
          track_data: track_data
        )

        exec_resp = PWN::Plugins::MSR206.exec(
          msr206_obj: msr206_obj,
          cmd: :simulate_power_cycle_warm_reset
        )

        track_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.copy_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.copy_card(opts = {})
        msr206_obj = opts[:msr206_obj]

        # Read Card to Backup
        track_data = backup_card(
          msr206_obj: msr206_obj
        )

        encoding = track_data.first[:encoding] if track_data.length == 3
        # TODO: Save Original Card Contents
        write_card(
          msr206_obj: msr206_obj,
          encoding: encoding,
          track_data: track_data
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.load_card_from_file(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.load_card_from_file(opts = {})
        msr206_obj = opts[:msr206_obj]

        file = ''
        restore_msg = ''
        loop do
          if restore_msg.empty?
            exec_resp = exec(
              msr206_obj: msr206_obj,
              cmd: :green_flash
            )
          end

          print 'Enter File Name to Restore to Card: '
          file = gets.scrub.chomp.strip
          break if File.exist?(file)

          restore_msg = "\n****** ERROR: #{file} does not exist ******"
          puts restore_msg
          exec_resp = exec(
            msr206_obj: msr206_obj,
            cmd: :green_off
          )
          exec_resp = exec(
            msr206_obj: msr206_obj,
            cmd: :yellow_flash
          )
        end

        track_data = JSON.parse(
          File.read(file),
          symbolize_names: true
        )

        exec_resp = exec(
          msr206_obj: msr206_obj,
          cmd: :yellow_off
        )

        # Read Card from Backup
        encoding = track_data.first[:encoding] if track_data.length == 3

        # TODO: Save Original Card Contents
        write_card(
          msr206_obj: msr206_obj,
          encoding: encoding,
          track_data: track_data
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.edit_card(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.edit_card(opts = {})
        msr206_obj = opts[:msr206_obj]

        # Read Card to Backup
        track_data = backup_card(
          msr206_obj: msr206_obj
        )

        # TODO: Inline Editing

        encoding = track_data.first[:encoding] if track_data.length == 3
        # TODO: Save Original Card Contents
        write_card(
          msr206_obj: msr206_obj,
          encoding: encoding,
          track_data: track_data
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::MSR206.get_config(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.get_config(opts = {})
        msr206_obj = opts[:msr206_obj]

        # --------------------------------------------------
        # Bit|Bit = 0                  |Bit = 1
        # --------------------------------------------------
        # 0  |Track 1 Read not present |Track 1 Read present
        # 1  |Track 2 Read not present |Track 2 Read present
        # 2  |Track 3 Read not present |Track 3 Read present
        # 3  |not used – should be 0   |not used
        # 4  |Track 3 Write not present|Track 3 Write present
        # 5  |Track 2 Write not present|Track 2 Write present
        # 6  |Track 1 Write not present|Track 1 Write present
        # 7  |parity bit**             |parity bit**
        exec_resp = PWN::Plugins::MSR206.exec(
          msr206_obj: msr206_obj,
          cmd: :configuration_request
        )

        config_arr = exec_resp[:binary].first.reverse.chars
        config_hash = {}
        config_arr.each_with_index do |bit_str, i|
          bit = bit_str.to_i
          config_hash[:track1_read] = false if bit.zero? && i.zero?
          config_hash[:track1_read] = true if bit == 1 && i.zero?

          config_hash[:track2_read] = false if bit.zero? && i == 1
          config_hash[:track2_read] = true if bit == 1 && i == 1

          config_hash[:track3_read] = false if bit.zero? && i == 2
          config_hash[:track3_read] = true if bit == 1 && i == 2

          config_hash[:not_used] if i == 3

          config_hash[:track1_write] = false if bit.zero? && i == 4
          config_hash[:track1_write] = true if bit == 1 && i == 4

          config_hash[:track2_write] = false if bit.zero? && i == 5
          config_hash[:track2_write] = true if bit == 1 && i == 5

          config_hash[:track3_write] = false if bit.zero? && i == 6
          config_hash[:track3_write] = true if bit == 1 && i == 6

          config_hash[:parity] = true if bit == 1 && i == 7
        end

        config_hash
      rescue StandardError => e
        raise e
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
            flow_control: 'optional - :none|:hard|:soft (defaults to :none)'
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
