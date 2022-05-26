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
      #   parity: 'optional - (defaults to SerialPort::NONE)',
      #   flow_control: 'optional - (defaults to SerialPort::HARD) SerialPort::NONE|SerialPort::SOFT|SerialPort::HARD'
      # )

      public_class_method def self.connect(opts = {})
        # Default Baud Rate for this Device is 19200
        opts[:baud] = 19_200 if opts[:baud].nil?
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
      # cmd_response_arr = get_cmd_responses(
      #   msr206_obj: 'required - msr206_obj returned from #connect method'
      # )

      public_class_method def self.get_cmd_responses(opts = {})
        msr206_obj = opts[:msr206_obj]

        raw_byte_arr = PWN::Plugins::Serial.dump_session_data(
          serial_obj: msr206_obj
        )

        hex_esc_raw_resp = ''
        raw_byte_arr.each do |byte|
          this_byte = byte.unpack1('H*')
          # Needed when #unpack1 returns 2 bytes instead of one
          # e.g."ް" translates to deb0 (that's not a double quote ")
          # instead of de b0
          # this condition is ghetto-hacker-ish.
          if this_byte.length == 4
            byte_one = this_byte[1..2]
            byte_two = this_byte[-2..-1]
            hex_esc_raw_resp = "#{hex_esc_raw_resp}\s#{byte_one}"
            hex_esc_raw_resp = "#{hex_esc_raw_resp}\s#{byte_two}"
          else
            hex_esc_raw_resp = "#{hex_esc_raw_resp}\s#{this_byte}"
          end
        end

        # Return command response array in space-delimited hex
        cmd_response_arr = hex_esc_raw_resp.upcase.strip.split(/(?=FF)/)
        cmd_response_arr.map(&:strip)
      rescue StandardError => e
        # Flush Responses for Next Request
        PWN::Plugins::Serial.flush_session_data(
          serial_obj: msr206_obj
        )

        raise e
      end

      # Supported Method Parameters::
      # parsed_cmd_resp_arr = parse_responses(
      #   cmd_resp: 'required - command response string'
      # )

      private_class_method def self.parse_responses(opts = {})
        msr206_obj = opts[:msr206_obj]
        cmd = opts[:cmd].to_s.scrub.strip.chomp

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
            all_cmd_responses = get_cmd_responses(
              msr206_obj: msr206_obj
            )
            # bytes_in_cmd_resp = cmd_resp.split.length if cmd_resp
            a_cmd_r_len = all_cmd_responses.length

            next_response_detected = true if a_cmd_r_len > last_a_cmd_r_len
          end

          #   cmd_resp = all_cmd_responses.last
          #   case cmd_resp
          #   when '21', '28', '29', '2A', '2B', '2D', '2F', '3A', '31', '32', '33', '3E', '3F', '5E', '7E', '98 FE'
          #     next_response_detected = true
          #   end
          next_response_detected = false
          last_a_cmd_r_len = a_cmd_r_len
          print "\n"
          keep_parsing_responses = false
        end

        all_cmd_responses
      rescue StandardError => e
        raise e
      ensure
        # Flush Responses for Next Request
        PWN::Plugins::Serial.flush_session_data(
          serial_obj: msr206_obj
        )
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
        when :power_on_report
          cmd_bytes = [0x3A]
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
        cmd_bytes.each do |byte|
          msr206_obj[:serial_conn].putc(byte)
        end

        # Parse commands response(s).
        # Return an array of hashes.
        parse_responses(
          msr206_obj: msr206_obj,
          cmd: cmd.to_sym
        )
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
            parity: 'optional (defaults to SerialPort::NONE)',
            flow_control: 'optional (defaults to SerialPort::NONE)'
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
