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
          set_write_density_210_bpi_tracks_1_3
          set_write_density_75_bpi_tracks_1_3
          set_write_density_210_bpi_tracks_2
          set_write_density_75_bpi_tracks_2
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
        when :version_report
          cmd_bytes = [0x39]
        when :simulate_power_cycle_warm_reset
          cmd_bytes = [0x7F]
        when :configuration_request
          cmd_bytes = [0x23]
        when :reproduce_last_command
          cmd_bytes = [0x25]
        when :resume_transmission_to_host
          cmd_bytes = [0x11]
        when :pause_transmission_to_host
          cmd_bytes = [0x13]
        when :abort_command
          cmd_bytes = [0x1B]
        when :red_on
          cmd_bytes = [0x4D]
        when :red_off
          cmd_bytes = [0x6D]
        when :red_flash
          cmd_bytes = [0x29]
        when :green_on
          cmd_bytes = [0x4C]
        when :green_off
          cmd_bytes = [0x6C]
        when :green_flash
          cmd_bytes = [0x28]
        when :yellow_on
          cmd_bytes = [0x4B]
        when :yellow_off
          cmd_bytes = [0x6B]
        when :yellow_flash
          cmd_bytes = [0x7C]
        when :arm_to_read
          cmd_bytes = [0x50]
        when :arm_to_read_w_speed_prompts
          cmd_bytes = [0x70]
        when :tx_iso_std_data_track1
          cmd_bytes = [0x51]
        when :tx_iso_std_data_track2
          cmd_bytes = [0x52]
        when :tx_iso_std_data_track3
          cmd_bytes = [0x53]
        when :tx_error_data
          cmd_bytes = [0x49]
        when :tx_custom_data_forward_track1
          cmd_bytes = [0x45]
        when :tx_custom_data_forward_track2
          cmd_bytes = [0x46]
        when :tx_custom_data_forward_track3
          cmd_bytes = [0x47]
        when :tx_passbook_data
          cmd_bytes = [0x58]
        when :alt_tx_passbook_data
          cmd_bytes = [0x78]
        when :write_verify
          cmd_bytes = [0x3F]
        when :card_edge_detect
          cmd_bytes = [0x26]
        when :load_iso_std_data_for_writing_track1
          cmd_bytes = [0x41]
        when :load_iso_std_data_for_writing_track2
          cmd_bytes = [0x42]
        when :load_iso_std_data_for_writing_track3
          cmd_bytes = [0x43]
        when :alt_load_iso_std_data_for_writing_track1
          cmd_bytes = [0x61]
        when :alt_load_iso_std_data_for_writing_track2
          cmd_bytes = [0x62]
        when :alt_load_iso_std_data_for_writing_track3
          cmd_bytes = [0x63]
        when :load_passbook_data_for_writing
          cmd_bytes = [0x6A]
        when :load_custom_data_for_writing_track1
          cmd_bytes = [0x45]
        when :load_custom_data_for_writing_track2
          cmd_bytes = [0x46]
        when :load_custom_data_for_writing_track3
          cmd_bytes = [0x47]
        when :set_write_density
          cmd_bytes = [0x3B]
        when :set_write_density_210_bpi_tracks_1_3
          cmd_bytes = [0x4F]
        when :set_write_density_75_bpi_tracks_1_3
          cmd_bytes = [0x6F]
        when :set_write_density_210_bpi_tracks_2
          cmd_bytes = [0x4E]
        when :set_write_density_75_bpi_tracks_2
          cmd_bytes = [0x6E]
        when :set_default_write_current
          cmd_bytes = [0x5B]
        when :view_default_write_current
          cmd_bytes = [0x5D]
        when :set_temp_write_current
          cmd_bytes = [0x3C]
        when :view_temp_write_current
          cmd_bytes = [0x3E]
        when :arm_to_write_with_raw
          cmd_bytes = [0x40]
        when :arm_to_write_no_raw
          cmd_bytes = [0x5A]
        when :arm_to_write_with_raw_speed_prompts
          cmd_bytes = [0x7A]
        else
          raise "Unsupported Command: #{cmd}.  Supported commands are:\n#{list_cmds}\n\n\n"
        end

        # If parameters to a command are set, append them.
        cmd_bytes += params_bytes unless params_bytes.empty?
        # Execute the command.
        cmd_bytes.each do |byte|
          son_micro_rfid_obj[:serial_conn].putc(byte)
        end

        # Parse commands response(s).
        # Return an array of hashes.
        parse_responses(
          son_micro_rfid_obj: son_micro_rfid_obj,
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
