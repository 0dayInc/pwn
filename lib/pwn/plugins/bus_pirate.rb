# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin is used for interacting with Bus Pirate v3.6
    # This plugin may be compatible with other versions, however,
    # has not been tested with anything other than v3.6.
    module BusPirate
      # Supported Method Parameters::
      # PWN::Plugins::BusPirate.connect_via_screen(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)'
      # )

      public_class_method def self.connect_via_screen(opts = {})
        block_dev = opts[:block_dev].to_s if File.exist?(
          opts[:block_dev].to_s
        )

        block_dev ||= '/dev/ttyUSB0'

        screen_bin = '/usr/bin/screen'
        raise "ERROR: #{screen_bin} not found." unless File.exist?(screen_bin)

        system(
          screen_bin,
          block_dev,
          '115200',
          '8',
          'N',
          '1'
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # bus_pirate_obj = PWN::Plugins::BusPirate.connect(
      #   block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
      #   baud: 'optional (defaults to 9600)',
      #   data_bits: 'optional (defaults to 8)',
      #   stop_bits: 'optional (defaults to 1)',
      #   parity: 'optional (defaults to SerialPort::NONE)',
      #   flow_control: 'optional (defaults to SerialPort::HARD) SerialPort::NONE|SerialPort::SOFT|SerialPort::HARD'
      # )

      public_class_method def self.connect(opts = {})
        PWN::Plugins::Serial.connect(opts)
      rescue StandardError => e
        disconnect(bus_pirate_obj: bus_pirate_obj) unless bus_pirate_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      #  PWN::Plugins::BusPirate.init_mode(
      #   bus_pirate_obj: 'required - bus_pirate_obj returned from #connect method'
      #   mode: 'required - bus pirate mode to invoke'
      # )
      public_class_method def self.init_mode(opts = {})
        bus_pirate_obj = opts[:bus_pirate_obj]
        mode = opts[:mode].to_s.strip.chomp.scrub.upcase

        case mode
        when 'BBI01'
          # Enter reset binary mode
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x00])
        when 'SPI1'
          # Enter binary SPI mode
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x01])
        when 'I2C1'
          # Enter I2C mode
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x02])
        when 'ART1'
          # Enter UART mode
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x03])
        when '1W01'
          # Enter 1-Wire mode
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x04])
        when 'RAW1'
          # Enter raw-wire mode
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x05])
        when 'RESET'
          # Reset Bus Pirate
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x0F])
        when 'STEST'
          # Bus Pirate self-tests
          PWN::Plugins::Serial.request(serial_obj: bus_pirate_obj, payload: [0x10])
        else
          raise "Invalid mode: #{mode}"
        end

        PWN::Plugins::Serial.response(serial_obj: bus_pirate_obj)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BusPirate.disconnect(
      #   bus_pirate_obj: 'required - bus_pirate_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        PWN::Plugins::Serial.disconnect(
          serial_obj: opts[:bus_pirate_obj]
        )
      rescue StandardError => e
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
          #{self}.connect_via_screen(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)'
          )

          bus_pirate_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 9600)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional - :even||:odd|:none (defaults to :none)'
          )

          #{self}.init_mode(
            bus_pirate_obj: 'required - bus_pirate_obj returned from #connect method'
            mode: 'required - bus pirate mode to invoke'
          )

          #{self}.disconnect(
            bus_pirate_obj: 'required - bus_pirate_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
