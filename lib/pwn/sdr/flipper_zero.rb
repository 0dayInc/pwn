# frozen_string_literal: true

module PWN
  module SDR
    # This plugin is used for interacting with Bus Pirate v3.6
    # This plugin may be compatible with other versions, however,
    # has not been tested with anything other than v3.6.
    module FlipperZero
      # Supported Method Parameters::
      # PWN::SDR::FlipperZero.connect_via_screen(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyACM0)'
      # )

      public_class_method def self.connect_via_screen(opts = {})
        block_dev = opts[:block_dev].to_s if File.exist?(
          opts[:block_dev].to_s
        )

        block_dev ||= '/dev/ttyACM0'

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
      # flipper_zero_obj = PWN::SDR::FlipperZero.connect(
      #   block_dev: 'optional serial block device path (defaults to /dev/ttyACM0)',
      #   baud: 'optional (defaults to 9600)',
      #   data_bits: 'optional (defaults to 8)',
      #   stop_bits: 'optional (defaults to 1)',
      #   parity: 'optional - :even||:odd|:none (defaults to :none)'
      # )

      public_class_method def self.connect(opts = {})
        PWN::Plugins::Serial.connect(opts)
      rescue StandardError => e
        disconnect(flipper_zero_obj: opts[:flipper_zero_obj]) unless opts[:flipper_zero_obj].nil?
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::SDR::FlipperZero.request(
      #   flipper_zero_obj: 'required - flipper_zero_obj returned from #connect method',
      #   payload: 'optional - payload to send to the device (defaults to help)'
      # )
      public_class_method def self.request(opts = {})
        serial_obj = opts[:flipper_zero_obj]
        payload = opts[:payload] ||= 'help'
        payload = "#{payload}\r\n"

        PWN::Plugins::Serial.request(
          serial_obj: serial_obj,
          payload: payload
        )
        sleep 0.1
        response = PWN::Plugins::Serial.dump_session_data.clone
        puts response.join
        PWN::Plugins::Serial.flush_session_data

        response
      rescue StandardError => e
        disconnect(flipper_zero_obj: opts[:flipper_zero_obj]) unless opts[:flipper_zero_obj].nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::SDR::FlipperZero.disconnect(
      #   flipper_zero_obj: 'required - flipper_zero_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        PWN::Plugins::Serial.disconnect(
          serial_obj: opts[:flipper_zero_obj]
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

          flipper_zero_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 9600)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional - :even||:odd|:none (defaults to :none)'
          )

          response = #{self}.request(
            flipper_zero_obj: 'required - flipper_zero_obj returned from #connect method',
            payload: 'required - payload to send to the device'
          );

          #{self}.disconnect(
            flipper_zero_obj: 'required - flipper_zero_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
