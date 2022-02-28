# frozen_string_literal: true

require 'serialport'

module PWN
  module Plugins
    # This plugin is used for interacting with serial devices including, but not limited to,
    # modems (including cellphone radios), legacy equipment, arduinos, & other misc ftdi devices
    module Serial
      # @session_data = ""
      @session_data = []

      # Supported Method Parameters::
      # serial_obj = PWN::Plugins::Serial.connect(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)',
      #   baud: 'optional - (defaults to 9600)',
      #   data_bits: 'optional - (defaults to 8)',
      #   stop_bits: 'optional - (defaults to 1)',
      #   parity: 'optional - (defaults to SerialPort::NONE)',
      #   flow_control: 'optional - (defaults to SerialPort::HARD) SerialPort::NONE|SerialPort::SOFT|SerialPort::HARD'
      # )

      public_class_method def self.connect(opts = {})
        block_dev = opts[:block_dev].to_s if File.exist?(
          opts[:block_dev].to_s
        )
        block_dev = '/dev/ttyUSB0' if opts[:block_dev].nil?

        baud = if opts[:baud].nil?
                 9_600
               else
                 opts[:baud].to_i
               end

        data_bits = if opts[:data_bits].nil?
                      8
                    else
                      opts[:data_bits].to_i
                    end

        stop_bits = if opts[:stop_bits].nil?
                      1
                    else
                      opts[:stop_bits].to_i
                    end

        parity = if opts[:parity].nil?
                   SerialPort::NONE
                 else
                   opts[:parity]
                 end

        flow_control = if opts[:flow_control].nil?
                         SerialPort::HARD
                       else
                         opts[:flow_control]
                       end

        serial_conn = SerialPort.new(
          block_dev,
          baud,
          data_bits,
          stop_bits,
          parity,
          flow_control
        )

        serial_obj = {}
        serial_obj[:serial_conn] = serial_conn
        serial_obj[:session_thread] = init_session_thread(
          serial_conn: serial_conn
        )

        serial_obj
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # session_thread = init_session_thread(
      #   serial_conn: 'required - SerialPort.new object'
      # )

      private_class_method def self.init_session_thread(opts = {})
        serial_conn = opts[:serial_conn]

        # Spin up a serial_obj session_thread
        Thread.new do
          serial_conn.read_timeout = -1
          serial_conn.flush

          loop do
            serial_conn.wait_readable
            # Read raw chars into @session_data,
            # convert to readable bytes if need-be
            # later.
            @session_data << serial_conn.readchar
          end
        end
      rescue StandardError => e
        session_thread&.terminate
        serial_conn&.close
        serial_conn = nil

        raise e
      end

      # Supported Method Parameters::
      # line_state = PWN::Plugins::Serial.get_line_state(
      #   serial_obj: 'required serial_obj returned from #connect method'
      # )

      public_class_method def self.get_line_state(opts = {})
        serial_obj = opts[:serial_obj]
        serial_conn = serial_obj[:serial_conn]
        serial_conn.get_signals
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # modem_params = PWN::Plugins::Serial.get_modem_params(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.get_modem_params(opts = {})
        serial_obj = opts[:serial_obj]
        serial_conn = serial_obj[:serial_conn]
        serial_conn.get_modem_params
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Serial.request(
      #   serial_obj: 'required serial_obj returned from #connect method',
      #   request: 'required - string to write to serial device'
      # )

      public_class_method def self.request(opts = {})
        serial_obj = opts[:serial_obj]
        request = opts[:request].to_s.scrub
        serial_conn = serial_obj[:serial_conn]
        chars_written = serial_conn.write(request)
        serial_conn.flush
        chars_written
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Serial.response(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.response(opts = {})
        serial_obj = opts[:serial_obj]
        @session_data.last
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::Serial.dump_session_data(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.dump_session_data(opts = {})
        serial_obj = opts[:serial_obj]

        @session_data
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::Serial.flush_session_data(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.flush_session_data(opts = {})
        serial_obj = opts[:serial_obj]

        @session_data.clear
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Serial.disconnect(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        serial_obj = opts[:serial_obj]
        serial_conn = serial_obj[:serial_conn]
        session_thread = serial_obj[:session_thread]
        flush_session_data(serial_obj: serial_obj)
        session_thread.terminate
        serial_conn.close
        serial_conn = nil
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          serial_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 9600)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional (defaults to SerialPort::NONE)',
            flow_control: 'optional (defaults to SerialPort::NONE)'
          )

          line_state = #{self}.get_line_state(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          modem_params = #{self}.get_modem_params(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          #{self}.request(
            serial_obj: 'required serial_obj returned from #connect method',
            request: 'required string to write to serial device'
          )

          #{self}.response(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          session_data_arr = #{self}.dump_session_data(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          #{self}.flush_session_data
            serial_obj: 'required serial_obj returned from #connect method'
          )

          #{self}.disconnect(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
