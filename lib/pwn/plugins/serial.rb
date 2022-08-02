# frozen_string_literal: true

require 'serialport'
require 'io/wait'

module PWN
  module Plugins
    # This plugin is used for interacting with serial devices including, but not limited to,
    # modems (including cellphone radios), legacy equipment, arduinos, & other misc ftdi devices
    module Serial
      @session_data = []

      # Supported Method Parameters::
      # serial_obj = PWN::Plugins::Serial.connect(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)',
      #   baud: 'optional - (defaults to 9600)',
      #   data_bits: 'optional - (defaults to 8)',
      #   stop_bits: 'optional - (defaults to 1)',
      #   parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none)',
      #   flow_control: 'optional - :none||:hard||:soft (defaults to :none)'
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

        case opts[:parity].to_s.to_sym
        when :even
          parity = SerialPort::EVEN
        when :mark
          parity = SerialPort::MARK
        when :odd
          parity = SerialPort::ODD
        when :space
          parity = SerialPort::SPACE
        else
          parity = SerialPort::NONE
        end

        case opts[:flow_control].to_s.to_sym
        when :hard
          flow_control = SerialPort::HARD
        when :soft
          flow_control = SerialPort::SOFT
        else
          flow_control = SerialPort::NONE
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
      #   payload: 'required - array of bytes OR string to write to serial device (e.g. [0x00, 0x41, 0x90, 0x00] OR "ATDT+15555555\r\n"'
      # )

      public_class_method def self.request(opts = {})
        serial_obj = opts[:serial_obj]
        payload = opts[:payload]
        serial_conn = serial_obj[:serial_conn]

        byte_arr = payload
        byte_arr = payload.chars if payload.instance_of?(String)

        byte_arr.each do |byte|
          serial_conn.putc(byte)
        end

        serial_conn.flush
      rescue StandardError => e
        disconnect(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # public_class_method def self.request(opts = {})
      #   serial_obj = opts[:serial_obj]
      #   request = opts[:request].to_s.scrub
      #   serial_conn = serial_obj[:serial_conn]
      #   chars_written = serial_conn.write(request)
      #   serial_conn.flush
      #   chars_written
      # rescue StandardError => e
      #   disconnect(serial_obj: serial_obj) unless serial_obj.nil?
      #   raise e
      # end

      # Supported Method Parameters::
      # PWN::Plugins::Serial.response(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.response(opts = {})
        serial_obj = opts[:serial_obj]

        raw_byte_arr = dump_session_data

        hex_esc_raw_resp = ''
        raw_byte_arr.each do |byte|
          # this_byte = "\s#{byte.unpack1('H*')}"
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
        flush_session_data

        raise e
      end

      # public_class_method def self.response(opts = {})
      #   serial_obj = opts[:serial_obj]
      #   @session_data.last
      # rescue StandardError => e
      #   disconnect(serial_obj: serial_obj) unless serial_obj.nil?
      #   raise e
      # end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::Serial.dump_session_data

      public_class_method def self.dump_session_data
        @session_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::Serial.flush_session_data

      public_class_method def self.flush_session_data
        @session_data.clear
      rescue StandardError => e
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
        flush_session_data
        session_thread.terminate
        serial_conn.close
        serial_conn = nil
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
          serial_obj = #{self}.connect(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional (defaults to 9600)',
            data_bits: 'optional (defaults to 8)',
            stop_bits: 'optional (defaults to 1)',
            parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none)',
            flow_control: 'optional - :none||:hard||:soft (defaults to :none)'
          )

          line_state = #{self}.get_line_state(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          modem_params = #{self}.get_modem_params(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          #{self}.request(
            serial_obj: 'required serial_obj returned from #connect method',
            payload: 'required - array of bytes OR string to write to serial device (e.g. [0x00, 0x41, 0x90, 0x00] OR \"ATDT+15555555\r\n\"'
          )

          #{self}.response(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          session_data_arr = #{self}.dump_session_data

          #{self}.flush_session_data

          #{self}.disconnect(
            serial_obj: 'required serial_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
