# frozen_string_literal: true

require 'English'

require 'uart'
require 'io/wait'

module PWN
  module Plugins
    # This plugin is used for interacting with serial devices including, but not limited to,
    # modems (including cellphone radios), legacy equipment, arduinos, & other misc ftdi devices
    module Serial
      @sessions = []
      @sessions_mutex = Mutex.new

      # Supported Method Parameters::
      # serial_obj = PWN::Plugins::Serial.connect(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)',
      #   baud: 'optional - (defaults to 9600)',
      #   data_bits: 'optional - (defaults to 8)',
      #   stop_bits: 'optional - (defaults to 1)',
      #   parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none)'
      # )

      public_class_method def self.connect(opts = {})
        block_dev = opts.fetch(:block_dev, '/dev/ttyUSB0')
        raise ArgumentError, 'Invalid serial block device' unless block_dev.is_a?(String) && !block_dev.empty? && !block_dev.include?("\0") && File.exist?(block_dev)

        baud = opts.fetch(:baud, 9_600)
        data_bits = opts.fetch(:data_bits, 8)
        stop_bits = opts.fetch(:stop_bits, 1)
        parity = opts.fetch(:parity, :none)

        case parity.to_s.to_sym
        when :even
          parity = 'E'
        when :odd
          parity = 'O'
        when :none
          parity = 'N'
        end
        raise "Invalid parity: #{opts[:parity]}" if parity.nil?

        mode = "#{data_bits}#{parity}#{stop_bits}"
        puts mode

        serial_conn = UART.open(
          block_dev,
          baud,
          mode
        )

        serial_obj = { session_data: [], session_mutex: Mutex.new }
        serial_obj[:serial_conn] = serial_conn
        @sessions_mutex.synchronize { @sessions << serial_obj }
        serial_obj[:session_thread] = init_session_thread(
          serial_obj: serial_obj
        )

        handed_off = true
        serial_obj
      ensure
        unless handed_off
          serial_obj ||= { serial_conn: serial_conn } if serial_conn
          cleanup_failed_session(serial_obj: serial_obj) if serial_obj
        end
      end

      # Supported Method Parameters::
      # session_thread = init_session_thread(
      #   serial_conn: 'required - SerialPort.new object'
      # )

      private_class_method def self.init_session_thread(opts = {})
        serial_obj = opts[:serial_obj]
        serial_conn = serial_obj[:serial_conn]

        Thread.new do
          serial_conn.flush

          loop do
            serial_conn.wait_readable
            byte = serial_conn.readchar
            serial_obj[:session_mutex].synchronize { serial_obj[:session_data] << byte }
          end
        rescue StandardError => e
          serial_obj[:session_mutex].synchronize { serial_obj[:session_error] = e }
        end
      end

      # Supported Method Parameters::
      # line_state = PWN::Plugins::Serial.get_line_state(
      #   serial_obj: 'required serial_obj returned from #connect method'
      # )

      public_class_method def self.get_line_state(opts = {})
        serial_obj = opts[:serial_obj]
        serial_conn = serial_obj[:serial_conn]
        # Should return something like:
        # {"rts"=>1, "dtr"=>1, "cts"=>1, "dsr"=>1, "dcd"=>0, "ri"=>0}
        buffer = [0].pack('i')
        serial_conn.ioctl(Termios::TIOCMGET, buffer)
        flags = buffer.unpack1('i')
        { 'rts' => Termios::TIOCM_RTS, 'dtr' => Termios::TIOCM_DTR,
          'cts' => Termios::TIOCM_CTS, 'dsr' => Termios::TIOCM_DSR,
          'dcd' => Termios::TIOCM_CAR, 'ri' => Termios::TIOCM_RNG }.transform_values { |mask| flags.anybits?(mask) ? 1 : 0 }
      rescue StandardError => e
        cleanup_failed_session(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # modem_params = PWN::Plugins::Serial.get_modem_params(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.get_modem_params(opts = {})
        serial_obj = opts[:serial_obj]
        serial_conn = serial_obj[:serial_conn]
        # Should return something like:
        # {"baud"=>9600, "data_bits"=>8, "stop_bits"=>1, "parity"=>0}
        attributes = Termios.tcgetattr(serial_conn)
        baud_name = Termios.constants.find { |name| name.to_s.match?(/\AB[0-9]+\z/) && Termios.const_get(name) == attributes.ospeed }
        raise IOError, 'Unrecognized UART baud rate' unless baud_name

        bits = (5..8).find { |width| (attributes.cflag & Termios::CSIZE) == Termios.const_get("CS#{width}") }
        parity = if attributes.cflag.nobits?(Termios::PARENB)
                   0
                 else
                   attributes.cflag.anybits?(Termios::PARODD) ? 1 : 2
                 end
        { 'baud' => baud_name.to_s.delete_prefix('B').to_i, 'data_bits' => bits,
          'stop_bits' => attributes.cflag.anybits?(Termios::CSTOPB) ? 2 : 1, 'parity' => parity }
      rescue StandardError => e
        cleanup_failed_session(serial_obj: serial_obj) unless serial_obj.nil?
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

        byte_arr = nil
        byte_arr = payload if payload.instance_of?(Array)
        byte_arr = payload.chars if payload.instance_of?(String)
        raise "ERROR: Invalid payload type: #{payload.class}" if byte_arr.nil?

        byte_arr.each do |byte|
          serial_conn.putc(byte)
        end

        sleep(0.1)
        serial_conn.flush
      rescue StandardError => e
        cleanup_failed_session(serial_obj: serial_obj) unless serial_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Serial.response(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.response(opts = {})
        serial_obj = opts[:serial_obj]

        raw_byte_arr = dump_session_data(serial_obj: serial_obj)

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
        flush_session_data(serial_obj: serial_obj) if serial_obj

        raise e
      end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::Serial.dump_session_data

      public_class_method def self.dump_session_data(opts = {})
        serial_obj = session_for_data(serial_obj: opts[:serial_obj])
        return [] unless serial_obj

        serial_obj[:session_mutex].synchronize do
          raise serial_obj[:session_error] if serial_obj[:session_error] && serial_obj[:session_data].empty?

          serial_obj[:session_data].dup
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # session_data = PWN::Plugins::Serial.flush_session_data

      public_class_method def self.flush_session_data(opts = {})
        serial_obj = session_for_data(serial_obj: opts[:serial_obj])
        return [] unless serial_obj

        serial_obj[:session_mutex].synchronize { serial_obj[:session_data].clear }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Serial.disconnect(
      #   serial_obj: 'required - serial_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        primary_error = nil
        serial_obj = opts[:serial_obj]
        return unless serial_obj

        serial_conn = serial_obj[:serial_conn]
        session_thread = serial_obj[:session_thread]
        session_thread&.terminate
        session_thread&.join unless session_thread == Thread.current
        flush_session_data(serial_obj: serial_obj) if serial_obj[:session_mutex]
        nil
      rescue StandardError, Interrupt => e
        primary_error = e
        raise
      ensure
        @sessions_mutex.synchronize { @sessions.delete_if { |session| session.equal?(serial_obj) } }
        begin
          serial_conn.close if serial_conn && !serial_conn.closed?
        rescue StandardError, Interrupt
          raise unless primary_error
        end
      end

      private_class_method def self.cleanup_failed_session(opts = {})
        disconnect(serial_obj: opts[:serial_obj])
      rescue StandardError, Interrupt
        # Invoked only while the caller is already propagating its own failure.
        nil
      end

      private_class_method def self.session_for_data(opts = {})
        return opts[:serial_obj] if opts[:serial_obj]

        @sessions_mutex.synchronize do
          raise ArgumentError, 'serial_obj is required when multiple serial sessions are open' if @sessions.length > 1

          @sessions.first
        end
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
          # Run connect and return its result
          #{self}.connect(
            block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)',
            baud: 'optional - (defaults to 9600)',
            data_bits: 'optional - (defaults to 8)',
            stop_bits: 'optional - (defaults to 1)',
            parity: 'optional - :even|:mark|:odd|:space|:none (defaults to :none)'
          )

          # Run get line state and return its result
          #{self}.get_line_state(
            serial_obj: 'required - required serial_obj returned from #connect method'
          )

          # Run get modem params and return its result
          #{self}.get_modem_params(
            serial_obj: 'required - serial_obj returned from #connect method'
          )

          # Run request and return its result
          #{self}.request(
            serial_obj: 'required - required serial_obj returned from #connect method',
            payload: 'required - array of bytes OR string to write to serial device (e.g. [0x00, 0x41, 0x90, 0x00] OR ATDT+15555555\\r\\n'
          )

          # Run response and return its result
          #{self}.response(
            serial_obj: 'required - serial_obj returned from #connect method'
          )

          # Run dump session data and return its result
          #{self}.dump_session_data(
            serial_obj: 'optional - selected connection; required when multiple sessions are open'
          )

          # Run flush session data and return its result
          #{self}.flush_session_data(
            serial_obj: 'optional - selected connection; required when multiple sessions are open'
          )

          # Run disconnect and return its result
          #{self}.disconnect(
            serial_obj: 'required - serial_obj returned from #connect method'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
