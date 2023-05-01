# frozen_string_literal: true

require 'logger'

module PWN
  # This plugin is used to instantiate a PWN logger with a custom message format
  module Log
    # Supported Method Parameters::
    # PWN::Log.create(
    # )
    public_class_method def self.append(opts = {})
      level = opts[:level].to_s.downcase.to_sym
      msg = opts[:msg]
      which_self = opts[:which_self].to_s
      event_history = opts[:event_history]

      driver_name = File.basename($PROGRAM_NAME)

      # Only attempt to exit gracefully if level == :error
      exit_gracefully = false

      if event_history.respond_to?('order_book')
        session = event_history.order_book[:path].split('/').first
        symbol = event_history.order_book[:symbol]
      end

      # Define Date / Time Format
      datetime_str = '%Y-%m-%d %H:%M:%S.%N%z'

      # Always append to log file
      if level == :learning
        log_file_path = "/tmp/pwn-ai-#{session}-#{symbol}.json" if level == :learning
        log_file = File.open(log_file_path, 'w')
      else
        log_file_path = '/tmp/pwn.log'
        log_file = File.open(log_file_path, 'a')
      end

      # Leave 10 "old" log files where
      # each file is ~ 1,024,000 bytes
      logger = Logger.new(
        log_file,
        10,
        1_024_000
      )
      logger.datetime_format = datetime_str

      case level
      when :debug
        logger.level = Logger::DEBUG
      when :error
        logger.level = Logger::ERROR
        exit_gracefully = true unless driver_name == 'pwn'
        puts "\nERROR: See #{log_file_path} for more details." if driver_name == 'pwn'
      when :fatal
        # This is reserved for the PWN::UI::Exit module
        # if the Interrupt or StandardError exceptions are
        # triggered.  This prevents infintely attempting to
        # exit if something in the module fails.
        logger.level = Logger::FATAL
        if driver_name == 'pwn'
          puts "\n FATAL ERROR: See #{log_file_path} for more details."
        end
      when :info, :learning
        logger.level = Logger::INFO
      when :unknown
        logger.level = Logger::UNKNOWN
      when :warn
        logger.level = Logger::WARN
      else
        level_error = "ERROR: Invalid log level. Valid options are:\n"
        level_error += ":debug\n:error\n:fatal\n:info\n:learning\n:unknown\n:warn\n"
        raise level_error
      end

      if level == :learning
        log_event = msg
        logger.formatter = proc do |_severity, _datetime, _progname, learning_arr|
          JSON.pretty_generate(
            learning_data: learning_arr
          )
        end
      else
        log_event = "driver: #{driver_name}"
        if event_history.respond_to?('order_book')
          log_event += ", session: #{session}, "
          log_event += "symbol: #{symbol}"
        end

        if msg.instance_of?(Interrupt)
          logger.level = Logger::WARN
          if driver_name == 'pwn'
            log_event += ' => CTRL+C Detected.'
          else
            log_event += ' => CTRL+C Detected...Exiting Session.'
            exit_gracefully = true unless driver_name == 'pwn'
          end
        else
          log_event += " => #{msg}"
          if msg.respond_to?('backtrace') && !msg.instance_of?(Errno::ECONNRESET)
            log_event += " => \n\t#{msg.backtrace.join("\n\t")}"
            log_event += "\n\n\n"
          end
        end
      end

      logger.add(logger.level, log_event, which_self)

      PWN::UI::Exit.gracefully(event_history: event_history) if exit_gracefully
    rescue Interrupt, StandardError => e
      raise e
    end

    # Display Usage for this Module

    public_class_method def self.help
      puts "USAGE:
        logger = #{self}.create()
      "
    end
  end
end
