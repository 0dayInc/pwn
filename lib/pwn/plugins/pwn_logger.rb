# frozen_string_literal: true

require 'logger'
require_relative '../redaction'

module PWN
  module Plugins
    # This plugin is used to instantiate a PWN logger with a custom message format
    module PWNLogger
      # Supported Method Parameters::
      # PWN::Plugins::PWNLogger.create(
      # )

      # Writes to the current $stdout. Logger.new($stdout) captures the terminal
      # at construction, so rake's per-example redirect cannot hide those lines.
      class CurrentStdout
        def write(*)
          return 0 if ENV['PWN_RAKE_SPEC'] == '1' && ENV['PWN_SPEC_VERBOSE'] != '1'

          $stdout.write(*)
        end

        def <<(arg)
          write(arg)
        end

        def flush
          $stdout.flush
        end

        def sync
          $stdout.sync
        end

        def sync=(value)
          $stdout.sync = value
        end

        def close; end

        def reopen(*)
          self
        end

        def tty?
          $stdout.tty?
        end
      end

      public_class_method def self.create(opts = {})
        logger = Logger.new(CurrentStdout.new)
        level = opts[:level]

        case level.to_s.downcase.to_sym
        when :debug
          logger.level = Logger::DEBUG
        when :error
          logger.level = Logger::ERROR
        when :fatal
          logger.level = Logger::FATAL
        when :unknown
          logger.level = Logger::UNKNOWN
        when :warn
          logger.level = Logger::WARN
        else
          logger.level = Logger::INFO
        end

        logger.datetime_format = '%Y-%m-%d %H:%M:%S.%N%z'

        logger.formatter = proc do |severity, _datetime, _progname, msg|
          # TODO: Include datetime & progname vars
          "[#{severity}] #{PWN::Redaction.redact(value: PWN::Redaction.redact(value: msg).to_s)}\n"
        end

        logger
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        'AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        '
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          # Run create and return its result
          #{self}.create(
            level: 'optional - level value consumed by #create'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
