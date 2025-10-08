# frozen_string_literal: true

require 'logger'

module PWN
  module Plugins
    # This plugin is used to instantiate a PWN logger with a custom message format
    module PWNLogger
      # Supported Method Parameters::
      # PWN::Plugins::PWNLogger.create(
      # )

      public_class_method def self.create(opts = {})
        logger = Logger.new($stdout)
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
          "[#{severity}] #{msg}\n"
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
          logger = #{self}.create(
            level: 'optional - logging verbosity :debug|:error|:fatal|:info|:unknown|:warn (Defaults to :info)'
          )
          #{self}.authors
        "
      end
    end
  end
end
