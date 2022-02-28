# frozen_string_literal: true

require 'logger'

module PWN
  module Plugins
    # This plugin is used to instantiate a PWN logger with a custom message format
    module PWNLogger
      # Supported Method Parameters::
      # PWN::Plugins::PWNLogger.create(
      # )

      public_class_method def self.create
        logger = Logger.new($stdout)
        logger.level = Logger::INFO
        logger.datetime_format = '%Y-%m-%d %H:%M:%S'

        logger.formatter = proc do |severity, _datetime, _progname, msg|
          # TODO: Include datetime & progname vars
          "[#{severity}] #{msg}\n"
        end

        logger
      rescue StandardError => e
        raise e
      end

      # Author(s):: Jacob Hoopes <jake.hoopes@gmail.com>

      public_class_method def self.authors
        'AUTHOR(S):
          Jacob Hoopes <jake.hoopes@gmail.com>
        '
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          logger = #{self}.create()
         #{self}.authors
        "
      end
    end
  end
end
