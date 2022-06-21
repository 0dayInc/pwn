# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin is used for interacting with an RFIDler using the
    # the screen command as a terminal emulator.
    module RFIDler
      # Supported Method Parameters::
      # PWN::Plugins::RFIDler.connect_via_screen(
      #   block_dev: 'optional - serial block device path (defaults to /dev/ttyUSB0)'
      # )

      public_class_method def self.connect_via_screen(opts = {})
        block_dev = opts[:block_dev].to_s if File.exist?(
          opts[:block_dev].to_s
        )

        block_dev = '/dev/ttyUSB0' if opts[:block_dev].nil?
        screen_bin = '/usr/bin/screen'

        raise "ERROR: #{screen_bin} not found." unless File.exist?(screen_bin)

        system(
          screen_bin,
          block_dev,
          '9600',
          '8',
          'N',
          '1'
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
          #{self}.connect_via_screen(
            block_dev: 'optional serial block device path (defaults to /dev/ttyUSB0)'
          )

          #{self}.authors
        "
      end
    end
  end
end
