# frozen_string_literal: true

require 'os'

module PWN
  module Plugins
    # This plugin converts images to readable text
    module DetectOS
      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.type

      public_class_method def self.type
        os = :cygwin if OS.cygwin?
        os = :freebsd if OS.freebsd?
        os = :linux if OS.linux?
        os = :netbsd if OS.host_os.include?('netbsd')
        os = :openbsd if OS.host_os.include?('openbsd')
        os = :osx if OS.osx?
        os = :windows if OS.windows?

        os
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.arch

      public_class_method def self.arch
        RUBY_PLATFORM.split('-').first
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.endian

      public_class_method def self.endian
        if [1].pack('I') == [1].pack('N')
          :big
        else
          :little
        end
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
          #{self}.type

          #{self}.arch

          #{self}.endian

          #{self}.authors
        "
      end
    end
  end
end
