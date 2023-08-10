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

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.type

          #{self}.authors
        "
      end
    end
  end
end
