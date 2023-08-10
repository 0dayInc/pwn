# frozen_string_literal: true

require 'os'

module PWN
  module Plugins
    # This plugin converts images to readable text
    module DetectOS
      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.type

      public_class_method def self.type
        :cygwin if OS.cygwin?
        :freebsd if OS.freebsd?
        :linux if OS.linux?
        :netbsd if OS.host_os.include?('netbsd')
        :openbsd if OS.host_os.include?('openbsd')
        :osx if OS.osx?
        :windows if OS.windows?
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
