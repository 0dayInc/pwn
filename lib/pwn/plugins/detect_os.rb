# frozen_string_literal: true

require 'os'

module PWN
  module Plugins
    # This plugin converts images to readable text
    module DetectOS
      # Supported Method Parameters::
      # PWN::Plugins::DetectOS.type

      public_class_method def self.type
        return :cygwin if OS.cygwin?
        return :linux if OS.linux?
        return :osx if OS.osx?
        return :windows if OS.windows?
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
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
