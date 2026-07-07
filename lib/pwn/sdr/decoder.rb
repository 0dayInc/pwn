# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SDR modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module SDR
    # Deocder Module for SDR signals.
    module Decoder
      autoload :Base, 'pwn/sdr/decoder/base'
      autoload :Flex, 'pwn/sdr/decoder/flex'
      autoload :GSM, 'pwn/sdr/decoder/gsm'
      autoload :POCSAG, 'pwn/sdr/decoder/pocsag'
      autoload :RDS, 'pwn/sdr/decoder/rds'

      # Display a List of Every PWN::AI Module

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        constants.sort
      end
    end
  end
end
