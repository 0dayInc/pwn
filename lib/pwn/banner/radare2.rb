# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module Radare2
      # Supported Method Parameters::
      # PWN::Banner::Radare2.get

      public_class_method def self.get
        '
        $ sudo r2 -d `pidof ${TARGET_BINARY}`
        [0x7f000070776e]> aaaa
        [0x7f000070776e]> ia ~..
        [0x7f000070776e]> afl ~..
        [0x7f000070776e]> db main
        [0x7f000070776e]> db
        [0x7f000070776e]> dc
        [0x7f000070776e]> pdg
        [0x7f000070776e]> v
        '.yellow
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
          #{self}.get

          #{self}.authors
        "
      end
    end
  end
end
