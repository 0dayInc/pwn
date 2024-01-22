# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module CodeCave
      # Supported Method Parameters::
      # PWN::Banner::CodeCave.get

      public_class_method def self.get
        '
        00000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
        00000010: 0200 0300 0100 0000 208e 0408 3400 0000  ........ ...4...
        00000020: ac00 0000 0000 0000 3400 2000 0100 2800  ........4. ...(.
        00000030: 0400 0300 0100 0000 0000 0000 0080 0408  ................
        00000040: 0080 0408 c000 0000 c000 0000 0500 0000  ................
        00000050: 0010 0000 0100 0000 0000 0000 0080 0408  ................
        00000060: 0000 0000 0000 0000 0000 0000 0600 0000  ................
        00000070: 7077 6e00 0000 0000 0000 0000 0000 0000  pwn.............
        00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
        00000090: 0000 0000 0000 0000 0000 0000 0000 0021  ...............!
        000000a0: b82a 0000 00b9 1d00 0000 baf4 0000 00ba  ..*.............
        000000b0: 9a86 0408 e970 ffff ff31 c040 cd80 0000  ....p...1.@.....
        '.light_black
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
