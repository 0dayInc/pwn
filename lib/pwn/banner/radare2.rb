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
        $ target_arm_bin="/usr/bin/id";
        $ alias r2="setarch $(uname -m) -R r2 -AA -c \"v r2-pwn-layout\""
        $ r2 -c "db (0x`readelf -S $target_arm_bin | grep text | awk "{print $NF}"`)+0x4+0x00000328" -c "ood" -c "dc" -c "v" $target_arm_bin
        '.yellow
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
          #{self}.get

          #{self}.authors
        "
      end
    end
  end
end
