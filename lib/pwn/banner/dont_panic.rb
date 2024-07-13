# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module DontPanic
      # Supported Method Parameters::
      # PWN::Banner::DontPanic.get

      public_class_method def self.get
        '
                    _,.-pwn-.,_
        \||\       ;;;;%%%@@@@@@       \ //,
         V|/     %;;%%%1cor15:1-4@@  ===Y//
         68=== ;;;;%%eph2:8-9@@@@@@@@    @Y
         ;Y   ;;%;%%%%%%rom3:23-28@@@@    Y
         ;Y  ;;;+;%%%2tim2:15@@@@@@@@@@    Y
         ;Y__;;;+;%%%%%%rom6:14@@@@@@@i;;__Y
        iiY"";;   "uu%@@@@@@@@@@uu"   @"";;;>
               Y     "UUUUUUUUU"     @@
               `;       ___ _       @
                 `;.  ,====\\=.  .;"
                   ``""""`==\\=="
                          `;=====
                            ===
        '.green
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
