# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module OffTheAir
      # Supported Method Parameters::
      # PWN::Banner::OffTheAir.get

      public_class_method def self.get
        c1 = '.....'.light_black
        c2 = '====='.yellow
        c3 = ':::::'.light_blue
        c4 = '====='.light_green
        c5 = '+++++'.light_purple
        c6 = '%%%%%'.red
        c7 = '#####'.blue
        d1 = '+++++'.blue
        d2 = '%%%%%'.black
        d3 = '+++++'.light_purple
        d4 = '%%%%%'.black
        d5 = '-----'.light_blue
        d6 = '@@@@@'.black
        d7 = 'PWN::'.red
        ee1 = '######'.red
        ee2 = '......'.white
        ee3 = '******'.blue
        ee4 = '::::::'.black
        ee5 = '@@@@@@'.black
        f1 = '%%%%%'.black

        "
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{c1}#{c2}#{c3}#{c4}#{c5}#{c6}#{c7}
          #{d1}#{d2}#{d3}#{d4}#{d5}#{d6}#{d7}
          #{ee1}#{ee2}#{ee3}#{ee4}#{ee5}#{f1}
          #{ee1}#{ee2}#{ee3}#{ee4}#{ee5}#{f1}
          #{ee1}#{ee2}#{ee3}#{ee4}#{ee5}#{f1}
        "
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
