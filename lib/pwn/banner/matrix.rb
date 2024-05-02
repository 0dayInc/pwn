# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module Matrix
      # Supported Method Parameters::
      # PWN::Banner::Matrix.get

      public_class_method def self.get
        rows = cols = 33

        matrix_arr = [
          "\u30a0",
          "\u30a1",
          "\u30a2",
          "\u30a3",
          "\u30a4",
          "\u30a5",
          "\u30a6",
          "\u30a7",
          "\u30a8",
          "\u30a9",
          "\u30aa",
          "\u30ab",
          "\u30ac",
          "\u30ad",
          "\u30ae",
          "\u30af",
          "\u30b0",
          "\u30b1",
          "\u30b2",
          "\u30b3",
          "\u30b4",
          "\u30b5",
          "\u30b6",
          "\u30b7",
          "\u30b8",
          "\u30b9",
          "\u30ba",
          "\u30bb",
          "\u30bc",
          "\u30bd",
          "\u30be",
          "\u30bf",
          "\u30c0",
          "\u30c1",
          "\u30c2",
          "\u30c3",
          "\u30c4",
          "\u30c5",
          "\u30c6",
          "\u30c7",
          "\u30c8",
          "\u30c9",
          "\u30ca",
          "\u30cb",
          "\u30cc",
          "\u30cd",
          "\u30ce",
          "\u30cf",
          "\u30d0",
          "\u30d1",
          "\u30d2",
          "\u30d3",
          "\u30d4",
          "\u30d5",
          "\u30d6",
          "\u30d7",
          "\u30d8",
          "\u30d9",
          "\u30da",
          "\u30db",
          "\u30dc",
          "\u30dd",
          "\u30de",
          "\u30df",
          "\u30e0",
          "\u30e1",
          "\u30e2",
          "\u30e3",
          "\u30e4",
          "\u30e5",
          "\u30e6",
          "\u30e7",
          "\u30e8",
          "\u30e9",
          "\u30ea",
          "\u30eb",
          "\u30ec",
          "\u30ed",
          "\u30ee",
          "\u30ef",
          "\u30f0",
          "\u30f1",
          "\u30f2",
          "\u30f3",
          "\u30f4",
          "\u30f5",
          "\u30f6",
          "\u30f7",
          "\u30f8",
          "\u30f9",
          "\u30fa",
          "\u30fb",
          "\u30fc",
          "\u30fd",
          "\u30fe",
          '0 ',
          '1 ',
          '2 ',
          '3 ',
          '4 ',
          '5 ',
          '6 ',
          '7 ',
          '8 ',
          '9 ',
          'A ',
          'c ',
          'R ',
          'y ',
          'P ',
          't ',
          'U ',
          'm ',
          'x ',
          'Z ',
          ': ',
          '{ ',
          '[ ',
          '} ',
          '] ',
          '| ',
          '` ',
          '~ ',
          '! ',
          '@ ',
          '# ',
          '$ ',
          '% ',
          '^ ',
          '& ',
          '* ',
          '( ',
          ') ',
          '_ ',
          '- ',
          '= ',
          '+ ',
          '> ',
          '< ',
          '. ',
          ', '
        ]

        matrix = ''
        rows.times.each do
          matrix_row = ''
          cols.times.each { matrix_row += "#{matrix_arr.sample} " }
          matrix = "#{matrix}#{matrix_row}\n"
        end

        matrix.green
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
