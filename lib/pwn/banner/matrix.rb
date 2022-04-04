# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module Matrix
      # Supported Method Parameters::
      # PWN::Banner::Matrix.get

      public_class_method def self.get
        cols = 33

        matrix_arr = [
          0x30a0.chr('UTF-8'),
          0x30a1.chr('UTF-8'),
          0x30a2.chr('UTF-8'),
          0x30a3.chr('UTF-8'),
          0x30a4.chr('UTF-8'),
          0x30a5.chr('UTF-8'),
          0x30a6.chr('UTF-8'),
          0x30a7.chr('UTF-8'),
          0x30a8.chr('UTF-8'),
          0x30a9.chr('UTF-8'),
          0x30aa.chr('UTF-8'),
          0x30ab.chr('UTF-8'),
          0x30ac.chr('UTF-8'),
          0x30ad.chr('UTF-8'),
          0x30ae.chr('UTF-8'),
          0x30af.chr('UTF-8'),
          0x30b0.chr('UTF-8'),
          0x30b1.chr('UTF-8'),
          0x30b2.chr('UTF-8'),
          0x30b3.chr('UTF-8'),
          0x30b4.chr('UTF-8'),
          0x30b5.chr('UTF-8'),
          0x30b6.chr('UTF-8'),
          0x30b7.chr('UTF-8'),
          0x30b8.chr('UTF-8'),
          0x30b9.chr('UTF-8'),
          0x30ba.chr('UTF-8'),
          0x30bb.chr('UTF-8'),
          0x30bc.chr('UTF-8'),
          0x30bd.chr('UTF-8'),
          0x30be.chr('UTF-8'),
          0x30bf.chr('UTF-8'),
          0x30c0.chr('UTF-8'),
          0x30c1.chr('UTF-8'),
          0x30c2.chr('UTF-8'),
          0x30c3.chr('UTF-8'),
          0x30c4.chr('UTF-8'),
          0x30c5.chr('UTF-8'),
          0x30c6.chr('UTF-8'),
          0x30c7.chr('UTF-8'),
          0x30c8.chr('UTF-8'),
          0x30c9.chr('UTF-8'),
          0x30ca.chr('UTF-8'),
          0x30cb.chr('UTF-8'),
          0x30cc.chr('UTF-8'),
          0x30cd.chr('UTF-8'),
          0x30ce.chr('UTF-8'),
          0x30cf.chr('UTF-8'),
          0x30d0.chr('UTF-8'),
          0x30d1.chr('UTF-8'),
          0x30d2.chr('UTF-8'),
          0x30d3.chr('UTF-8'),
          0x30d4.chr('UTF-8'),
          0x30d5.chr('UTF-8'),
          0x30d6.chr('UTF-8'),
          0x30d7.chr('UTF-8'),
          0x30d8.chr('UTF-8'),
          0x30d9.chr('UTF-8'),
          0x30da.chr('UTF-8'),
          0x30db.chr('UTF-8'),
          0x30dc.chr('UTF-8'),
          0x30dd.chr('UTF-8'),
          0x30de.chr('UTF-8'),
          0x30df.chr('UTF-8'),
          0x30e0.chr('UTF-8'),
          0x30e1.chr('UTF-8'),
          0x30e2.chr('UTF-8'),
          0x30e3.chr('UTF-8'),
          0x30e4.chr('UTF-8'),
          0x30e5.chr('UTF-8'),
          0x30e6.chr('UTF-8'),
          0x30e7.chr('UTF-8'),
          0x30e8.chr('UTF-8'),
          0x30e9.chr('UTF-8'),
          0x30ea.chr('UTF-8'),
          0x30eb.chr('UTF-8'),
          0x30ec.chr('UTF-8'),
          0x30ed.chr('UTF-8'),
          0x30ee.chr('UTF-8'),
          0x30ef.chr('UTF-8'),
          0x30f0.chr('UTF-8'),
          0x30f1.chr('UTF-8'),
          0x30f2.chr('UTF-8'),
          0x30f3.chr('UTF-8'),
          0x30f4.chr('UTF-8'),
          0x30f5.chr('UTF-8'),
          0x30f6.chr('UTF-8'),
          0x30f7.chr('UTF-8'),
          0x30f8.chr('UTF-8'),
          0x30f9.chr('UTF-8'),
          0x30fa.chr('UTF-8'),
          0x30fb.chr('UTF-8'),
          0x30fc.chr('UTF-8'),
          0x30fd.chr('UTF-8'),
          0x30fe.chr('UTF-8'),
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

        last_index = matrix_arr.length - 1

        matrix = ''
        cols.times do
          matrix_row = ''
          most_cols = cols - 1
          most_cols.times.each do
            matrix_row += "#{matrix_arr[Random.rand(0..last_index)]} "
          end
          matrix_row += matrix_arr[Random.rand(0..last_index)]
          matrix = "#{matrix}#{matrix_row}\n"
        end

        matrix = "#{matrix}PWN\n"
        matrix.green
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
