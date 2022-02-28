# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin provides useful employer identification number capabilities
    module EIN
      # Supported Method Parameters::
      # PWN::Plugins::EIN.generate(
      #   count: 'required - number of EIN numbers to generate'
      # )

      public_class_method def self.generate(opts = {})
        count = opts[:count].to_i

        ein_prefix_data_struct = [
          { campus: :andover, prefix: 10 },
          { campus: :andover, prefix: 12 },
          { campus: :atlanta, prefix: 60 },
          { campus: :atlanta, prefix: 67 },
          { campus: :austin, prefix: 50 },
          { campus: :austin, prefix: 53 },
          { campus: :brookhaven, prefix: 1 },
          { campus: :brookhaven, prefix: 2 },
          { campus: :brookhaven, prefix: 3 },
          { campus: :brookhaven, prefix: 4 },
          { campus: :brookhaven, prefix: 5 },
          { campus: :brookhaven, prefix: 6 },
          { campus: :brookhaven, prefix: 11 },
          { campus: :brookhaven, prefix: 13 },
          { campus: :brookhaven, prefix: 14 },
          { campus: :brookhaven, prefix: 16 },
          { campus: :brookhaven, prefix: 21 },
          { campus: :brookhaven, prefix: 22 },
          { campus: :brookhaven, prefix: 23 },
          { campus: :brookhaven, prefix: 25 },
          { campus: :brookhaven, prefix: 34 },
          { campus: :brookhaven, prefix: 51 },
          { campus: :brookhaven, prefix: 52 },
          { campus: :brookhaven, prefix: 54 },
          { campus: :brookhaven, prefix: 55 },
          { campus: :brookhaven, prefix: 56 },
          { campus: :brookhaven, prefix: 57 },
          { campus: :brookhaven, prefix: 58 },
          { campus: :brookhaven, prefix: 59 },
          { campus: :brookhaven, prefix: 65 },
          { campus: :cincinnati, prefix: 30 },
          { campus: :cincinnati, prefix: 32 },
          { campus: :cincinnati, prefix: 35 },
          { campus: :cincinnati, prefix: 36 },
          { campus: :cincinnati, prefix: 37 },
          { campus: :cincinnati, prefix: 38 },
          { campus: :cincinnati, prefix: 61 },
          { campus: :fresno, prefix: 15 },
          { campus: :fresno, prefix: 24 },
          { campus: :kansas_city, prefix: 40 },
          { campus: :kansas_city, prefix: 44 },
          { campus: :memphis, prefix: 94 },
          { campus: :memphis, prefix: 95 },
          { campus: :ogden, prefix: 80 },
          { campus: :ogden, prefix: 90 },
          { campus: :philadelphia, prefix: 33 },
          { campus: :philadelphia, prefix: 39 },
          { campus: :philadelphia, prefix: 41 },
          { campus: :philadelphia, prefix: 42 },
          { campus: :philadelphia, prefix: 43 },
          { campus: :philadelphia, prefix: 46 },
          { campus: :philadelphia, prefix: 48 },
          { campus: :philadelphia, prefix: 62 },
          { campus: :philadelphia, prefix: 63 },
          { campus: :philadelphia, prefix: 64 },
          { campus: :philadelphia, prefix: 66 },
          { campus: :philadelphia, prefix: 68 },
          { campus: :philadelphia, prefix: 71 },
          { campus: :philadelphia, prefix: 72 },
          { campus: :philadelphia, prefix: 73 },
          { campus: :philadelphia, prefix: 74 },
          { campus: :philadelphia, prefix: 75 },
          { campus: :philadelphia, prefix: 76 },
          { campus: :philadelphia, prefix: 77 },
          { campus: :philadelphia, prefix: 82 },
          { campus: :philadelphia, prefix: 83 },
          { campus: :philadelphia, prefix: 84 },
          { campus: :philadelphia, prefix: 85 },
          { campus: :philadelphia, prefix: 86 },
          { campus: :philadelphia, prefix: 87 },
          { campus: :philadelphia, prefix: 88 },
          { campus: :philadelphia, prefix: 91 },
          { campus: :philadelphia, prefix: 92 },
          { campus: :philadelphia, prefix: 93 },
          { campus: :philadelphia, prefix: 98 },
          { campus: :philadelphia, prefix: 99 },
          { campus: :internet, prefix: 20 },
          { campus: :internet, prefix: 26 },
          { campus: :internet, prefix: 27 },
          { campus: :internet, prefix: 45 },
          { campus: :internet, prefix: 46 },
          { campus: :internet, prefix: 47 },
          { campus: :internet, prefix: 81 },
          { campus: :internet, prefix: 82 },
          { campus: :internet, prefix: 83 },
          { campus: :small_business_administration, prefix: 31 }
        ]

        ein_result_arr = []
        (1..count).each do
          this_ein_prefix_data_struct_index = Random.rand(ein_prefix_data_struct.length)
          this_ein_prefix_data_struct = ein_prefix_data_struct[this_ein_prefix_data_struct_index]
          this_ein_prefix_campus = this_ein_prefix_data_struct[:campus]
          this_ein_prefix = format('%0.2d', this_ein_prefix_data_struct[:prefix])
          this_ein_suffix = format('%0.7d', Random.rand(0..9_999_999))
          this_ein = { campus: this_ein_prefix_campus, ein: "#{this_ein_prefix}-#{this_ein_suffix}" }
          ein_result_arr.push(this_ein)
        end

        ein_result_arr
      rescue StandardError => e
        raise e
      end

      # Author(s):: Jacob Hoopes <jake.hoopes@gmail.com>

      public_class_method def self.authors
        "AUTHOR(S):
          Jacob Hoopes <jake.hoopes@gmail.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.generate(
            count: 'required - number of EIN numbers to generate'
          )

          #{self}.authors
        "
      end
    end
  end
end
