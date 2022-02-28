# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin provides useful social security number capabilities
    module SSN
      # Supported Method Parameters::
      # PWN::Plugins::SSN.generate(
      #   count: 'required - number of SSN numbers to generate'
      # )

      public_class_method def self.generate(opts = {})
        count = opts[:count].to_i

        # Based upon new SSN Randomization:
        # https://www.ssa.gov/employer/randomization.html
        ssn_result_arr = []
        (1..count).each do
          this_area = format('%0.3d', Random.rand(1..999))
          this_group = format('%0.2d', Random.rand(1..99))
          this_serial = format('%0.4d', Random.rand(1..9999))
          this_ssn = "#{this_area}-#{this_group}-#{this_serial}"
          ssn_result_arr.push(this_ssn)
        end

        ssn_result_arr
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.generate(
            count: 'required - number of SSN numbers to generate'
          )

          #{self}.authors
        "
      end
    end
  end
end
