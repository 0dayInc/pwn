# frozen_string_literal: true

# require 'credit_card_validations'

module PWN
  module Plugins
    # This plugin provides useful credit card capabilities
    module CreditCard
      # Supported Method Parameters::
      # PWN::Plugins::CreditCard.generate(
      #   type: 'required - card to generate :amex|:unionpay|:dankort|:diners|:elo|:discover|:hipercard|:jcb|:maestro|:mastercard|:mir|:rupay|:solo|:switch|:visa',
      #   count: 'required - number of numbers to generate'
      # )

      public_class_method def self.generate(opts = {})
        type = opts[:type].to_s.scrub.strip.chomp.to_sym
        count = opts[:count].to_i

        cc_result_arr = []
        (1..count).each do
          cc_result_arr.push(CreditCardValidations::Factory.random(type))
        end

        cc_result_arr
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
          #{self}.generate(
            type: 'required - card to generate :amex|:unionpay|:dankort|:diners|:elo|:discover|:hipercard|:jcb|:maestro|:mastercard|:mir|:rupay|:solo|:switch|:visa',
            count: 'required - number of numbers to generate'
          )

          #{self}.authors
        "
      end
    end
  end
end
