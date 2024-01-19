# frozen_string_literal: true

require 'credit_card_validations'
require 'credit_card_validations/string'

module PWN
  module Plugins
    # This plugin provides useful credit card capabilities
    module CreditCard
      # Supported Method Parameters::
      # PWN::Plugins::CreditCard.generate(
      #   type: 'required - card to generate :amex|:unionpay|:dankort|:diners|:elo|:discover|:hipercard|:jcb|:maestro|:mastercard|:mir|:rupay|:solo|:switch|:visa',
      #   count: 'optional - number of numbers to generate (defaults to 1)'
      # )

      public_class_method def self.generate(opts = {})
        type = opts[:type].to_s.scrub.strip.chomp.to_sym
        count = opts[:count].to_i
        count = 1 if count.zero?

        cc_result_arr = []
        (1..count).each do
          cc_result_arr.push(CreditCardValidations::Factory.random(type))
        end

        cc_result_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::CreditCard.type(
      #   cc: 'required - e.g. XXXX XXXX XXXX XXXX'
      # )

      public_class_method def self.type(opts = {})
        cc = opts[:cc].to_s.scrub.strip.chomp
        cc.credit_card_brand
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
            count: 'optional - number of numbers to generate (defaults to 1)'
          )

          #{self}.type(
            cc: 'required - e.g. XXXX XXXX XXXX XXXX'
          )

          #{self}.authors
        "
      end
    end
  end
end
