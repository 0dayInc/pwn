# frozen_string_literal: true

require 'credit_card_validations'
require 'credit_card_validations/string'

module PWN
  module Plugins
    # This plugin provides useful credit card capabilities
    module CreditCard
      # Supported Method Parameters::
      # PWN::Plugins::CreditCard.list_types

      public_class_method def self.list_types
        %i[
          amex
          unionpay
          dankort
          diners
          elo
          discover
          hipercard
          jcb
          maestro
          mastercard
          mir
          rupay
          solo
          switch
          visa
        ]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::CreditCard.generate(
      #   type: 'optional - card type from #list_types method to generate (defaults to :random)',
      #   count: 'optional - number of numbers to generate (defaults to 1)'
      # )

      public_class_method def self.generate(opts = {})
        type = opts[:type] ||= :random
        type = type.to_s.strip.scrub.chomp.downcase.to_sym

        count = opts[:count].to_i
        count = 1 if count.zero?

        cc_result_arr = []
        (1..count).each do
          gen_type = list_types.sample if type == :random
          gen_type = type unless type == :random
          cc_hash = type(cc: CreditCardValidations::Factory.random(gen_type))
          cc_result_arr.push(cc_hash)
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
        cc_hash = {}
        cc_hash[:number] = cc
        cc_hash[:type] = cc.credit_card_brand

        cc_hash
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
          #{self}.list_types

          #{self}.generate(
            type: 'required - card to generate from #list_types method to generate',
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
