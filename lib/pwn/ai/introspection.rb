# frozen_string_literal: true

require 'json'
require 'rest-client'

module PWN
  module AI
    # This plugin interacts with PWN::Env's `ai` data structure
    # when `PWN::Env[:ai][:introspection]` is set to `true`.
    module Introspection
      # Supported Method Parameters::
      # response = PWN::AI::Introspection.reflect_on(
      #   request: 'required - String - What you want the AI to reflect on',
      #   system_role_content: 'optional - context to set up the model behavior for reflection'
      # )

      public_class_method def self.reflect_on(opts = {})
        request = opts[:request]
        raise 'ERROR: request must be provided' if request.nil?

        system_role_content = opts[:system_role_content]

        response = nil

        ai_introspection = PWN::Env[:ai][:introspection]

        if ai_introspection && request.length.positive?
          valid_ai_engines = PWN::AI.help.reject { |e| e.downcase == :introspection }.map(&:downcase)
          engine = PWN::Env[:ai][:active].to_s.downcase.to_sym
          raise "ERROR: Unsupported AI engine. Supported engines are: #{valid_ai_engines}" unless valid_ai_engines.include?(engine)

          case engine
          when :grok
            response = PWN::AI::Grok.chat(
              request: request.chomp,
              system_role_content: system_role_content,
              spinner: false
            )
            response = response[:choices].last[:content] if response.is_a?(Hash) &&
                                                            response.key?(:choices) &&
                                                            response[:choices].last.keys.include?(:content)
          when :ollama
            response = PWN::AI::Ollama.chat(
              request: request.chomp,
              system_role_content: system_role_content,
              spinner: false
            )
            puts response
          when :openai
            response = PWN::AI::OpenAI.chat(
              request: request.chomp,
              system_role_content: system_role_content,
              spinner: false
            )
            if response.is_a?(Hash) && response.key?(:choices)
              response = response[:choices].last[:text] if response[:choices].last.keys.include?(:text)
              response = response[:choices].last[:content] if response[:choices].last.keys.include?(:content)
            end
          end
        end

        response
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
          #{self}.reflect_on(
            request: 'required - String - What you want the AI to reflect on',
            system_role_content: 'optional - context to set up the model behavior for reflection'
          )

          #{self}.authors
        "
      end
    end
  end
end
