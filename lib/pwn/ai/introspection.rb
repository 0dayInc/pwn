# frozen_string_literal: true

require 'json'
require 'rest-client'
require 'tty-spinner'

module PWN
  module AI
    # This plugin interacts with PWN::Env's `ai` data structure
    # when `PWN::Env[:ai][:introspection]` is set to `true`.
    module Introspection
      # Supported Method Parameters::
      # response = PWN::AI::Introspection.reflect

      public_class_method def self.reflect
        engine = PWN::Env[:ai][:active].to_s.downcase.to_sym
        base_uri = PWN::Env[:ai][engine][:base_uri]
        model = PWN::Env[:ai][engine][:model]
        key = PWN::Env[:ai][engine][:key]
        system_role_content = PWN::Env[:ai][engine][:system_role_content]
        temp = PWN::Env[:ai][engine][:temp]

        case engine
        when :grok
          response = PWN::AI::Grok.chat(
            base_uri: base_uri,
            token: key,
            model: model,
            system_role_content: system_role_content,
            temp: temp,
            request: request.chomp,
            spinner: false
          )
        when :ollama
          response = PWN::AI::Ollama.chat(
            base_uri: base_uri,
            token: key,
            model: model,
            system_role_content: system_role_content,
            temp: temp,
            request: request.chomp,
            spinner: false
          )
        when :openai
          response = PWN::AI::OpenAI.chat(
            base_uri: base_uri,
            token: key,
            model: model,
            system_role_content: system_role_content,
            temp: temp,
            request: request.chomp,
            spinner: false
          )
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
          #{self}.reflect

          #{self}.authors
        "
      end
    end
  end
end
