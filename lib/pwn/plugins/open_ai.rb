# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # This plugin is used for interacting w/ OpenAI's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    # This is based on the following OpenAI API Specification:
    # https://api.openai.com/v1
    module OpenAI
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # open_ai_rest_call(
      #   token: 'required - open_ai bearer token',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.open_ai_rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        base_open_ai_api_uri = 'https://api.openai.com/v1'
        token = opts[:token]

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_open_ai_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              authorization: "Bearer #{token}",
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_open_ai_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              authorization: "Bearer #{token}"
            },
            payload: http_body,
            verify_ssl: false
          )

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
        response
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::OpenAI.get_models(
      #   token: 'required - Bearer token',
      # )

      public_class_method def self.get_models(opts = {})
        token = opts[:token]

        response = open_ai_rest_call(
          token: token,
          rest_call: 'models'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::OpenAI.chat_gpt(
      #   token: 'required - Bearer token',
      #   request: 'required - message to ChatGPT'
      #   model: 'optional - model to use for text generation (defaults to text-davinci-003)',
      #   temp: 'optional - integer (deafults to 0)',
      #   max_tokens: 'optional - integer (deafults to 1024)'
      # )

      public_class_method def self.chat_gpt(opts = {})
        token = opts[:token]
        request = opts[:request]
        model = opts[:model]
        model ||= 'text-davinci-003'
        temp = opts[:temp].to_i
        temp = 0 unless temp.positive?
        max_tokens = opts[:max_tokens].to_i
        max_tokens = 1024 unless max_tokens.positive?

        rest_call = 'completions'

        http_body = {
          model: model,
          prompt: request,
          temperature: temp,
          max_tokens: max_tokens
        }

        response = open_ai_rest_call(
          http_method: :post,
          token: token,
          rest_call: rest_call,
          http_body: http_body.to_json
        )

        JSON.parse(response, symbolize_names: true)
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
          response = #{self}.chat_gpt(
            token: 'required - Bearer token',
            request: 'required - message to ChatGPT',
            model: 'optional - model to use for text generation (defaults to text-davinci-003)',
            temp: 'optional - integer (deafults to 0)',
            max_tokens: 'optional - integer (deafults to 1024)'
          )

          #{self}.authors
        "
      end
    end
  end
end
