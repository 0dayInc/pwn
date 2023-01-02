# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # This plugin is used for interacting w/ ChatSonic's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    # This is based on the following ChatSonic API Specification:
    # https://docs.writesonic.com/reference/chatsonic_v2businesscontentchatsonic_post-1
    module ChatSonic
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # chat_sonic_rest_call(
      #   apu_key: 'required - chat_sonic api_key',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.chat_sonic_rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        base_chat_sonic_api_uri = 'https://api.writesonic.com/v2/business/content'
        api_key = opts[:api_key]

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_chat_sonic_api_uri}/#{rest_call}",
            headers: {
              accept: 'application/json',
              content_type: 'application/json; charset=UTF-8',
              x_api_key: api_key,
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_chat_sonic_api_uri}/#{rest_call}",
            headers: {
              accept: 'application/json',
              content_type: 'application/json; charset=UTF-8',
              x_api_key: api_key,
              params: params
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
      # response = PWN::Plugins::ChatSonic.chat(
      #   api_key: 'required - ChatSonic API Key',
      #   input_text: 'required - message to ChatSonic'
      #   enable_google_results: 'optional - use Google to answer (default to true)',
      #   enable_memory: 'optional - try to continue previous conversation (default to false)',
      # )

      public_class_method def self.chat(opts = {})
        api_key = opts[:api_key]
        input_text = opts[:input_text]

        enable_google_results = opts[:enable_google_results]
        enable_google_results ||= true

        enable_memory = opts[:enable_memory]
        enable_memory ||= false

        params = opts[:params]
        params ||= {}

        rest_call = 'chatsonic'

        params[:engine] = 'premium'

        http_body = {
          enable_google_results: enable_google_results,
          enable_memory: enable_memory,
          input_text: input_text
        }

        response = chat_sonic_rest_call(
          http_method: :post,
          api_key: api_key,
          rest_call: rest_call,
          params: params,
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
          response = #{self}.chat(
            api_key: 'required - ChatSonic API Key',
            input_text: 'required - message to ChatSonic'
            enable_google_results: 'optional - use Google to answer (default to true)',
            enable_memory: 'optional - try to continue previous conversation (default to false)',
          )

          #{self}.authors
        "
      end
    end
  end
end
