# frozen_string_literal: true

require 'json'
require 'base64'

module PWN
  module Plugins
    # This plugin is used for interacting w/ HackerOne's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    module HackerOne
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # h1_obj = PWN::Plugins::HackerOne.login(
      #   username: 'required - username',
      #   token: 'optional - api token (will prompt if nil)'
      # )

      public_class_method def self.login(opts = {})
        username = opts[:username].to_s.scrub
        base_h1_api_uri = 'https://api.hackerone.com/v1/'.to_s.scrub

        token = if opts[:token].nil?
                  PWN::Plugins::AuthenticationHelper.mask_password
                else
                  opts[:token].to_s.scrub
                end

        auth_payload = {}
        auth_payload[:username] = username
        auth_payload[:token] = token

        base64_str = "#{username}:#{token}"
        base64_encoded_auth = Base64.strict_encode64(base64_str).to_s.chomp
        basic_auth_header = "Basic #{base64_encoded_auth}"

        @@logger.info("Logging into HackerOne REST API: #{base_h1_api_uri}")
        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request
        response = rest_client.execute(
          method: :get,
          url: base_h1_api_uri,
          headers: {
            authorization: basic_auth_header,
            content_type: 'application/json; charset=UTF-8'
          }
        )

        # Return array containing the post-authenticated HackerOne REST API token
        json_response = JSON.parse(response, symbolize_names: true)
        h1_success = json_response['success']
        api_token = json_response['token']
        h1_obj = {}
        h1_obj[:h1_success] = h1_success
        h1_obj[:api_token] = api_token
        h1_obj[:raw_response] = response

        h1_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # h1_rest_call(
      #   h1_obj: 'required h1_obj returned from #login method',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.h1_rest_call(opts = {})
        h1_obj = opts[:h1_obj]
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        http_body = opts[:http_body].to_s.scrub
        h1_success = h1_obj[:h1_success].to_s.scrub
        base_h1_api_uri = 'https://api.hackerone.com/v1/'.to_s.scrub
        api_token = h1_obj[:api_token]

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request
        rest_client = browser_obj[:browser]::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_h1_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              params: { token: api_token }
            }
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_h1_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8'
            },
            payload: http_body
          )

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::HackerOne.logout(
      #   h1_obj: 'required h1_obj returned from #login method'
      # )

      public_class_method def self.logout(opts = {})
        h1_obj = opts[:h1_obj]
        @@logger.info('Logging out...')
        h1_obj = nil
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
          h1_obj = #{self}.login(
            username: 'required username',
            token: 'optional api token (will prompt if nil)'
          )

          h1_obj = #{self}.logout(
            h1_obj: 'required h1_obj returned from #login method'
          )

          #{self}.authors
        "
      end
    end
  end
end
