# frozen_string_literal: true

require 'base64'
require 'json'

module PWN
  module Plugins
    # This plugin converts images to readable text
    # TODO: Convert all rest requests to POST instead of GET
    module TwitterAPI
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # bearer_token = PWN::Plugins::TwitterAPI.app_only_login(
      #   consumer_key: 'required - consumer key for app-only authentication',
      #   consumer_secret: 'optional - consumer secret (will prompt if nil)'
      # )

      public_class_method def self.app_only_login(opts = {})
        base_api_uri = 'https://api.twitter.com'

        consumer_key = opts[:consumer_key].to_s.strip.chomp.scrub
        consumer_secret = if opts[:consumer_secret].nil?
                            PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Consumer Secret')
                          else
                            opts[:consumer_secret].to_s.chomp.strip.scrub
                          end

        authz_str = Base64.strict_encode64("#{consumer_key}:#{consumer_secret}")
        http_headers = {}
        http_headers[:content_type] = 'application/x-www-form-urlencoded;charset=UTF-8'
        http_headers[:authorization] = "Basic #{authz_str}"

        @@logger.info("Logging into TwitterAPI REST API: #{base_api_uri}")
        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request
        response = rest_client.execute(
          method: :post,
          url: "#{base_api_uri}/oauth2/token",
          headers: http_headers,
          payload: 'grant_type=client_credentials'
        )

        # Return array containing the post-authenticated TwitterAPI REST API token
        json_response = JSON.parse(response, symbolize_names: true)
        json_response[:access_token]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # twitter_rest_call(
      #   bearer_token: 'required bearer_token returned from #app_only_login method',
      #   rest_call: 'required rest call to make per the schema',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.twitter_rest_call(opts = {})
        bearer_token = opts[:bearer_token]
        rest_call = opts[:rest_call].to_s.scrub
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        host = bearer_token[:host]
        port = bearer_token[:port]
        base_zap_api_uri = "http://#{host}:#{port}"

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_zap_api_uri}/#{rest_call}",
            headers: {
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_zap_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8'
            },
            payload: http_body,
            verify_ssl: false
          )

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end

        sleep 3

        response
      rescue StandardError, SystemExit, Interrupt => e
        logout(bearer_token) unless bearer_token.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TwitterAPI.logout(
      #   bearer_token: 'required bearer_token returned from #app_only_login method'
      # )

      public_class_method def self.app_only_logout(opts = {})
        bearer_token = opts[:bearer_token]
        @@logger.info('Logging out...')
        # TODO: Terminate Session if Possible via API Call
        bearer_token = nil
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
          bearer_token = #{self}.app_only_login(
            consumer_key: 'required - consumer key for app-only authentication',
            consumer_secret: 'optional - consumer secret (will prompt if nil)'
          )

          #{self}.app_only_logout(
            bearer_token: 'required bearer_token returned from #app_only_login method'
          )

          #{self}.authors
        "
      end
    end
  end
end
