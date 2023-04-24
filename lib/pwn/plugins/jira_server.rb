# frozen_string_literal: true

require 'json'
require 'tty-spinner'

module PWN
  module Plugins
    # This plugin is used for interacting w/ on-prem Jira Server's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    # This is based on the following Jira API Specification:
    # https://developer.atlassian.com/server/jira/platform/rest-apis/
    module JiraServer
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # rest_call(
      #   token: 'required - bearer token',
      #   http_method: 'optional HTTP method (defaults to GET)',
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        base_api_uri = opts[:base_api_uri]

        raise 'ERROR: base_api_uri cannot be nil.' if base_api_uri.nil?

        token = opts[:token]

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        spinner = TTY::Spinner.new
        spinner.auto_spin

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_api_uri}/#{rest_call}",
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
            url: "#{base_api_uri}/#{rest_call}",
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

        JSON.parse(response, symbolize_names: true)
      rescue ExceptionWithResponse => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      rescue StandardError => e
        raise e
      ensure
        spinner.stop
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.get_issue(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/corp.jira.com/rest/api/latest)',
      #   token: 'required - bearer token',
      #   issue: 'required - issue to lookup'
      # )

      public_class_method def self.get_issue(opts = {})
        base_api_uri = opts[:base_api_uri]

        token = opts[:token]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Personal Access Token'
        )

        issue = opts[:issue]

        raise 'ERROR: issue cannot be nil.' if issue.nil?

        rest_call(
          base_api_uri: base_api_uri,
          token: token,
          rest_call: "issue/#{issue}"
        )
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
          issue_resp = PWN::Plugins::JiraServer.get_issue(
            base_api_uri: 'required - base URI for Jira (e.g. https:/corp.jira.com/rest/api/latest)',
            token: 'required - bearer token',
            issue: 'required - issue to lookup'
          )

          #{self}.authors
        "
      end
    end
  end
end
