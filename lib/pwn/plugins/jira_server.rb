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

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

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
      rescue RestClient::ExceptionWithResponse => e
        if e.response
          puts "HTTP BASE URL: #{base_api_uri}"
          puts "HTTP PATH: #{rest_call}"
          puts "HTTP RESPONSE CODE: #{e.response.code}"
          puts "HTTP RESPONSE HEADERS: #{e.response.headers}"
          puts "HTTP RESPONSE BODY:\n#{e.response.body}\n\n\n"
        end
      rescue StandardError => e
        raise e
      ensure
        spinner.stop
      end

      # Supported Method Parameters::
      # all_fields = PWN::Plugins::JiraServer.get_all_fields(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - bearer token'
      # )

      public_class_method def self.get_all_fields(opts = {})
        base_api_uri = opts[:base_api_uri]

        token = opts[:token]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Personal Access Token'
        )

        rest_call(
          base_api_uri: base_api_uri,
          token: token,
          rest_call: 'field'
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.get_issue(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - bearer token',
      #   issue: 'required - issue to lookup (e.g. Bug, Issue, Story, or Epic ID)',
      #   params: 'optional - additional parameters to pass in the URI (e.g. fields, expand, etc.)'
      # )

      public_class_method def self.get_issue(opts = {})
        base_api_uri = opts[:base_api_uri]

        token = opts[:token]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Personal Access Token'
        )

        issue = opts[:issue]
        params = opts[:params]

        raise 'ERROR: issue cannot be nil.' if issue.nil?

        rest_call(
          base_api_uri: base_api_uri,
          token: token,
          rest_call: "issue/#{issue}",
          params: params
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.create_issue(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - bearer token',
      #   project_key: 'required - project key (e.g. PWN)',
      #   summary: 'required - summary of the issue (e.g. Epic for PWN-1337)',
      #   issue_type: 'required - issue type (e.g. :epic, :story, :bug)',
      #   description: 'optional - description of the issue',
      #   additional_fields: 'optional - additional fields to set in the issue (e.g. labels, components, custom fields, etc.)'
      # )

      public_class_method def self.create_issue(opts = {})
        base_api_uri = opts[:base_api_uri]

        token = opts[:token]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Personal Access Token'
        )
        project_key = opts[:project_key]
        raise 'ERROR: project_key cannot be nil.' if project_key.nil?

        summary = opts[:summary]
        raise 'ERROR: summary cannot be nil.' if summary.nil?

        issue_type = opts[:issue_type]
        raise 'ERROR: issue_type values must be one of :epic, :story, or :bug.' unless %i[epic story bug].include?(issue_type)

        description = opts[:description]

        additional_fields = opts[:additional_fields] ||= { fields: {} }

        all_fields = get_all_fields(base_api_uri: base_api_uri, token: token)
        epic_name_field_key = all_fields.find { |field| field[:name] == 'Epic Name' }[:id]

        epic_name = summary

        http_body = {
          fields: {
            project: {
              key: project_key
            },
            summary: summary,
            issuetype: {
              name: issue_type.to_s.capitalize
            },
            "#{epic_name_filed_key}": epic_name,
            description: description
          }
        }

        http_body[:fields].merge!(additional_fields[:fields])

        rest_call(
          http_method: :post,
          base_api_uri: base_api_uri,
          token: token,
          rest_call: "issue/#{issue}",
          http_body: http_body
        )
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
          all_fields = #{self}.get_all_fields(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - bearer token'
          )

          issue_resp = #{self}.get_issue(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - bearer token',
            issue: 'required - issue to lookup (e.g. Bug, Issue, Story, or Epic ID)',
            params: 'optional - additional parameters to pass in the URI'
          )

          issue_resp = #{self}.create_issue(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - bearer token',
            project_key: 'required - project key (e.g. PWN)',
            summary: 'required - summary of the issue (e.g. Epic for PWN-1337)',
            issue_type: 'required - issue type (e.g. :epic, :story, :bug)',
            description: 'optional - description of the issue',
            additional_fields: 'optional - additional fields to set in the issue (e.g. labels, components, custom fields, etc.)'
          )

          **********************************************************************
          * For more information on the Jira Server REST API, see:
          * https://developer.atlassian.com/server/jira/platform/rest-apis/

          #{self}.authors
        "
      end
    end
  end
end
