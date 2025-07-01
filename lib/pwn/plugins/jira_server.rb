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
      #   token: 'required - personal access token',
      #   http_method: 'optional HTTP method (defaults to GET)',
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.rest_call(opts = {})
        token = opts[:token]
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        headers = opts[:http_headers] ||= {
          content_type: 'application/json; charset=UTF-8',
          authorization: "Bearer #{token}"
        }

        http_body = opts[:http_body]
        base_api_uri = opts[:base_api_uri]

        raise 'ERROR: base_api_uri cannot be nil.' if base_api_uri.nil?

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        spinner = TTY::Spinner.new
        spinner.auto_spin

        max_request_attempts = 3
        tot_request_attempts ||= 1

        case http_method
        when :delete, :get
          headers[:params] = params
          response = rest_client.execute(
            method: http_method,
            url: "#{base_api_uri}/#{rest_call}",
            headers: headers,
            verify_ssl: false,
            timeout: 180
          )

        when :post, :put
          if http_body.is_a?(Hash)
            if http_body.key?(:multipart)
              headers[:content_type] = 'multipart/form-data'
              headers[:x_atlassian_token] = 'no-check'
            else
              http_body = http_body.to_json
            end
          end

          response = rest_client.execute(
            method: http_method,
            url: "#{base_api_uri}/#{rest_call}",
            headers: headers,
            payload: http_body,
            verify_ssl: false,
            timeout: 180
          )
        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end

        jira_response = response if response.is_a?(RestClient::Response) && response.code == 204
        jira_response = JSON.parse(response, symbolize_names: true) if response.is_a?(RestClient::Response) && response.code != 204

        jira_response
      rescue RestClient::ExceptionWithResponse => e
        if e.response
          puts "HTTP BASE URL: #{base_api_uri}"
          puts "HTTP PATH: #{rest_call}"
          puts "HTTP RESPONSE CODE: #{e.response.code}"
          puts "HTTP RESPONSE HEADERS: #{e.response.headers}"
          puts "HTTP RESPONSE BODY:\n#{e.response.body}\n\n\n"
        end

        raise e
      rescue IO::TimeoutError => e
        raise e if tot_request_attempts == max_request_attempts

        tot_request_attempts += 1
        @@logger.warn("Timeout Error: Retrying request (Attempt #{tot_request_attempts}/#{max_request_attempts})")
        sleep(2)
        retry
      rescue Errno::ECONNREFUSED => e
        raise e if tot_request_attempts == max_request_attempts

        puts "\nTCP Connection Unavailable."
        puts "Attempt (#{tot_request_attempts} of #{max_request_attempts}) in 60s"
        60.downto(1) do
          print '.'
          sleep 1
        end
        tot_request_attempts += 1

        retry
      rescue StandardError => e
        raise e
      ensure
        spinner.stop unless spinner.nil?
      end

      # Supported Method Parameters::
      # all_fields = PWN::Plugins::JiraServer.get_all_fields(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - personal access token'
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
      # user = PWN::Plugins::JiraServer.get_user(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - personal access token',
      #   username: 'required - username to lookup (e.g. jane.doe)',
      #   params: 'optional - additional parameters to pass in the URI (e.g. expand, etc.)'
      # )

      public_class_method def self.get_user(opts = {})
        base_api_uri = opts[:base_api_uri]

        token = opts[:token]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Personal Access Token'
        )

        username = opts[:username]
        raise 'ERROR: username cannot be nil.' if username.nil?

        params = { key: username }
        additional_params = opts[:params]

        params.merge!(additional_params) if additional_params.is_a?(Hash)

        rest_call(
          base_api_uri: base_api_uri,
          token: token,
          rest_call: 'user',
          params: params
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.get_issue(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - personal access token',
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
      #   token: 'required - personal access token',
      #   project_key: 'required - project key (e.g. PWN)',
      #   summary: 'required - summary of the issue (e.g. Epic for PWN-1337)',
      #   issue_type: 'required - issue type (e.g. :epic, :story, :bug)',
      #   description: 'optional - description of the issue',
      #   epic_name: 'optional - name of the epic',
      #   additional_fields: 'optional - additional fields to set in the issue (e.g. labels, components, custom fields, etc.)'
      #   attachments: 'optional - array of attachment paths to upload to the issue (e.g. ["/path/to/file1.txt", "/path/to/file2.png"])'
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

        description = opts[:description].to_s.scrub

        additional_fields = opts[:additional_fields] ||= { fields: {} }
        raise 'ERROR: additional_fields Hash must contain a :fields key that is also a Hash.' unless additional_fields.is_a?(Hash) && additional_fields.key?(:fields) && additional_fields[:fields].is_a?(Hash)

        attachments = opts[:attachments] ||= []
        raise 'ERROR: attachments must be an Array.' unless attachments.is_a?(Array)

        all_fields = get_all_fields(base_api_uri: base_api_uri, token: token)
        epic_name_field_key = all_fields.find { |field| field[:name] == 'Epic Name' }[:id]

        epic_name = opts[:epic_name]

        http_body = {
          fields: {
            project: {
              key: project_key
            },
            summary: summary,
            issuetype: {
              name: issue_type.to_s.capitalize
            },
            "#{epic_name_field_key}": epic_name,
            description: description
          }
        }

        http_body[:fields].merge!(additional_fields[:fields])

        issue_resp = rest_call(
          http_method: :post,
          base_api_uri: base_api_uri,
          token: token,
          rest_call: 'issue',
          http_body: http_body
        )

        if attachments.any?
          issue = issue_resp[:key]

          http_body = {
            multipart: true,
            file: attachments.map { |attachment| File.binread(attachment) }
          }

          rest_call(
            http_method: :post,
            base_api_uri: base_api_uri,
            token: token,
            rest_call: "issue/#{issue}/attachments",
            http_body: http_body
          )
        end

        issue_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.update_issue(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - personal access token',
      #   fields: 'required - fields to update in the issue (e.g. summary, description, labels, components, custom fields, etc.)',
      #   attachments: 'optional - array of attachment paths to upload to the issue (e.g. ["/path/to/file1.txt", "/path/to/file2.png"])'
      # )

      public_class_method def self.update_issue(opts = {})
        base_api_uri = opts[:base_api_uri]

        token = opts[:token]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Personal Access Token'
        )
        issue = opts[:issue]
        raise 'ERROR: project_key cannot be nil.' if issue.nil?

        fields = opts[:fields] ||= { fields: {} }
        raise 'ERROR: fields Hash must contain a :fields key that is also a Hash.' unless fields.is_a?(Hash) && fields.key?(:fields) && fields[:fields].is_a?(Hash)

        attachments = opts[:attachments] ||= []

        http_body = fields

        issue_resp = rest_call(
          http_method: :put,
          base_api_uri: base_api_uri,
          token: token,
          rest_call: "issue/#{issue}",
          http_body: http_body
        )

        if attachments.any?
          http_body = {
            multipart: true,
            file: attachments.map { |attachment| File.binread(attachment) }
          }

          rest_call(
            http_method: :post,
            base_api_uri: base_api_uri,
            token: token,
            rest_call: "issue/#{issue}/attachments",
            http_body: http_body
          )
        end

        issue_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.delete_issue(
      #   base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
      #   token: 'required - personal access token',
      #   issue: 'required - issue to delete (e.g. Bug, Issue, Story, or Epic ID)'
      # )

      public_class_method def self.delete_issue(opts = {})
        base_api_uri = opts[:base_api_uri]

        token = opts[:token]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Personal Access Token'
        )

        issue = opts[:issue]

        raise 'ERROR: issue cannot be nil.' if issue.nil?

        rest_call(
          http_method: :delete,
          base_api_uri: base_api_uri,
          token: token,
          rest_call: "issue/#{issue}"
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
            token: 'required - personal access token'
          )

          user = #{self}.get_user(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - personal access token',
            username: 'required - username to lookup (e.g. jane.doe')',
            params: 'optional - additional parameters to pass in the URI (e.g. expand, etc.)'
          )

          issue_resp = #{self}.get_issue(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - personal access token',
            issue: 'required - issue to lookup (e.g. Bug, Issue, Story, or Epic ID)',
            params: 'optional - additional parameters to pass in the URI'
          )

          issue_resp = #{self}.create_issue(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - personal access token',
            project_key: 'required - project key (e.g. PWN)',
            summary: 'required - summary of the issue (e.g. Epic for PWN-1337)',
            issue_type: 'required - issue type (e.g. :epic, :story, :bug)',
            description: 'optional - description of the issue',
            epic_name: 'optional - name of the epic',
            additional_fields: 'optional - additional fields to set in the issue (e.g. labels, components, custom fields, etc.)',
            attachments: 'optional - array of attachment paths to upload to the issue (e.g. [\"/path/to/file1.txt\", \"/path/to/file2.png\"])'
          )

          issue_resp = #{self}.update_issue(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - personal access token',
            issue: 'required - issue to update (e.g. Bug, Issue, Story, or Epic ID)',
            fields: 'required - fields to update in the issue (e.g. summary, description, labels, components, custom fields, etc.)',
            attachments: 'optional - array of attachment paths to upload to the issue (e.g. [\"/path/to/file1.txt\", \"/path/to/file2.png\"])'
          )

          issue_resp = #{self}.delete_issue(
            base_api_uri: 'required - base URI for Jira (e.g. https:/jira.corp.com/rest/api/latest)',
            token: 'required - personal access token',
            issue: 'required - issue to delete (e.g. Bug, Issue, Story, or Epic ID)'
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
