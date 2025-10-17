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
        jserver = PWN::Env[:plugins][:jira_server]
        raise 'ERROR: Jira Server Hash not found in PWN::Env.  Run i`pwn -Y default.yaml`, then `PWN::Env` for usage.' if jserver.nil?

        base_uri = jserver[:base_uri]
        token = jserver[:token]

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

        raise 'ERROR: base_uri cannot be nil.' if base_uri.nil?

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
            url: "#{base_uri}/#{rest_call}",
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
            url: "#{base_uri}/#{rest_call}",
            headers: headers,
            payload: http_body,
            verify_ssl: false,
            timeout: 180
          )
        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end

        case response.code
        when 201, 204
          response = { http_response_code: response.code }
        else
          response = JSON.parse(response, symbolize_names: true) if response.is_a?(RestClient::Response)
          response[:http_response_code] = response.code if response.is_a?(RestClient::Response)
        end

        response
      rescue RestClient::ExceptionWithResponse => e
        if e.response
          puts "HTTP BASE URL: #{base_uri}"
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
      # all_fields = PWN::Plugins::JiraServer.get_all_fields

      public_class_method def self.get_all_fields
        rest_call(rest_call: 'field')
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # user = PWN::Plugins::JiraServer.get_user(
      #   username: 'required - username to lookup (e.g. jane.doe)',
      #   params: 'optional - additional parameters to pass in the URI (e.g. expand, etc.)'
      # )

      public_class_method def self.get_user(opts = {})
        username = opts[:username] || PWN::Plugins::AuthenticationHelper.username
        raise 'ERROR: username cannot be nil.' if username.nil?

        params = { key: username }
        additional_params = opts[:params]

        params.merge!(additional_params) if additional_params.is_a?(Hash)

        rest_call(
          rest_call: 'user',
          params: params
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.get_issue(
      #   issue: 'required - issue to lookup (e.g. Bug, Issue, Story, or Epic ID)',
      #   params: 'optional - additional parameters to pass in the URI (e.g. fields, expand, etc.)'
      # )

      public_class_method def self.get_issue(opts = {})
        issue = opts[:issue]
        params = opts[:params]

        raise 'ERROR: issue cannot be nil.' if issue.nil?

        rest_call(
          rest_call: "issue/#{issue}",
          params: params
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.create_issue(
      #   project_key: 'required - project key (e.g. PWN)',
      #   summary: 'required - summary of the issue (e.g. Epic for PWN-1337)',
      #   issue_type: 'required - issue type (e.g. :epic, :story, :bug)',
      #   description: 'optional - description of the issue',
      #   epic_name: 'optional - name of the epic',
      #   additional_fields: 'optional - additional fields to set in the issue (e.g. labels, components, custom fields, etc.)'
      #   attachments: 'optional - array of attachment paths to upload to the issue (e.g. ["/tmp/file1.txt", "/tmp/file2.txt"])',
      #   comment: 'optional - comment to add to the issue (e.g. "This is a comment")'
      # )

      public_class_method def self.create_issue(opts = {})
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

        comment = opts[:comment]

        all_fields = get_all_fields
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
          rest_call: 'issue',
          http_body: http_body
        )
        issue = issue_resp[:key]

        if attachments.any?
          attachments.each do |attachment|
            raise "ERROR: #{attachment} not found." unless File.exist?(attachment)

            http_body = {
              multipart: true,
              file: File.new(attachment, 'rb')
            }

            rest_call(
              http_method: :post,
              rest_call: "issue/#{issue}/attachments",
              http_body: http_body
            )
          end
        end

        if comment
          issue_comment(
            issue: issue,
            comment_action: :add,
            comment: comment
          )
        end

        get_issue(issue: issue)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.update_issue(
      #   fields: 'required - fields to update in the issue (e.g. summary, description, labels, components, custom fields, etc.)',
      #   attachments: 'optional - array of attachment paths to upload to the issue (e.g. ["/tmp/file1.txt", "/tmp/file2.txt"])',
      # )

      public_class_method def self.update_issue(opts = {})
        issue = opts[:issue]
        raise 'ERROR: project_key cannot be nil.' if issue.nil?

        fields = opts[:fields] ||= { fields: {} }
        raise 'ERROR: fields Hash must contain a :fields key that is also a Hash.' unless fields.is_a?(Hash) && fields.key?(:fields) && fields[:fields].is_a?(Hash)

        attachments = opts[:attachments] ||= []
        raise 'ERROR: attachments must be an Array.' unless attachments.is_a?(Array)

        http_body = fields

        rest_call(
          http_method: :put,
          rest_call: "issue/#{issue}",
          http_body: http_body
        )

        if attachments.any?
          attachments.each do |attachment|
            raise "ERROR: #{attachment} not found." unless File.exist?(attachment)

            http_body = {
              multipart: true,
              file: File.new(attachment, 'rb')
            }

            rest_call(
              http_method: :post,
              rest_call: "issue/#{issue}/attachments",
              http_body: http_body
            )
          end
        end

        get_issue(
          issue: issue
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.issue_comment(
      #   issue: 'required - issue to delete (e.g. Bug, Issue, Story, or Epic ID)',
      #   comment_action: 'required - action to perform on the issue comment (e.g. :delete, :add, :update - Defaults to :add)',
      #   comment_id: 'optional - comment ID to delete or update (e.g. 10000)',
      #   author: 'optional - author of the comment (e.g. "jane.doe")',
      #   comment: 'optional - comment to add or update in the issue (e.g. "This is a comment")'
      # )

      public_class_method def self.issue_comment(opts = {})
        issue = opts[:issue]
        raise 'ERROR: issue cannot be nil.' if issue.nil?

        comment_action = opts[:comment_action] ||= :add
        raise 'ERROR: comment_action must be one of :delete, :add, or :update.' unless %i[delete add update].include?(comment_action)

        comment_id = opts[:comment_id]
        raise 'ERROR: comment_id cannot be nil when comment_action is :delete or :update.' unless %i[delete update].include?(comment_action) || comment_id.nil?

        author = opts[:author]
        comment = opts[:comment].to_s.scrub

        case comment_action
        when :add
          http_method = :post
          rest_call = "issue/#{issue}/comment"
          http_body = { body: comment }
          http_body[:author] = { key: author } if author
        when :delete
          http_method = :delete
          rest_call = "issue/#{issue}/comment/#{comment_id}"
          http_body = nil
        when :update
          http_method = :put
          rest_call = "issue/#{issue}/comment/#{comment_id}"
          http_body = { body: comment }
          http_body[:author] = { key: author } if author
        end

        rest_call(
          http_method: http_method,
          rest_call: rest_call,
          http_body: http_body
        )

        get_issue(issue: issue)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.delete_issue(
      #   issue: 'required - issue to delete (e.g. Bug, Issue, Story, or Epic ID)'
      # )

      public_class_method def self.delete_issue(opts = {})
        issue = opts[:issue]
        raise 'ERROR: issue cannot be nil.' if issue.nil?

        rest_call(
          http_method: :delete,
          rest_call: "issue/#{issue}"
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # issue_resp = PWN::Plugins::JiraServer.delete_attachment(
      #   id: 'required - attachment ID to delete (e.g. 10000) found in #get_issue method'
      # )

      public_class_method def self.delete_attachment(opts = {})
        id = opts[:id]
        raise 'ERROR: attachment_id cannot be nil.' if id.nil?

        rest_call(
          http_method: :delete,
          rest_call: "attachment/#{id}"
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
          all_fields = #{self}.get_all_fields

          user = #{self}.get_user(
            username: 'required - username to lookup (e.g. jane.doe')',
            params: 'optional - additional parameters to pass in the URI (e.g. expand, etc.)'
          )

          issue_resp = #{self}.get_issue(
            issue: 'required - issue to lookup (e.g. Bug, Issue, Story, or Epic ID)',
            params: 'optional - additional parameters to pass in the URI'
          )

          issue_resp = #{self}.create_issue(
            project_key: 'required - project key (e.g. PWN)',
            summary: 'required - summary of the issue (e.g. Epic for PWN-1337)',
            issue_type: 'required - issue type (e.g. :epic, :story, :bug)',
            description: 'optional - description of the issue',
            epic_name: 'optional - name of the epic',
            additional_fields: 'optional - additional fields to set in the issue (e.g. labels, components, custom fields, etc.)',
            attachments: 'optional - array of attachment paths to upload to the issue (e.g. [\"/tmp/file1.txt\", \"/tmp/file2.txt\"])',
            comment: 'optional - comment to add to the issue (e.g. \"This is a comment\")'
          )

          issue_resp = #{self}.update_issue(
            issue: 'required - issue to update (e.g. Bug, Issue, Story, or Epic ID)',
            fields: 'required - fields to update in the issue (e.g. summary, description, labels, components, custom fields, etc.)',
            attachments: 'optional - array of attachment paths to upload to the issue (e.g. [\"/tmp/file1.txt\", \"/tmp/file2.txt\"])'
          )

          issue_resp = #{self}.issue_comment(
            issue: 'required - issue to comment on (e.g. Bug, Issue, Story, or Epic ID)',
            comment_action: 'required - action to perform on the issue comment (e.g. :delete, :add, :update - Defaults to :add)',
            comment_id: 'optional - comment ID to delete or update (e.g. 10000)',
            author: 'optional - author of the comment (e.g. \"jane.doe\")',
            comment: 'optional - comment to add or update in the issue (e.g. \"This is a comment\")'
          )

          issue_resp = #{self}.delete_issue(
            issue: 'required - issue to delete (e.g. Bug, Issue, Story, or Epic ID)'
          )

          issue_resp = #{self}.delete_attachment(
            id: 'required - attachment ID to delete (e.g. 10000) found in #get_issue method'
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
