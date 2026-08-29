# frozen_string_literal: true

require 'base64'
require 'json'
require 'rest-client'

module PWN
  module Plugins
    # This plugin is used for interacting w/ HackerOne's Hacker REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    #
    # Spec: https://api.hackerone.com/getting-started-hacker-api/#getting-started-hacker-api
    #
    # Auth: HTTP Basic on every request (username + API token).
    # Base: https://api.hackerone.com/v1/hackers/
    #
    # Credentials are sourced from PWN::Env[:plugins][:hackerone]:
    #   plugins:
    #     hackerone:
    #       username: your-h1-username
    #       api_key:  your-h1-api-token
    module HackerOne
      @@logger = PWN::Plugins::PWNLogger.create

      BASE_H1_API_URI = 'https://api.hackerone.com/v1/hackers'

      # Resolve username: explicit opt -> PWN::Env -> ENV
      private_class_method def self.resolve_username(opts = {})
        opts[:username] ||
          PWN::Env.dig(:plugins, :hackerone, :username) ||
          ENV.fetch('HACKERONE_USERNAME', nil)
      end

      # Resolve API token: explicit opt -> PWN::Env -> ENV
      # Accepts :api_key, :token, or :api_token aliases.
      private_class_method def self.resolve_api_key(opts = {})
        opts[:api_key] ||
          opts[:token] ||
          opts[:api_token] ||
          PWN::Env.dig(:plugins, :hackerone, :api_key) ||
          PWN::Env.dig(:plugins, :hackerone, :token) ||
          ENV.fetch('HACKERONE_API_KEY', nil) ||
          ENV.fetch('HACKERONE_TOKEN', nil)
      end

      # Supported Method Parameters::
      # h1_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)',
      #   rest_call: 'required rest path relative to /v1/hackers (e.g. "me/reports")',
      #   params: 'optional query params Hash',
      #   http_body: 'optional HTTP body (Hash/Array auto-JSONified; String passed through)',
      #   username: 'optional - HackerOne username (default PWN::Env)',
      #   api_key: 'optional - HackerOne API token (default PWN::Env)',
      #   raw: 'optional - return raw RestClient::Response (default false)'
      # )

      private_class_method def self.h1_rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub.sub(%r{\A/}, '')
        params = opts[:params]
        http_body = opts[:http_body]
        http_body = http_body.to_json if http_body.is_a?(Hash) || http_body.is_a?(Array)
        raw = opts[:raw]

        username = resolve_username(opts).to_s.scrub
        api_key = resolve_api_key(opts).to_s.scrub
        raise 'ERROR: HackerOne username missing - set plugins.hackerone.username in ~/.pwn/pwn.yaml' if username.empty?
        raise 'ERROR: HackerOne api_key missing - set plugins.hackerone.api_key in ~/.pwn/pwn.yaml' if api_key.empty?

        basic_auth_header = "Basic #{Base64.strict_encode64("#{username}:#{api_key}")}"

        headers = {
          authorization: basic_auth_header,
          accept: 'application/json',
          content_type: 'application/json; charset=UTF-8'
        }
        headers[:params] = params if params

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        url = rest_call.empty? ? BASE_H1_API_URI : "#{BASE_H1_API_URI}/#{rest_call}"

        response = rest_client.execute(
          method: http_method,
          url: url,
          headers: headers,
          payload: http_body,
          verify_ssl: false
        )

        return response if raw

        JSON.parse(response.body, symbolize_names: true)
      rescue ::RestClient::TooManyRequests
        @@logger.warn('HackerOne rate limit (429). Sleeping 10s then retrying...')
        sleep 10
        retry
      rescue ::RestClient::Unauthorized, ::RestClient::Forbidden,
             ::RestClient::BadRequest, ::RestClient::NotFound,
             ::RestClient::UnprocessableEntity => e
        @@logger.error("HackerOne #{e.class}: #{e.response&.body}")
        raise e
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # h1_obj = PWN::Plugins::HackerOne.login(
      #   username: 'optional - username (default PWN::Env[:plugins][:hackerone][:username])',
      #   api_key: 'optional - api token (default PWN::Env; will prompt if still nil)',
      #   token: 'optional - alias for api_key'
      # )
      # Backward-compatible session object. Auth is HTTP Basic on every subsequent
      # call; login simply resolves + validates credentials against me/reports.

      public_class_method def self.login(opts = {})
        username = resolve_username(opts)
        api_key = resolve_api_key(opts)

        api_key = PWN::Plugins::AuthenticationHelper.mask_password if api_key.nil? || api_key.to_s.empty?

        username = username.to_s.scrub
        api_key = api_key.to_s.scrub
        raise 'ERROR: HackerOne username required' if username.empty?
        raise 'ERROR: HackerOne api_key required' if api_key.empty?

        @@logger.info("Validating HackerOne Hacker API credentials for #{username}")
        # Prefer a cheap authenticated endpoint (balance is small; me/reports is list)
        h1_rest_call(
          rest_call: 'payments/balance',
          username: username,
          api_key: api_key
        )

        {
          username: username,
          api_key: api_key,
          base_h1_api_uri: BASE_H1_API_URI
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::HackerOne.api(
      #   path: 'required - path relative to /v1/hackers (e.g. "me/reports")',
      #   method: 'optional - :get|:post|:put|:patch|:delete (default :get)',
      #   params: 'optional - query params Hash',
      #   body: 'optional - request body Hash/Array/String',
      #   username: 'optional',
      #   api_key: 'optional',
      #   h1_obj: 'optional - session from #login (supplies username/api_key)',
      #   raw: 'optional - return raw response (default false)'
      # )

      public_class_method def self.api(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          http_method: opts[:method] || opts[:http_method] || :get,
          rest_call: opts[:path].to_s.delete_prefix('/'),
          params: opts[:params],
          http_body: opts[:body] || opts[:http_body],
          username: creds[:username],
          api_key: creds[:api_key],
          raw: opts[:raw]
        )
      rescue StandardError => e
        raise e
      end

      # Pull username/api_key from opts or h1_obj session.
      private_class_method def self.creds_from(opts = {})
        h1_obj = opts[:h1_obj] || {}
        {
          username: opts[:username] || h1_obj[:username],
          api_key: opts[:api_key] || opts[:token] || opts[:api_token] || h1_obj[:api_key] || h1_obj[:token]
        }
      end

      # ---- Reports -------------------------------------------------------

      # Supported Method Parameters::
      # reports = PWN::Plugins::HackerOne.get_me_reports(
      #   params: 'optional - query params Hash (e.g. page/filter)',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_me_reports(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          rest_call: 'me/reports',
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # report = PWN::Plugins::HackerOne.get_report(
      #   id: 'required - report id',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_report(opts = {})
        id = opts[:id]
        raise 'ERROR: report id required' if id.nil? || id.to_s.empty?

        creds = creds_from(opts)
        h1_rest_call(
          rest_call: "reports/#{id}",
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # report = PWN::Plugins::HackerOne.create_report(
      #   team_handle: 'required - program handle',
      #   title: 'required - report title',
      #   vulnerability_information: 'required - detailed description',
      #   impact: 'optional - impact text',
      #   severity_rating: 'optional - none|low|medium|high|critical',
      #   weakness_id: 'optional - weakness id integer',
      #   structured_scope_id: 'optional - structured scope id',
      #   body: 'optional - full JSON:API body Hash (overrides attribute kwargs)',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.create_report(opts = {})
        creds = creds_from(opts)
        http_body = opts[:body]
        if http_body.nil?
          attrs = {
            team_handle: opts[:team_handle],
            title: opts[:title],
            vulnerability_information: opts[:vulnerability_information]
          }
          attrs[:impact] = opts[:impact] if opts.key?(:impact)
          attrs[:severity_rating] = opts[:severity_rating] if opts.key?(:severity_rating)
          attrs[:weakness_id] = opts[:weakness_id] if opts.key?(:weakness_id)
          attrs[:structured_scope_id] = opts[:structured_scope_id] if opts.key?(:structured_scope_id)

          raise 'ERROR: team_handle required' if attrs[:team_handle].to_s.empty?
          raise 'ERROR: title required' if attrs[:title].to_s.empty?
          raise 'ERROR: vulnerability_information required' if attrs[:vulnerability_information].to_s.empty?

          http_body = {
            data: {
              type: 'report',
              attributes: attrs
            }
          }
        end

        h1_rest_call(
          http_method: :post,
          rest_call: 'reports',
          http_body: http_body,
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # ---- Payments ------------------------------------------------------

      # Supported Method Parameters::
      # balance = PWN::Plugins::HackerOne.get_balance(
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_balance(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          rest_call: 'payments/balance',
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # earnings = PWN::Plugins::HackerOne.get_earnings(
      #   params: 'optional - query params Hash',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_earnings(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          rest_call: 'payments/earnings',
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # payouts = PWN::Plugins::HackerOne.get_payouts(
      #   params: 'optional - query params Hash',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_payouts(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          rest_call: 'payments/payouts',
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # ---- Programs -------------------------------------------------------

      # Supported Method Parameters::
      # programs = PWN::Plugins::HackerOne.get_programs(
      #   params: 'optional - query params Hash',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_programs(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          rest_call: 'programs',
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # program = PWN::Plugins::HackerOne.get_program(
      #   handle: 'required - program handle',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_program(opts = {})
        handle = opts[:handle].to_s.scrub
        raise 'ERROR: program handle required' if handle.empty?

        creds = creds_from(opts)
        h1_rest_call(
          rest_call: "programs/#{handle}",
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # scopes = PWN::Plugins::HackerOne.get_structured_scopes(
      #   handle: 'required - program handle',
      #   params: 'optional',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_structured_scopes(opts = {})
        handle = opts[:handle].to_s.scrub
        raise 'ERROR: program handle required' if handle.empty?

        creds = creds_from(opts)
        h1_rest_call(
          rest_call: "programs/#{handle}/structured_scopes",
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # exclusions = PWN::Plugins::HackerOne.get_scope_exclusions(
      #   handle: 'required - program handle',
      #   params: 'optional',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_scope_exclusions(opts = {})
        handle = opts[:handle].to_s.scrub
        raise 'ERROR: program handle required' if handle.empty?

        creds = creds_from(opts)
        h1_rest_call(
          rest_call: "programs/#{handle}/scope_exclusions",
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # weaknesses = PWN::Plugins::HackerOne.get_weaknesses(
      #   handle: 'required - program handle',
      #   params: 'optional',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_weaknesses(opts = {})
        handle = opts[:handle].to_s.scrub
        raise 'ERROR: program handle required' if handle.empty?

        creds = creds_from(opts)
        h1_rest_call(
          rest_call: "programs/#{handle}/weaknesses",
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # ---- Hacktivity -----------------------------------------------------

      # Supported Method Parameters::
      # items = PWN::Plugins::HackerOne.get_hacktivity(
      #   params: 'optional - query params Hash',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_hacktivity(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          rest_call: 'hacktivity',
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # ---- Report Intents ------------------------------------------------

      # Supported Method Parameters::
      # intents = PWN::Plugins::HackerOne.get_report_intents(
      #   params: 'optional',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_report_intents(opts = {})
        creds = creds_from(opts)
        h1_rest_call(
          rest_call: 'report_intents',
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # intent = PWN::Plugins::HackerOne.get_report_intent(
      #   id: 'required - report intent id',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_report_intent(opts = {})
        id = opts[:id]
        raise 'ERROR: report intent id required' if id.nil? || id.to_s.empty?

        creds = creds_from(opts)
        h1_rest_call(
          rest_call: "report_intents/#{id}",
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # intent = PWN::Plugins::HackerOne.create_report_intent(
      #   body: 'required - full JSON:API body Hash',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.create_report_intent(opts = {})
        body = opts[:body]
        raise 'ERROR: body required for create_report_intent' if body.nil?

        creds = creds_from(opts)
        h1_rest_call(
          http_method: :post,
          rest_call: 'report_intents',
          http_body: body,
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # intent = PWN::Plugins::HackerOne.update_report_intent(
      #   id: 'required - report intent id',
      #   body: 'required - full JSON:API body Hash',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.update_report_intent(opts = {})
        id = opts[:id]
        body = opts[:body]
        raise 'ERROR: report intent id required' if id.nil? || id.to_s.empty?
        raise 'ERROR: body required for update_report_intent' if body.nil?

        creds = creds_from(opts)
        h1_rest_call(
          http_method: :put,
          rest_call: "report_intents/#{id}",
          http_body: body,
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # result = PWN::Plugins::HackerOne.delete_report_intent(
      #   id: 'required - report intent id',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.delete_report_intent(opts = {})
        id = opts[:id]
        raise 'ERROR: report intent id required' if id.nil? || id.to_s.empty?

        creds = creds_from(opts)
        h1_rest_call(
          http_method: :delete,
          rest_call: "report_intents/#{id}",
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # result = PWN::Plugins::HackerOne.submit_report_intent(
      #   id: 'required - report intent id',
      #   body: 'optional - JSON:API body Hash',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.submit_report_intent(opts = {})
        id = opts[:id]
        raise 'ERROR: report intent id required' if id.nil? || id.to_s.empty?

        creds = creds_from(opts)
        h1_rest_call(
          http_method: :post,
          rest_call: "report_intents/#{id}/submit",
          http_body: opts[:body],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # attachments = PWN::Plugins::HackerOne.get_report_intent_attachments(
      #   report_intent_id: 'required - report intent id',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.get_report_intent_attachments(opts = {})
        rid = opts[:report_intent_id] || opts[:id]
        raise 'ERROR: report_intent_id required' if rid.nil? || rid.to_s.empty?

        creds = creds_from(opts)
        h1_rest_call(
          rest_call: "report_intents/#{rid}/attachments",
          params: opts[:params],
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # result = PWN::Plugins::HackerOne.delete_report_intent_attachment(
      #   report_intent_id: 'required - report intent id',
      #   id: 'required - attachment id',
      #   username: 'optional', api_key: 'optional', h1_obj: 'optional'
      # )

      public_class_method def self.delete_report_intent_attachment(opts = {})
        rid = opts[:report_intent_id]
        id = opts[:id]
        raise 'ERROR: report_intent_id required' if rid.nil? || rid.to_s.empty?
        raise 'ERROR: attachment id required' if id.nil? || id.to_s.empty?

        creds = creds_from(opts)
        h1_rest_call(
          http_method: :delete,
          rest_call: "report_intents/#{rid}/attachments/#{id}",
          username: creds[:username],
          api_key: creds[:api_key]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::HackerOne.logout(
      #   h1_obj: 'required h1_obj returned from #login method'
      # )
      # Clears the session hash in-place (no server-side session to destroy).

      public_class_method def self.logout(opts = {})
        h1_obj = opts[:h1_obj]
        @@logger.info('Clearing HackerOne session object...')
        h1_obj.clear if h1_obj.respond_to?(:clear)
        nil
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
          # Run login and return its result
          #{self}.login(
            username: 'optional - username (default PWN::Env[:plugins][:hackerone][:username])',
            api_key: 'optional - api token (default PWN::Env; will prompt if still nil)',
            token: 'optional - alias for api_key'
          )

          # Run api and return its result
          #{self}.api(
            path: 'required - path relative to /v1/hackers (e.g. me/reports)',
            method: 'optional - :get|:post|:put|:patch|:delete (default :get)',
            params: 'optional - query params Hash',
            body: 'optional - request body Hash/Array/String (defaults to opts[:http_body])',
            username: 'optional - username value consumed by #api',
            api_key: 'optional - api key value consumed by #api',
            h1_obj: 'optional - session from #login (supplies username/api_key)',
            raw: 'optional - return raw response (default false)',
            http_method: 'optional - http method value consumed by #api (defaults to :get)',
            http_body: 'optional - http body value consumed by #api'
          )

          # ---- Reports -------------------------------------------------------
          #{self}.get_me_reports(
            params: 'optional - query params Hash (e.g. page/filter)',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get report and return its result
          #{self}.get_report(
            id: 'required - report id',
            username: 'optional - optional, api_key: optional, h1_obj: optional',
            params: 'optional - params value consumed by #get_report'
          )

          # Run create report and return its result
          #{self}.create_report(
            team_handle: 'required - program handle',
            title: 'required - report title',
            vulnerability_information: 'required - detailed description',
            impact: 'optional - impact text',
            severity_rating: 'optional - none|low|medium|high|critical',
            weakness_id: 'optional - weakness id integer',
            structured_scope_id: 'optional - structured scope id value consumed by #create_report',
            body: 'optional - full JSON:API body Hash (overrides attribute kwargs)',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # ---- Payments ------------------------------------------------------
          #{self}.get_balance(
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get earnings and return its result
          #{self}.get_earnings(
            params: 'optional - query params Hash',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get payouts and return its result
          #{self}.get_payouts(
            params: 'optional - query params Hash',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # ---- Programs -------------------------------------------------------
          #{self}.get_programs(
            params: 'optional - query params Hash',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get program and return its result
          #{self}.get_program(
            handle: 'required - program handle',
            username: 'optional - optional, api_key: optional, h1_obj: optional',
            params: 'optional - params value consumed by #get_program'
          )

          # Run get structured scopes and return its result
          #{self}.get_structured_scopes(
            handle: 'required - program handle',
            params: 'optional - params value consumed by #get_structured_scopes',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get scope exclusions and return its result
          #{self}.get_scope_exclusions(
            handle: 'required - program handle',
            params: 'optional - params value consumed by #get_scope_exclusions',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get weaknesses and return its result
          #{self}.get_weaknesses(
            handle: 'required - program handle',
            params: 'optional - params value consumed by #get_weaknesses',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # ---- Hacktivity -----------------------------------------------------
          #{self}.get_hacktivity(
            params: 'optional - query params Hash',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # ---- Report Intents ------------------------------------------------
          #{self}.get_report_intents(
            params: 'optional - params value consumed by #get_report_intents',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get report intent and return its result
          #{self}.get_report_intent(
            id: 'required - report intent id',
            username: 'optional - optional, api_key: optional, h1_obj: optional',
            params: 'optional - params value consumed by #get_report_intent'
          )

          # Run create report intent and return its result
          #{self}.create_report_intent(
            body: 'required - full JSON:API body Hash',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run update report intent and return its result
          #{self}.update_report_intent(
            id: 'required - report intent id',
            body: 'required - full JSON:API body Hash',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run delete report intent and return its result
          #{self}.delete_report_intent(
            id: 'required - report intent id',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run submit report intent and return its result
          #{self}.submit_report_intent(
            id: 'required - report intent id',
            body: 'optional - JSON:API body Hash',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Run get report intent attachments and return its result
          #{self}.get_report_intent_attachments(
            report_intent_id: 'required - report intent id value consumed by #get_report_intent_attachments (defaults to opts[:id])',
            username: 'optional - optional, api_key: optional, h1_obj: optional',
            id: 'required - id value consumed by #get_report_intent_attachments',
            params: 'optional - params value consumed by #get_report_intent_attachments'
          )

          # Run delete report intent attachment and return its result
          #{self}.delete_report_intent_attachment(
            report_intent_id: 'required - report intent id value consumed by #delete_report_intent_attachment',
            id: 'required - attachment id',
            username: 'optional - optional, api_key: optional, h1_obj: optional'
          )

          # Clears the session hash in-place (no server-side session to destroy)
          #{self}.logout(
            h1_obj: 'required - required h1_obj returned from #login method'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
