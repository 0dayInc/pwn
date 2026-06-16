# frozen_string_literal: true

require 'json'
require 'rest-client'
require 'tty-spinner'
require 'uri'
require 'base64'

module PWN
  module AI
    # This plugin interacts with xAI's Grok API, similar to the Grok plugin.
    # It provides methods to list models, generate completions, and chat.
    # API documentation: https://docs.x.ai/docs
    # Obtain an API key from https://x.ai/api
    module Grok
      # Supported Method Parameters::
      # bearer = PWN::AI::Grok.obtain_oauth_bearer_token(
      #   client_id: 'xAI OAuth Client ID',
      #   client_secret: 'xAI OAuth Client Secret'
      #   token_uri: 'optional - xAI OAuth token endpoint (defaults to https://auth.x.ai/oauth2/token)'
      # )
      #
      # Internal: only invoked when oauth config (client_id etc) is present and no valid bearer_token.
      # Constructs the authorize URL (https://auth.x.ai/oauth2/authorize) for the user to complete
      # consent in browser (standard for authorization_code flow). Prompts for the code returned
      # after redirect (OOB), then exchanges at token_uri for the bearer_token.
      # This fulfills calling the authorize endpoint (via URL) only when oauth configured.
      # Uses xAI's supported scopes like grok-cli:access. Stores result in the oauth hash for the session.
      # Supported Method Parameters::
      # bearer = PWN::AI::Grok.obtain_oauth_bearer_token(
      #   client_id: 'xAI OAuth Client ID',
      #   client_secret: 'xAI OAuth Client Secret',
      #   token_uri: 'optional - xAI OAuth token endpoint (defaults to https://auth.x.ai/oauth2/token)'
      # )
      #
      # Public so users can manually trigger enrollment if desired.
      # INTERNAL default path: only invoked from grok_rest_call when oauth client_id+secret present
      # and no bearer_token yet in the loaded PWN::Env (from pwn-vault encrypted ~/.pwn/pwn.yaml).
      #
      # This is a SINGULAR ENROLLMENT process (not per-call or per-session).
      # The resulting bearer_token (and optional refresh_token) is long-lived for xAI SuperGrok
      # subscriptions. Once you store it in your pwn-vault config, every future `pwn` / PWN::Env load
      # will have it; the guard will skip this flow entirely and use "Authorization: Bearer ..." directly.
      # (No re-prompting every time you run pwn or call PWN::AI::Grok.chat.)
      public_class_method def self.obtain_oauth_bearer_token(opts = {})
        client_id = opts[:client_id]
        client_secret = opts[:client_secret]

        scope = 'grok-cli:access'
        redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
        auth_uri = 'https://auth.x.ai/oauth2/authorize'
        token_uri = opts[:token_uri] || 'https://auth.x.ai/oauth2/token'

        # Build authorize URL -- this is the "call" to the authorize endpoint (user opens to consent)
        params = {
          client_id: client_id,
          response_type: 'code',
          scope: scope,
          redirect_uri: redirect_uri
        }
        authorize_url = "#{auth_uri}?#{URI.encode_www_form(params)}"

        puts "\n[*] OAuth ENROLLMENT for Grok (xAI SuperGrok subscription)."
        puts '    This is a ONE-TIME / SINGULAR enrollment process.'
        puts '    The bearer_token you receive is LONG-LIVED (store it once; no re-obtain every call or run).'
        puts ''
        puts '    Step 1: Open this URL in your browser and complete the authorization/consent for the grok-cli app:'
        puts "            #{authorize_url}"
        puts ''
        puts '    Step 2: After consent you will see (or be redirected to) an authorization code. Copy it exactly.'
        puts ''

        code = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Enter the authorization code from xAI OAuth')

        # Exchange code for bearer at token endpoint.
        # Use standard confidential client auth: Authorization: Basic base64(client_id:client_secret)
        # + client_id in body (secret NOT in body).
        basic = "Basic #{Base64.strict_encode64("#{client_id}:#{client_secret}")}"
        payload = {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: redirect_uri,
          client_id: client_id
        }

        response = RestClient.post(
          token_uri,
          payload,
          {
            content_type: 'application/x-www-form-urlencoded',
            authorization: basic
          }
        )

        data = JSON.parse(response.body)

        if data['error']
          desc = data['error_description'] || data['error']
          raise "xAI OAuth token endpoint error: #{data['error']} - #{desc}"
        end

        access_token = data['access_token']

        if access_token
          opts[:bearer_token] = access_token
          opts[:refresh_token] = data['refresh_token'] if data['refresh_token']
          puts "\n[*] SUCCESS: Bearer token obtained via authorize + token exchange."
          puts '    (Cached in-memory for this Ruby process so subsequent Grok calls in the same run skip re-enrollment.)'
          puts ''
          puts '    TO MAKE THIS PERMANENT (strongly recommended -- one-time only):'
          puts '    1. Copy the bearer_token below (and refresh_token if present).'
          puts '    2. Run your pwn-vault tool (or equivalent) and store under the ai.grok.oauth section:'
          puts "         ai.grok.oauth.bearer_token = #{access_token}"
          puts "         ai.grok.oauth.refresh_token = #{data['refresh_token']}" if data['refresh_token']
          puts '    3. (Optional) You may leave or remove client_id/client_secret after storing the bearer.'
          puts '    4. Next time PWN::Env loads (pwn -Y, pwn REPL, scripts, etc.) the bearer will be present'
          puts '       from your encrypted ~/.pwn/pwn.yaml -- the guard will skip this entire flow.'
          puts '       No more browser prompts or code pasting on future uses.'
          puts ''
          puts '    The token is long-lived for your SuperGrok subscription (xAI manages expiry/refresh as needed).'
          return access_token
        end

        raise 'No access_token received from xAI OAuth token endpoint (unexpected response)'
      rescue StandardError => e
        raise "Failed to obtain Grok OAuth bearer token: #{e.message}"
      end

      # Supported Method Parameters::
      # grok_ai_rest_call(
      #   token: 'required - grok_ai bearer token',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   base_uri: 'optional base grok api URI (defaults to https://api.x.ai/v1)',
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   timeout: 'optional timeout in seconds (defaults to 900)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      private_class_method def self.grok_rest_call(opts = {})
        engine = PWN::Env[:ai][:grok]
        raise 'ERROR: Grok Hash not found in PWN::Env.  Run `pwn -Y default.yaml`, then `PWN::Env` for usage.' if engine.nil?

        oauth = engine[:oauth] ||= {}
        if oauth[:client_id] && !oauth[:client_id].to_s.empty? && !oauth[:client_id].to_s.match?(/optional/i) &&
           oauth[:client_secret] && !oauth[:client_secret].to_s.empty? && !oauth[:client_secret].to_s.match?(/optional/i) &&
           (oauth[:bearer_token].nil? || oauth[:bearer_token].to_s.empty? || oauth[:bearer_token].to_s.match?(/optional/i))
          # ONLY call authorize flow when BOTH oauth:client_id + client_secret configured (non-optional)
          # AND no valid bearer_token yet. This is the singular enrollment trigger.
          # (Bearer is long-lived; store via pwn-vault once so future PWN::Env loads skip this.)
          # Pass the live oauth hash so obtain can mutate it (for in-process cache; inner hash is mutable).
          token = obtain_oauth_bearer_token(oauth)
        end

        token ||= engine[:key]
        token ||= PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Grok API Key (oauth:client_id will auto-trigger authorize flow for bearer_token if configured)')

        http_method = opts[:http_method].to_s.scrub.to_sym ||= :get

        base_uri = engine[:base_uri] ||= 'https://api.x.ai/v1'
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        headers = {
          content_type: 'application/json; charset=UTF-8',
          authorization: "Bearer #{token}"
        }

        http_body = opts[:http_body]
        http_body ||= {}

        timeout = opts[:timeout]
        timeout ||= 900

        spinner = opts[:spinner] || false

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        if spinner
          spin = TTY::Spinner.new(format: :dots)
          spin.auto_spin
        end

        retry_count = 0
        begin
          case http_method
          when :delete, :get
            headers[:params] = params
            response = rest_client.execute(
              method: http_method,
              url: "#{base_uri}/#{rest_call}",
              headers: headers,
              verify_ssl: false,
              timeout: timeout
            )

          when :post
            if http_body.key?(:multipart)
              headers[:content_type] = 'multipart/form-data'

              response = rest_client.execute(
                method: http_method,
                url: "#{base_uri}/#{rest_call}",
                headers: headers,
                payload: http_body,
                verify_ssl: false,
                timeout: timeout
              )
            else
              response = rest_client.execute(
                method: http_method,
                url: "#{base_uri}/#{rest_call}",
                headers: headers,
                payload: http_body.to_json,
                verify_ssl: false,
                timeout: timeout
              )
            end
          else
            raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
          end

          response
        rescue RestClient::TooManyRequests => e
          retry_after = e.response.headers[:retry_after]&.to_i ||= (0.5 * (retry_count + 1))
          sleep(retry_after + rand(0.3..5.0))
          retry_count += 1

          retry
        end
      rescue RestClient::ExceptionWithResponse => e
        puts "ERROR: #{e.message}: #{e.response}"
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      ensure
        spin.stop if spinner
      end

      # Supported Method Parameters::
      # models = PWN::AI::Grok.get_models

      public_class_method def self.get_models
        models = grok_rest_call(rest_call: 'models')

        JSON.parse(models, symbolize_names: true)[:data]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::AI::Grok.chat_with_tools(
      #   messages: 'required - full OpenAI-format messages array (system/user/assistant/tool)',
      #   tools: 'optional - OpenAI tools array [{type:"function", function:{...}}]',
      #   tool_choice: 'optional - "auto" | "none" | "required" | {type:"function", function:{name:..}}',
      #   model: 'optional - overrides PWN::Env[:ai][:grok][:model]',
      #   temp: 'optional - temperature (defaults to PWN::Env[:ai][:grok][:temp] || 1)',
      #   timeout: 'optional - seconds (default 900)',
      #   spinner: 'optional - display spinner (default false)'
      # )
      #
      # Returns the raw chat/completions response Hash with :choices intact
      # (including :message[:tool_calls]) — used by PWN::AI::Agent::Loop.
      # xAI's API is OpenAI-compatible for tool calling, so the request and
      # response shapes are identical to PWN::AI::OpenAI.chat_with_tools.

      public_class_method def self.chat_with_tools(opts = {})
        engine   = PWN::Env[:ai][:grok]
        messages = opts[:messages]
        raise 'ERROR: messages array is required' if messages.nil? || messages.empty?

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f
        temp = engine[:temp].to_f.nonzero? || 1 if temp.zero?

        http_body = {
          model: model,
          messages: messages,
          temperature: temp,
          stream: false
        }
        http_body[:tools]       = opts[:tools]       if opts[:tools] && !opts[:tools].empty?
        http_body[:tool_choice] = opts[:tool_choice] if opts[:tool_choice]

        response = grok_rest_call(
          http_method: :post,
          rest_call: 'chat/completions',
          http_body: http_body,
          timeout: opts[:timeout],
          spinner: opts[:spinner]
        )
        return nil if response.nil?

        json_resp = JSON.parse(response, symbolize_names: true)
        json_resp[:assistant_message] = json_resp.dig(:choices, 0, :message)
        json_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::AI::Grok.chat(
      #   request: 'required - message to Grok'
      #   model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:grok][:model])',
      #   temp: 'optional - creative response float (deafults to PWN::Env[:ai][:grok][:temp])',
      #   system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:grok][:system_role_content])',
      #   response_history: 'optional - pass response back in to have a conversation',
      #   speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
      #   timeout: 'optional timeout in seconds (defaults to 900)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      public_class_method def self.chat(opts = {})
        engine = PWN::Env[:ai][:grok]
        request = opts[:request]
        max_prompt_length = engine[:max_prompt_length] ||= 256_000
        request_trunc_idx = ((max_prompt_length - 1) / 3.36).floor
        request = request[0..request_trunc_idx]

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f ||= engine[:temp].to_f
        temp = 1 if temp.zero?

        rest_call = 'chat/completions'

        response_history = opts[:response_history]

        max_tokens = response_history[:usage][:total_tokens] unless response_history.nil?

        system_role_content = opts[:system_role_content] ||= engine[:system_role_content]

        system_role = {
          role: 'system',
          content: system_role_content
        }

        user_role = {
          role: 'user',
          content: request
        }

        response_history ||= { choices: [system_role] }
        choices_len = response_history[:choices].length

        http_body = {
          model: model,
          messages: [system_role],
          temperature: temp,
          stream: false
        }

        if response_history[:choices].length > 1
          response_history[:choices][1..-1].each do |message|
            http_body[:messages].push(message)
          end
        end

        http_body[:messages].push(user_role)

        timeout = opts[:timeout]
        spinner = opts[:spinner]

        response = grok_rest_call(
          http_method: :post,
          rest_call: rest_call,
          http_body: http_body,
          timeout: timeout,
          spinner: spinner
        )

        json_resp = JSON.parse(response, symbolize_names: true)
        assistant_resp = json_resp[:choices].first[:message]
        json_resp[:choices] = http_body[:messages]
        json_resp[:choices].push(assistant_resp)

        speak_answer = true if opts[:speak_answer]

        if speak_answer
          answer = assistant_resp[:content]
          text_path = "/tmp/#{SecureRandom.hex}.pwn_voice"
          # answer = json_resp[:choices].last[:text]
          # answer = json_resp[:choices].last[:content] if gpt
          File.write(text_path, answer)
          PWN::Plugins::Voice.text_to_speech(text_path: text_path)
          File.unlink(text_path)
        end

        json_resp
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
          models = #{self}.get_models

          response = #{self}.chat(
            request: 'required - message to Grok',
            model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:grok][:model])',
            temp: 'optional - creative response float (defaults to PWN::Env[:ai][:grok][:temp])',
            system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:grok][:system_role_content])',
            response_history: 'optional - pass response back in to have a conversation',
            speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
            timeout: 'optional - timeout in seconds (defaults to 900)'.
            spinner: 'optional - display spinner (defaults to false)'
          )

          #{self}.authors
        "
      end
    end
  end
end
