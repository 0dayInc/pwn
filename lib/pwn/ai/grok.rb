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
      # Internal helper: true when +val+ is a *real* configured value coming
      # from PWN::Config / pwn-vault (i.e. not nil, not blank, and not one of
      # the "optional - ..." / "required - ..." placeholder strings that
      # PWN::Config.default_env writes into a fresh ~/.pwn/pwn.yaml).
      # Used so OAuth + API key resolution behaves correctly regardless of
      # whether the user edited every field.
      private_class_method def self.real_config_value?(val)
        s = val.to_s.strip
        return false if s.empty?
        return false if s.match?(/\A(optional|required)\b/i)

        true
      end

      # ------------------------------------------------------------------
      # xAI Grok OAuth (SuperGrok) -- public-client OIDC, no client_secret.
      #
      # auth.x.ai is a full OIDC provider (/.well-known/openid-configuration).
      # xAI ships a PUBLIC client for the Grok CLI; the same client_id is used
      # by NousResearch/hermes-agent (`hermes auth add xai-oauth`) and is reused
      # here so PWN can obtain a Bearer for https://api.x.ai/v1 without an API
      # key.  token_endpoint_auth_methods_supported includes 'none', so no
      # client_secret is required -- only PKCE / device_code.
      #
      # Two grants are implemented:
      #   * RFC 8628 device_authorization  -> default; headless / SSH friendly.
      #   * refresh_token                  -> silent renewal once enrolled.
      #
      # Access tokens are short-lived JWTs (ES256, `exp` claim). The
      # refresh_token is long-lived -- persist it via pwn-vault under
      # ai.grok.oauth.refresh_token and PWN::AI::Grok refreshes transparently
      # on every run.
      # ------------------------------------------------------------------
      XAI_OAUTH_ISSUER     = 'https://auth.x.ai'
      XAI_OAUTH_DEVICE_URI = "#{XAI_OAUTH_ISSUER}/oauth2/device/code".freeze
      XAI_OAUTH_TOKEN_URI  = "#{XAI_OAUTH_ISSUER}/oauth2/token".freeze
      # Public Grok-CLI client_id (same one hermes-agent uses).
      XAI_OAUTH_CLIENT_ID  = 'b1a00492-073a-47ea-816f-4c329264a828'
      XAI_OAUTH_SCOPE      = 'openid profile email offline_access grok-cli:access api:access'

      # Internal: decode a JWT payload (no sig verification) to read `exp`.
      private_class_method def self.jwt_exp(token)
        seg = token.to_s.split('.')[1]
        return nil unless seg

        seg += '=' * ((4 - (seg.length % 4)) % 4)
        JSON.parse(Base64.urlsafe_decode64(seg))['exp']
      rescue StandardError
        nil
      end

      # Internal: true when +token+ is absent, not a JWT, or expires within
      # +skew+ seconds.
      private_class_method def self.oauth_token_expiring?(token, skew = 120)
        return true unless real_config_value?(token)

        exp = jwt_exp(token)
        return false if exp.nil? # opaque token -- trust it

        Time.now.to_i >= (exp.to_i - skew)
      end

      # Supported Method Parameters::
      # access_token = PWN::AI::Grok.refresh_oauth_bearer_token(
      #   refresh_token: 'required - xAI OAuth refresh_token',
      #   client_id:     'optional - defaults to public Grok-CLI client',
      #   token_uri:     'optional - defaults to https://auth.x.ai/oauth2/token'
      # )
      #
      # Exchanges a refresh_token for a fresh access_token at auth.x.ai.
      # On success, writes :bearer_token (and a rotated :refresh_token if
      # returned) back into the passed opts/oauth Hash so the live PWN::Env
      # stays warm for the rest of the process.
      public_class_method def self.refresh_oauth_bearer_token(opts = {})
        refresh_token = opts[:refresh_token]
        raise 'refresh_token is required' unless real_config_value?(refresh_token)

        client_id = real_config_value?(opts[:client_id]) ? opts[:client_id] : XAI_OAUTH_CLIENT_ID
        token_uri = real_config_value?(opts[:token_uri]) ? opts[:token_uri] : XAI_OAUTH_TOKEN_URI

        resp = RestClient.post(
          token_uri,
          {
            grant_type: 'refresh_token',
            refresh_token: refresh_token,
            client_id: client_id
          },
          content_type: 'application/x-www-form-urlencoded',
          accept: 'application/json'
        )
        data = JSON.parse(resp.body)
        raise "xAI OAuth refresh error: #{data['error']} - #{data['error_description']}" if data['error']

        opts[:bearer_token]  = data['access_token']
        opts[:refresh_token] = data['refresh_token'] if data['refresh_token']
        opts[:expires_at]    = Time.now.to_i + data['expires_in'].to_i if data['expires_in']
        data['access_token']
      rescue RestClient::ExceptionWithResponse => e
        raise "xAI OAuth refresh failed (HTTP #{e.http_code}): #{e.response&.body}"
      end

      # Supported Method Parameters::
      # bearer = PWN::AI::Grok.obtain_oauth_bearer_token(
      #   client_id: 'optional - xAI OAuth Client ID (defaults to public Grok-CLI client)',
      #   scope:     'optional - space-delimited scopes (defaults to XAI_OAUTH_SCOPE)',
      #   timeout:   'optional - seconds to wait for user consent (default 300)'
      # )
      #
      # Runs the RFC 8628 OAuth 2.0 Device Authorization Grant against
      # auth.x.ai using xAI's public Grok-CLI client (no client_secret).
      # This is the same identity path `hermes auth add xai-oauth` uses --
      # a SuperGrok / X Premium+ subscription on the account is what grants
      # api:access at consent time.
      #
      #   1. POST /oauth2/device/code    -> device_code, user_code, verification_uri
      #   2. User opens verification_uri_complete in a browser and approves.
      #   3. Poll POST /oauth2/token (grant_type=device_code) until access_token.
      #
      # On success the access_token + refresh_token are written back into the
      # passed opts/oauth Hash (so PWN::Env[:ai][:grok][:oauth] is live-cached)
      # and the operator is told exactly what to persist via pwn-vault.
      public_class_method def self.obtain_oauth_bearer_token(opts = {})
        client_id = real_config_value?(opts[:client_id]) ? opts[:client_id] : XAI_OAUTH_CLIENT_ID
        scope     = real_config_value?(opts[:scope])     ? opts[:scope]     : XAI_OAUTH_SCOPE
        token_uri = real_config_value?(opts[:token_uri]) ? opts[:token_uri] : XAI_OAUTH_TOKEN_URI
        timeout   = (opts[:timeout] || 300).to_i

        # -- Step 1: request device + user code -------------------------------
        dev = JSON.parse(
          RestClient.post(
            XAI_OAUTH_DEVICE_URI,
            { client_id: client_id, scope: scope },
            content_type: 'application/x-www-form-urlencoded',
            accept: 'application/json'
          ).body
        )
        raise "xAI device_code error: #{dev['error']} - #{dev['error_description']}" if dev['error']

        device_code   = dev['device_code']
        user_code     = dev['user_code']
        verify_uri    = dev['verification_uri_complete'] || dev['verification_uri']
        interval      = (dev['interval'] || 5).to_i
        expires_in    = (dev['expires_in'] || timeout).to_i
        deadline      = Time.now.to_i + [expires_in, timeout].min

        puts "\n[*] xAI Grok OAuth -- Device Authorization (RFC 8628, public client, no secret)"
        puts '    A SuperGrok / X Premium+ subscription on the approving account is required.'
        puts ''
        puts '    Step 1: In a browser (any device), open:'
        puts "            #{verify_uri}"
        puts "    Step 2: Confirm the code matches:  #{user_code}"
        puts '    Step 3: Approve access for "Grok CLI".'
        puts ''
        puts "    Waiting for approval (polling every #{interval}s, timeout #{deadline - Time.now.to_i}s)..."

        # -- Step 2: poll the token endpoint ---------------------------------
        data = nil
        loop do
          sleep interval
          begin
            tok = RestClient.post(
              token_uri,
              {
                grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                device_code: device_code,
                client_id: client_id
              },
              content_type: 'application/x-www-form-urlencoded',
              accept: 'application/json'
            )
            data = JSON.parse(tok.body)
          rescue RestClient::ExceptionWithResponse => e
            data = begin
              JSON.parse(e.response.body)
            rescue StandardError
              { 'error' => "http_#{e.http_code}", 'error_description' => e.response&.body }
            end
          end

          case data['error']
          when nil
            break # success
          when 'authorization_pending'
            raise 'xAI OAuth device flow timed out waiting for user approval.' if Time.now.to_i >= deadline

            next
          when 'slow_down'
            interval += 5
            next
          when 'access_denied'
            raise 'xAI OAuth device flow: user denied the authorization request.'
          when 'expired_token'
            raise 'xAI OAuth device flow: device_code expired before approval; re-run enrollment.'
          else
            raise "xAI OAuth device flow error: #{data['error']} - #{data['error_description']}"
          end
        end

        access_token  = data['access_token']
        refresh_token = data['refresh_token']
        raise 'xAI OAuth token endpoint returned no access_token.' unless access_token

        opts[:bearer_token]  = access_token
        opts[:refresh_token] = refresh_token if refresh_token
        opts[:expires_at]    = Time.now.to_i + data['expires_in'].to_i if data['expires_in']

        puts "\n[*] SUCCESS: xAI Grok OAuth bearer obtained via device_code grant."
        puts '    Cached in-memory for this pwn / pwn-ai process.'
        puts ''
        puts '    TO MAKE THIS PERMANENT (recommended -- one-time), store via pwn-vault:'
        puts "      ai.grok.oauth.refresh_token = #{refresh_token}" if refresh_token
        puts "      ai.grok.oauth.bearer_token  = #{access_token}"
        puts '    On future runs the refresh_token alone is enough -- PWN::AI::Grok will'
        puts '    silently exchange it for a fresh access_token (no browser, no prompt).'
        puts ''

        access_token
      rescue RestClient::ExceptionWithResponse => e
        raise "Failed to obtain Grok OAuth bearer token (HTTP #{e.http_code}): #{e.response&.body}"
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
        engine = PWN::Env.dig(:ai, :grok) if defined?(PWN::Env)
        raise 'ERROR: Grok Hash not found in PWN::Env.  Run `pwn -Y default.yaml`, then `PWN::Env` for usage.' if engine.nil?

        # ------------------------------------------------------------------
        # Bearer resolution (all sourced from PWN::Config / pwn-vault via
        # PWN::Env[:ai][:grok]). Priority order:
        #   1. oauth[:bearer_token]  -> if present AND not expiring (JWT exp).
        #   2. oauth[:refresh_token] -> silent refresh_token grant at auth.x.ai
        #                               (writes new bearer back into oauth hash).
        #   3. oauth device flow     -> RFC 8628 enrollment via public Grok-CLI
        #                               client. Triggered when the oauth section
        #                               is opted-in (client_id set OR :enroll
        #                               truthy) OR when no engine[:key] exists.
        #   4. engine[:key]          -> classic xAI API key.
        #   5. interactive prompt    -> last resort.
        # Placeholder strings ("optional - ..." / "required - ...") written by
        # PWN::Config.default_env are treated as UNSET.
        # ------------------------------------------------------------------
        oauth = engine[:oauth].is_a?(Hash) ? engine[:oauth] : (engine[:oauth] ||= {})
        token = nil

        token = oauth[:bearer_token] if real_config_value?(oauth[:bearer_token]) && !oauth_token_expiring?(oauth[:bearer_token])

        if token.nil? && real_config_value?(oauth[:refresh_token])
          begin
            token = refresh_oauth_bearer_token(oauth)
          rescue StandardError => e
            warn "[!] Grok OAuth refresh failed, falling back: #{e.message}"
          end
        end

        oauth_opt_in = real_config_value?(oauth[:client_id]) ||
                       oauth[:enroll] == true ||
                       real_config_value?(oauth[:bearer_token]) ||
                       real_config_value?(oauth[:refresh_token])

        if token.nil? && (oauth_opt_in || !real_config_value?(engine[:key]))
          # Singular device-flow enrollment. Result is written back into the
          # live oauth hash so subsequent grok_rest_call invocations inside the
          # same pwn / pwn-ai process reuse it silently.
          token = obtain_oauth_bearer_token(oauth)
        end

        token = engine[:key] if token.nil? && real_config_value?(engine[:key])

        token ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Grok API Key (or run PWN::AI::Grok.obtain_oauth_bearer_token for SuperGrok OAuth)'
        )

        http_method = opts[:http_method].nil? ? :get : opts[:http_method].to_s.scrub.to_sym

        base_uri = real_config_value?(engine[:base_uri]) ? engine[:base_uri] : 'https://api.x.ai/v1'
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
