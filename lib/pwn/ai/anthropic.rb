# frozen_string_literal: true

require 'json'
require 'rest-client'
require 'tty-spinner'
require 'securerandom'

module PWN
  module AI
    # This plugin interacts with Anthropic's Claude API.
    # It provides methods to list models, generate completions, and chat.
    # API documentation: https://docs.anthropic.com/en/api
    # Obtain an API key from https://console.anthropic.com/
    module Anthropic
      # Supported Method Parameters::
      # anthropic_rest_call(
      #   token: 'required - anthropic api key',
      #   http_method: 'optional HTTP method (defaults to GET)',
      #   base_uri: 'optional base anthropic api URI (defaults to https://api.anthropic.com/v1)',
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   timeout: 'optional timeout in seconds (defaults to 300)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      private_class_method def self.anthropic_rest_call(opts = {})
        engine = PWN::Env[:ai][:anthropic]
        raise 'ERROR: Anthropic Hash not found in PWN::Env.  Run `pwn -Y default.yaml`, then `PWN::Env` for usage.' if engine.nil?

        token = engine[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Anthropic API Key')

        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end

        base_uri = engine[:base_uri] ||= 'https://api.anthropic.com/v1'
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        headers = {
          content_type: 'application/json; charset=UTF-8',
          'x-api-key': token,
          'anthropic-version': '2023-06-01'
        }

        http_body = opts[:http_body]
        http_body ||= {}

        timeout = opts[:timeout]
        timeout ||= 300

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
            raise "Unsupported HTTP Method #{http_method} for #{self} Plugin"
          end

          response.body
        rescue RestClient::TooManyRequests => e
          retry_after = e.response.headers[:retry_after]&.to_i || (0.5 * (retry_count + 1))
          sleep(retry_after + rand(0.3..5.0))
          retry_count += 1

          retry
        rescue RestClient::ExceptionWithResponse => e
          raise "Anthropic API Error: #{e.message}: #{e.response}"
        rescue StandardError => e
          case e.message
          when '400 Bad Request', '404 Resource Not Found'
            raise "#{e.message}: #{e.response}"
          else
            raise e
          end
        ensure
          spin.stop if spinner
        end
      end

      # Supported Method Parameters::
      # models = PWN::AI::Anthropic.get_models

      public_class_method def self.get_models
        models = anthropic_rest_call(rest_call: 'models')

        JSON.parse(models, symbolize_names: true)[:data]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::AI::Anthropic.chat(
      #   request: 'required - message to Anthropic',
      #   model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:anthropic][:model])',
      #   temp: 'optional - creative response float (defaults to PWN::Env[:ai][:anthropic][:temp])',
      #   system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:anthropic][:system_role_content])',
      #   response_history: 'optional - pass response back in to have a conversation',
      #   speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
      #   timeout: 'optional timeout in seconds (defaults to 300)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      public_class_method def self.chat(opts = {})
        engine = PWN::Env[:ai][:anthropic]
        request = opts[:request]
        max_prompt_length = engine[:max_prompt_length] ||= 200_000
        request_trunc_idx = ((max_prompt_length - 1) / 3.36).floor
        request = request[0..request_trunc_idx]

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f ||= engine[:temp].to_f
        temp = 1 if temp.zero?

        rest_call = 'messages'

        response_history = opts[:response_history]

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

        http_body = {
          model: model,
          max_tokens: 4096,
          temperature: temp,
          system: system_role_content,
          messages: []
        }

        if response_history[:choices].length > 1
          response_history[:choices][1..].each do |message|
            next if message[:role] == 'system'

            http_body[:messages].push(role: message[:role].to_s, content: message[:content].to_s)
          end
        end

        http_body[:messages].push(role: 'user', content: request)

        timeout = opts[:timeout]
        spinner = opts[:spinner]

        response = anthropic_rest_call(
          http_method: :post,
          rest_call: rest_call,
          http_body: http_body,
          timeout: timeout,
          spinner: spinner
        )

        json_resp = JSON.parse(response, symbolize_names: true)
        raise "Anthropic API Error: #{json_resp[:error] || json_resp}" if json_resp[:error] || json_resp[:type] == 'error'

        assistant_content = if json_resp[:content] && json_resp[:content].is_a?(Array) && json_resp[:content].first
                              json_resp[:content].first[:text]
                            else
                              ''
                            end
        assistant_resp = {
          role: 'assistant',
          content: assistant_content
        }

        # Build choices for PWN compatibility: [system, ...history..., user, assistant]
        json_resp[:choices] = [system_role] + http_body[:messages]
        json_resp[:choices].push(assistant_resp)

        # Ensure compatibility fields
        json_resp[:id] ||= "msg_#{SecureRandom.hex(8)}"
        json_resp[:object] ||= 'message'
        json_resp[:model] ||= model

        if json_resp[:usage].is_a?(Hash)
          inp_tokens = json_resp[:usage][:input_tokens] || 0
          out_tokens = json_resp[:usage][:output_tokens] || 0
          json_resp[:usage][:total_tokens] = inp_tokens + out_tokens
        else
          json_resp[:usage] = { input_tokens: 0, output_tokens: 0, total_tokens: 0 }
        end

        speak_answer = true if opts[:speak_answer]

        if speak_answer
          answer = assistant_resp[:content]
          text_path = "/tmp/#{SecureRandom.hex}.pwn_voice"
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
            request: 'required - message to Anthropic',
            model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:anthropic][:model])',
            temp: 'optional - creative response float (defaults to PWN::Env[:ai][:anthropic][:temp])',
            system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:anthropic][:system_role_content])',
            response_history: 'optional - pass response back in to have a conversation',
            speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
            timeout: 'optional - timeout in seconds (defaults to 300)',
            spinner: 'optional - display spinner (defaults to false)'
          )

          #{self}.authors
        "
      end
    end
  end
end
