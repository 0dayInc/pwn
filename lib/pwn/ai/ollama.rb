# frozen_string_literal: true

require 'json'
require 'base64'
require 'securerandom'
require 'tty-spinner'

module PWN
  module AI
    # This plugin is used for interacting w/ Ollama's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    # This is based on the following Ollama API Specification:
    # https://api.openai.com/v1
    module Ollama
      # Supported Method Parameters::
      # ollama_rest_call(
      #   base_uri: 'required - base URI for the Ollama API',
      #   token: 'required - ollama bearer token',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   timeout: 'optional timeout in seconds (defaults to 300)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      private_class_method def self.ollama_rest_call(opts = {})
        engine = PWN::Env[:ai][:ollama]
        raise 'ERROR: Jira Server Hash not found in PWN::Env.  Run i`pwn -Y default.yaml`, then `PWN::Env` for usage.' if engine.nil?

        base_uri = engine[:base_uri]
        raise 'ERROR: base_uri must be provided in PWN::Env[:ai][:ollama][:base_uri]' if base_uri.nil?

        token = engine[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Ollama (i.e. OpenAPI) Key')
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]

        headers = {
          content_type: 'application/json; charset=UTF-8',
          authorization: "Bearer #{token}"
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
      # response = PWN::AI::Ollama.get_models

      public_class_method def self.get_models
        models = ollama_rest_call(rest_call: 'ollama/api/tags')

        JSON.parse(models, symbolize_names: true)[:models]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::AI::Ollama.chat(
      #   request: 'required - message to ChatGPT'
      #   model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:ollama][:model])',
      #   temp: 'optional - creative response float (deafults to PWN::Env[:ai][:ollama][:temp])',
      #   system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:ollama][:system_role_content])',
      #   response_history: 'optional - pass response back in to have a conversation',
      #   speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
      #   timeout: 'optional timeout in seconds (defaults to 300)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      public_class_method def self.chat(opts = {})
        engine = PWN::Env[:ai][:ollama]
        request = opts[:request]

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f ||= engine[:temp].to_f
        temp = 1 if temp.zero?

        rest_call = 'ollama/v1/chat/completions'

        response_history = opts[:response_history]

        max_tokens = response_history[:usage][:total_tokens] unless response_history.nil?

        system_role_content = opts[:system_role_content] ||= engine[:system_role_content]
        system_role_content = response_history[:choices].first[:content] if response_history

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

        response = ollama_rest_call(
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
            request: 'required - message to ChatGPT',
            model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:ollama][:model])',
            temp: 'optional - creative response float (defaults to PWN::Env[:ai][:ollama][:temp])',
            system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:ollama][:system_role_content])',
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
