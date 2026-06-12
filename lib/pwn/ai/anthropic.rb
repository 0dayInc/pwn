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

      # ----------------------------------------------------------------------
      # Native tool-calling adapter for PWN::AI::Agent::Loop.
      #
      # Accepts an OpenAI-shape conversation (messages: + tools:), translates
      # it to Anthropic's /v1/messages wire format (top-level system string,
      # tool_use / tool_result content blocks, input_schema), POSTs, then
      # translates the response back to the canonical OpenAI shape:
      #   { choices: [{ message: { role:, content:, tool_calls:[...] } }],
      #     assistant_message: <same hash> }
      #
      # The returned assistant message ALSO carries :_native_content (the raw
      # content-block array) so that on the next loop iteration we can
      # round-trip tool_use blocks exactly, which Anthropic requires for a
      # tool_result to be accepted.
      # ----------------------------------------------------------------------

      # Supported Method Parameters::
      # response = PWN::AI::Anthropic.chat_raw(
      #   messages: 'required - OpenAI-format messages array (system/user/assistant/tool)',
      #   tools: 'optional - OpenAI tools array [{type:"function", function:{...}}]',
      #   tool_choice: 'optional - "auto" | "none" | "required" | {type:"function", function:{name:..}}',
      #   model: 'optional - overrides PWN::Env[:ai][:anthropic][:model]',
      #   temp: 'optional - temperature (defaults to PWN::Env[:ai][:anthropic][:temp] || 1)',
      #   max_tokens: 'optional - defaults to 4096',
      #   timeout: 'optional - seconds (default 300)',
      #   spinner: 'optional - display spinner (default false)'
      # )

      public_class_method def self.chat_raw(opts = {})
        engine   = PWN::Env[:ai][:anthropic]
        messages = opts[:messages]
        raise 'ERROR: messages array is required' if messages.nil? || messages.empty?

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f
        temp = engine[:temp].to_f.nonzero? || 1 if temp.zero?

        system_str, anth_messages = oa_messages_to_anthropic(messages: messages)

        http_body = {
          model: model,
          max_tokens: opts[:max_tokens] || 4096,
          temperature: temp,
          messages: anth_messages
        }
        http_body[:system] = system_str if system_str && !system_str.empty?

        if opts[:tools] && !opts[:tools].empty?
          http_body[:tools] = opts[:tools].map do |t|
            fn = t[:function] || t['function'] || t
            {
              name: fn[:name] || fn['name'],
              description: fn[:description] || fn['description'],
              input_schema: fn[:parameters] || fn['parameters'] || { type: 'object', properties: {} }
            }
          end
          http_body[:tool_choice] = anth_tool_choice(choice: opts[:tool_choice]) if opts[:tool_choice]
        end

        response = anthropic_rest_call(
          http_method: :post,
          rest_call: 'messages',
          http_body: http_body,
          timeout: opts[:timeout],
          spinner: opts[:spinner]
        )
        return nil if response.nil?

        json_resp = JSON.parse(response, symbolize_names: true)
        raise "Anthropic API Error: #{json_resp[:error] || json_resp}" if json_resp[:error] || json_resp[:type] == 'error'

        anthropic_resp_to_oa(response: json_resp)
      rescue StandardError => e
        raise e
      end

      # OpenAI messages[] -> [system_string, anthropic messages[]]
      private_class_method def self.oa_messages_to_anthropic(opts = {})
        messages = opts[:messages] ||= []
        system_parts = []
        out = []
        pending_tool_results = []

        flush_tool_results = lambda do
          return if pending_tool_results.empty?

          out << { role: 'user', content: pending_tool_results.dup }
          pending_tool_results.clear
        end

        messages.each do |m|
          role = (m[:role] || m['role']).to_s
          case role
          when 'system', 'developer'
            system_parts << (m[:content] || m['content']).to_s
          when 'user'
            flush_tool_results.call
            out << { role: 'user', content: (m[:content] || m['content']).to_s }
          when 'assistant'
            flush_tool_results.call
            # Prefer the raw content-block array if a prior chat_raw round
            # attached it — guarantees byte-exact tool_use round-trip.
            raw = m[:_native_content] || m['_native_content']
            if raw.is_a?(Array) && !raw.empty?
              out << { role: 'assistant', content: raw }
              next
            end

            blocks = []
            txt = (m[:content] || m['content']).to_s
            blocks << { type: 'text', text: txt } unless txt.empty?
            Array(m[:tool_calls] || m['tool_calls']).each do |tc|
              fn   = tc[:function] || tc['function'] || {}
              args = fn[:arguments] || fn['arguments']
              input = if args.is_a?(Hash)
                        args
                      elsif args.is_a?(String) && !args.strip.empty?
                        begin
                          JSON.parse(args)
                        rescue StandardError
                          { _raw: args }
                        end
                      else
                        {}
                      end
              blocks << {
                type: 'tool_use',
                id: tc[:id] || tc['id'] || "toolu_#{SecureRandom.hex(8)}",
                name: fn[:name] || fn['name'],
                input: input
              }
            end
            blocks << { type: 'text', text: '' } if blocks.empty?
            out << { role: 'assistant', content: blocks }
          when 'tool'
            pending_tool_results << {
              type: 'tool_result',
              tool_use_id: (m[:tool_call_id] || m['tool_call_id']).to_s,
              content: (m[:content] || m['content']).to_s
            }
          end
        end
        flush_tool_results.call

        [system_parts.join("\n\n"), out]
      end

      # Anthropic /v1/messages response -> OpenAI chat/completions shape
      private_class_method def self.anthropic_resp_to_oa(opts = {})
        resp = opts[:response] ||= {}
        blocks     = Array(resp[:content])
        text       = blocks.select { |b| b[:type] == 'text' }.map { |b| b[:text] }.join
        tool_calls = blocks.select { |b| b[:type] == 'tool_use' }.map do |b|
          {
            id: b[:id],
            type: 'function',
            function: { name: b[:name], arguments: JSON.generate(b[:input] || {}) }
          }
        end

        msg = {
          role: 'assistant',
          content: text.empty? && !tool_calls.empty? ? nil : text,
          tool_calls: tool_calls,
          _native_content: blocks
        }

        usage = resp[:usage] || {}
        {
          id: resp[:id],
          object: 'chat.completion',
          model: resp[:model],
          stop_reason: resp[:stop_reason],
          usage: {
            prompt_tokens: usage[:input_tokens],
            completion_tokens: usage[:output_tokens],
            total_tokens: (usage[:input_tokens] || 0) + (usage[:output_tokens] || 0)
          },
          choices: [{ index: 0, message: msg, finish_reason: resp[:stop_reason] }],
          assistant_message: msg
        }
      end

      private_class_method def self.anth_tool_choice(opts = {})
        choice = opts[:choice]
        case choice
        when 'none', :none then { type: 'none' }
        when 'required', :required, 'any', :any then { type: 'any' }
        when Hash
          fn = choice[:function] || choice['function'] || choice
          { type: 'tool', name: fn[:name] || fn['name'] }
        else # 'auto', :auto, nil, anything else
          { type: 'auto' }
        end
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
