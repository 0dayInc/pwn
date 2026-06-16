# frozen_string_literal: true

require 'json'
require 'rest-client'
require 'tty-spinner'
require 'securerandom'

module PWN
  module AI
    # This plugin interacts with Google's Gemini API (Generative Language).
    # It provides methods to list models, generate completions, and chat,
    # plus a native tool-calling adapter (`chat_with_tools`) for PWN::AI::Agent::Loop.
    #
    # API documentation: https://ai.google.dev/api
    # Obtain an API key from https://aistudio.google.com/app/apikey
    module Gemini
      # Supported Method Parameters::
      # gemini_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)',
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   timeout: 'optional timeout in seconds (defaults to 900)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      private_class_method def self.gemini_rest_call(opts = {})
        engine = PWN::Env[:ai][:gemini]
        raise 'ERROR: Gemini Hash not found in PWN::Env.  Run `pwn -Y default.yaml`, then `PWN::Env` for usage.' if engine.nil?

        token = engine[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Google Gemini API Key')

        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end

        base_uri = engine[:base_uri] ||= 'https://generativelanguage.googleapis.com/v1beta'
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        headers = {
          content_type: 'application/json; charset=UTF-8',
          'x-goog-api-key': token
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
            response = rest_client.execute(
              method: http_method,
              url: "#{base_uri}/#{rest_call}",
              headers: headers,
              payload: http_body.to_json,
              verify_ssl: false,
              timeout: timeout
            )
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
          raise "Gemini API Error: #{e.message}: #{e.response}"
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
      # models = PWN::AI::Gemini.get_models

      public_class_method def self.get_models
        models = gemini_rest_call(rest_call: 'models')

        JSON.parse(models, symbolize_names: true)[:models]
      rescue StandardError => e
        raise e
      end

      # ----------------------------------------------------------------------
      # Native tool-calling adapter for PWN::AI::Agent::Loop.
      #
      # Accepts an OpenAI-shape conversation (messages: + tools:), translates
      # it to Gemini's models/{model}:generateContent wire format
      # (systemInstruction, contents[].role 'user'/'model', parts[].text /
      # functionCall / functionResponse, tools[].functionDeclarations), POSTs,
      # then translates the response back to the canonical OpenAI shape:
      #   { choices: [{ message: { role:, content:, tool_calls:[...] } }],
      #     assistant_message: <same hash> }
      #
      # The returned assistant message ALSO carries :_native_content (the raw
      # parts[] array) so that on the next loop iteration we can round-trip
      # functionCall blocks exactly.
      # ----------------------------------------------------------------------

      # Supported Method Parameters::
      # response = PWN::AI::Gemini.chat_with_tools(
      #   messages: 'required - OpenAI-format messages array (system/user/assistant/tool)',
      #   tools: 'optional - OpenAI tools array [{type:"function", function:{...}}]',
      #   tool_choice: 'optional - "auto" | "none" | "required" | {type:"function", function:{name:..}}',
      #   model: 'optional - overrides PWN::Env[:ai][:gemini][:model]',
      #   temp: 'optional - temperature (defaults to PWN::Env[:ai][:gemini][:temp] || 1)',
      #   max_tokens: 'optional - maxOutputTokens (defaults to 8192)',
      #   timeout: 'optional - seconds (default 900)',
      #   spinner: 'optional - display spinner (default false)'
      # )

      public_class_method def self.chat_with_tools(opts = {})
        engine   = PWN::Env[:ai][:gemini]
        messages = opts[:messages]
        raise 'ERROR: messages array is required' if messages.nil? || messages.empty?

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f
        temp = engine[:temp].to_f.nonzero? || 1 if temp.zero?

        system_str, contents = oa_messages_to_gemini(messages: messages)

        http_body = {
          contents: contents,
          generationConfig: {
            temperature: temp,
            maxOutputTokens: opts[:max_tokens] || 8192
          }
        }
        http_body[:systemInstruction] = { parts: [{ text: system_str }] } if system_str && !system_str.empty?

        if opts[:tools] && !opts[:tools].empty?
          http_body[:tools] = [{
            functionDeclarations: opts[:tools].map do |t|
              fn = t[:function] || t['function'] || t
              {
                name: fn[:name] || fn['name'],
                description: fn[:description] || fn['description'],
                parameters: fn[:parameters] || fn['parameters'] || { type: 'object', properties: {} }
              }
            end
          }]
          http_body[:toolConfig] = gemini_tool_config(choice: opts[:tool_choice]) if opts[:tool_choice]
        end

        response = gemini_rest_call(
          http_method: :post,
          rest_call: "models/#{model}:generateContent",
          http_body: http_body,
          timeout: opts[:timeout],
          spinner: opts[:spinner]
        )
        return nil if response.nil?

        json_resp = JSON.parse(response, symbolize_names: true)
        raise "Gemini API Error: #{json_resp[:error]}" if json_resp[:error]

        gemini_resp_to_oa(response: json_resp)
      rescue StandardError => e
        raise e
      end

      # OpenAI messages[] -> [system_string, gemini contents[]]
      private_class_method def self.oa_messages_to_gemini(opts = {})
        messages = opts[:messages] ||= []
        system_parts = []
        out = []
        # tool_call_id -> function name (Gemini's functionResponse links by name, not id)
        tool_name_by_id = {}

        messages.each do |m|
          role = (m[:role] || m['role']).to_s
          case role
          when 'system', 'developer'
            system_parts << (m[:content] || m['content']).to_s
          when 'user'
            out << { role: 'user', parts: [{ text: (m[:content] || m['content']).to_s }] }
          when 'assistant'
            raw = m[:_native_content] || m['_native_content']
            if raw.is_a?(Array) && !raw.empty?
              parts = raw.map do |p|
                if p[:functionCall]
                  tool_name_by_id[p.dig(:functionCall, :_id).to_s] = p.dig(:functionCall, :name)
                  { functionCall: p[:functionCall].except(:_id) }
                else
                  p
                end
              end
              out << { role: 'model', parts: parts }
              next
            end

            parts = []
            txt = (m[:content] || m['content']).to_s
            parts << { text: txt } unless txt.empty?
            Array(m[:tool_calls] || m['tool_calls']).each do |tc|
              fn   = tc[:function] || tc['function'] || {}
              args = fn[:arguments] || fn['arguments']
              args_h = if args.is_a?(Hash)
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
              name = fn[:name] || fn['name']
              tool_name_by_id[(tc[:id] || tc['id']).to_s] = name
              parts << { functionCall: { name: name, args: args_h } }
            end
            parts << { text: '' } if parts.empty?
            out << { role: 'model', parts: parts }
          when 'tool'
            tcid = (m[:tool_call_id] || m['tool_call_id']).to_s
            name = (m[:name] || m['name'] || tool_name_by_id[tcid]).to_s
            content = (m[:content] || m['content']).to_s
            resp = begin
              JSON.parse(content)
            rescue StandardError
              { content: content }
            end
            out << { role: 'user', parts: [{ functionResponse: { name: name, response: resp } }] }
          end
        end

        [system_parts.join("\n\n"), out]
      end

      # Gemini generateContent response -> OpenAI chat/completions shape
      private_class_method def self.gemini_resp_to_oa(opts = {})
        resp = opts[:response] ||= {}
        cand  = Array(resp[:candidates]).first || {}
        parts = Array(cand.dig(:content, :parts))

        text = parts.select { |p| p.key?(:text) }.map { |p| p[:text] }.join
        tool_calls = parts.select { |p| p.key?(:functionCall) }.map do |p|
          fc = p[:functionCall]
          id = "call_#{SecureRandom.hex(8)}"
          # Stash the synthetic id inside the part for round-trip name lookup
          p[:functionCall] = fc.merge(_id: id)
          {
            id: id,
            type: 'function',
            function: { name: fc[:name], arguments: JSON.generate(fc[:args] || {}) }
          }
        end

        msg = {
          role: 'assistant',
          content: text.empty? && !tool_calls.empty? ? nil : text,
          tool_calls: tool_calls,
          _native_content: parts
        }

        usage = resp[:usageMetadata] || {}
        {
          id: "gemini_#{SecureRandom.hex(6)}",
          object: 'chat.completion',
          model: resp[:modelVersion] || cand[:modelVersion],
          stop_reason: cand[:finishReason],
          usage: {
            prompt_tokens: usage[:promptTokenCount],
            completion_tokens: usage[:candidatesTokenCount],
            total_tokens: usage[:totalTokenCount] ||
              ((usage[:promptTokenCount] || 0) + (usage[:candidatesTokenCount] || 0))
          },
          choices: [{ index: 0, message: msg, finish_reason: cand[:finishReason] }],
          assistant_message: msg
        }
      end

      private_class_method def self.gemini_tool_config(opts = {})
        choice = opts[:choice]
        case choice
        when 'none', :none then { functionCallingConfig: { mode: 'NONE' } }
        when 'required', :required, 'any', :any then { functionCallingConfig: { mode: 'ANY' } }
        when Hash
          fn = choice[:function] || choice['function'] || choice
          { functionCallingConfig: { mode: 'ANY', allowedFunctionNames: [fn[:name] || fn['name']] } }
        else # 'auto', :auto, nil, anything else
          { functionCallingConfig: { mode: 'AUTO' } }
        end
      end

      # Supported Method Parameters::
      # response = PWN::AI::Gemini.chat(
      #   request: 'required - message to Gemini',
      #   model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:gemini][:model])',
      #   temp: 'optional - creative response float (defaults to PWN::Env[:ai][:gemini][:temp])',
      #   system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:gemini][:system_role_content])',
      #   response_history: 'optional - pass response back in to have a conversation',
      #   speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
      #   timeout: 'optional timeout in seconds (defaults to 900)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      public_class_method def self.chat(opts = {})
        engine  = PWN::Env[:ai][:gemini]
        request = opts[:request]
        max_prompt_length = engine[:max_prompt_length] ||= 1_000_000
        request = request.to_s[0, ((max_prompt_length - 1) / 3.36).floor]

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f
        temp = engine[:temp].to_f.nonzero? || 1 if temp.zero?

        system_role_content = opts[:system_role_content] ||= engine[:system_role_content]
        system_role = { role: 'system', content: system_role_content }
        user_role   = { role: 'user',   content: request }

        response_history = opts[:response_history]
        response_history ||= { choices: [system_role] }

        # Build the OpenAI-shape messages array, then reuse the Gemini
        # translator so .chat and .chat_with_tools share one wire path.
        messages = [system_role]
        if response_history[:choices].length > 1
          response_history[:choices][1..].each do |msg|
            r = (msg[:role] || msg['role']).to_s
            next if r == 'system'

            messages.push(msg)
          end
        end
        messages.push(user_role)

        sys_str, contents = oa_messages_to_gemini(messages: messages)

        http_body = {
          contents: contents,
          generationConfig: { temperature: temp, maxOutputTokens: 8192 }
        }
        http_body[:systemInstruction] = { parts: [{ text: sys_str }] } if sys_str && !sys_str.empty?

        response = gemini_rest_call(
          http_method: :post,
          rest_call: "models/#{model}:generateContent",
          http_body: http_body,
          timeout: opts[:timeout],
          spinner: opts[:spinner]
        )

        json_resp = JSON.parse(response, symbolize_names: true)
        raise "Gemini API Error: #{json_resp[:error]}" if json_resp[:error]

        parts = Array(json_resp.dig(:candidates, 0, :content, :parts))
        assistant_content = parts.select { |p| p.key?(:text) }.map { |p| p[:text] }.join
        assistant_resp = { role: 'assistant', content: assistant_content }

        # Build choices for PWN compatibility: [system, ...history..., user, assistant]
        json_resp[:choices] = messages
        json_resp[:choices].push(assistant_resp)
        json_resp[:id] ||= "gemini_#{SecureRandom.hex(6)}"
        json_resp[:object] ||= 'chat.completion'
        json_resp[:model]  ||= model

        usage = json_resp[:usageMetadata] || {}
        json_resp[:usage] = {
          prompt_tokens: usage[:promptTokenCount] || 0,
          completion_tokens: usage[:candidatesTokenCount] || 0,
          total_tokens: usage[:totalTokenCount] ||
                        ((usage[:promptTokenCount] || 0) + (usage[:candidatesTokenCount] || 0))
        }

        if opts[:speak_answer]
          text_path = "/tmp/#{SecureRandom.hex}.pwn_voice"
          File.write(text_path, assistant_content)
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
            request: 'required - message to Gemini',
            model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:gemini][:model])',
            temp: 'optional - creative response float (defaults to PWN::Env[:ai][:gemini][:temp])',
            system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:gemini][:system_role_content])',
            response_history: 'optional - pass response back in to have a conversation',
            speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
            timeout: 'optional - timeout in seconds (defaults to 900)',
            spinner: 'optional - display spinner (defaults to false)'
          )

          response = #{self}.chat_with_tools(
            messages: 'required - OpenAI-format messages array',
            tools: 'optional - OpenAI tools array',
            tool_choice: 'optional - auto | none | required | {function:{name:..}}',
            model: 'optional - overrides PWN::Env[:ai][:gemini][:model]'
          )

          #{self}.authors
        "
      end
    end
  end
end
