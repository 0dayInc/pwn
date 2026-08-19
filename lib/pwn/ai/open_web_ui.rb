# frozen_string_literal: true

require 'json'
require 'base64'
require 'securerandom'

module PWN
  module AI
    # Client for Open WebUI's REST API via PWN::Plugins::TransparentBrowser (:rest).
    #
    # Live Open WebUI routes (gateway base_uri, no trailing slash):
    #   GET  /api/v1/models              OpenAI-compat model list (:data)
    #   POST /api/v1/chat/completions    OpenAI-compat chat (SSE when stream:true)
    #   POST /api/chat/completions       alias of the above
    #   GET  /ollama/api/tags            proxied Ollama tags (:models)
    #   POST /ollama/api/chat            proxied Ollama chat (NDJSON when stream:true)
    #   POST /ollama/api/embed           proxied embeddings (see PWN::MemoryIndex)
    #
    # Bare /api/chat and bare /v1/* are NOT API routes on stock Open WebUI —
    # they 405 or return the SPA HTML shell.
    module OpenWebUI
      private_class_method def self.real_config_value?(opts = {})
        s = opts[:value].to_s.strip
        return false if s.empty?
        return false if s.match?(/\A(optional|required)\b/i)
        return false if s.match?(/REDACTED/i)
        return false if s.match?(/\A<{3}.*>{3}\z/)

        true
      end

      # Supported Method Parameters::
      # openwebui_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)',
      #   rest_call: 'required rest call path relative to base_uri',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   timeout: 'optional timeout in seconds (defaults to 900)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      private_class_method def self.openwebui_rest_call(opts = {})
        engine = PWN::Env[:ai][:openwebui]
        raise 'ERROR: Open WebUI engine hash not found in PWN::Env[:ai][:openwebui]. Run `pwn -Y default.yaml`, then `PWN::Env` for usage.' if engine.nil?

        base_uri = engine[:base_uri].to_s.strip
        raise 'ERROR: base_uri must be provided in PWN::Env[:ai][:openwebui][:base_uri]' unless real_config_value?(value: base_uri)

        base_uri = base_uri.chomp('/')

        token = real_config_value?(value: engine[:key]) ? engine[:key].to_s.strip : nil
        if token.nil?
          # JWT/API key is required for Open WebUI. Only solicit on a real TTY;
          # never hang CI / agent tool loops waiting on mask_password.
          interactive = $stdin.tty? && $stdout.tty? && ENV['PWN_NONINTERACTIVE'].to_s.empty?
          raise 'ERROR: Open WebUI API key missing in PWN::Env[:ai][:openwebui][:key]. Set it via pwn-vault (Settings >> Account >> JWT Token).' unless interactive

          token = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Open WebUI (i.e. OpenAPI) Key')
          raise 'ERROR: Open WebUI API key is required' if token.to_s.strip.empty?

          engine[:key] = token
        end

        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub.sub(%r{\A/}, '')
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
        stream = http_body.is_a?(Hash) && http_body[:stream] == true

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        spin = PWN::Plugins::TTYSpinner.start if spinner

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
            elsif stream
              # RestClient :block_response yields Net::HTTPResponse; we must
              # drain the body ourselves. Open WebUI emits NDJSON (proxied
              # /ollama/api/*) or SSE data: lines (OpenAI-compat /api/v1/*).
              # Assemble into a single non-stream JSON body so callers keep
              # JSON.parse + the same :message / :choices shape.
              #
              # IMPORTANT: do NOT RestClient::Response.create(..., request=nil).
              # AbstractResponse#history calls request.redirection_history and
              # raises NoMethodError.
              #
              # ABSOLUTE DEADLINE: Net::HTTP read_timeout only fires on *idle*
              # gaps between chunks. A thinking model that dribbles tokens
              # forever never idles out. Enforce a wall-clock deadline
              # independent of chunk cadence.
              assembled = nil
              stream_err = nil
              deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout.to_f
              idle_timeout = [timeout.to_f, 120.0].min
              rest_client.execute(
                method: http_method,
                url: "#{base_uri}/#{rest_call}",
                headers: headers,
                payload: http_body.to_json,
                verify_ssl: false,
                open_timeout: [timeout.to_f, 30.0].min,
                read_timeout: idle_timeout,
                block_response: lambda do |http_resp|
                  buf = +''
                  bytes = 0
                  http_resp.read_body do |chunk|
                    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
                    if now > deadline
                      stream_err = "ERROR: Open WebUI stream absolute timeout after #{timeout}s for #{rest_call} (received #{bytes} bytes - model likely stuck in unbounded thinking; lower num_ctx / set num_predict)"
                      raise stream_err
                    end
                    buf << chunk
                    bytes += chunk.bytesize
                  end
                  code = http_resp.code.to_i
                  unless code.between?(200, 299)
                    stream_err = "ERROR: Open WebUI HTTP #{code} for #{rest_call}: #{buf.to_s[0, 800]}"
                    return
                  end
                  if buf.to_s.strip.empty?
                    stream_err = "ERROR: Open WebUI empty stream body for #{rest_call} (HTTP #{code})"
                    return
                  end
                  # SPA HTML mis-route (wrong path → 200 HTML shell)
                  if buf.lstrip.start_with?('<!DOCTYPE', '<!doctype', '<html')
                    stream_err = "ERROR: Open WebUI returned HTML for #{rest_call} (wrong API path or unauthenticated SPA fallback)"
                    return
                  end
                  assembled = assemble_openwebui_stream(body: buf, rest_call: rest_call)
                end
              )
              raise stream_err if stream_err
              raise "ERROR: Open WebUI stream produced no assembled body for #{rest_call}" if assembled.nil?

              response = assembled
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

          # Non-stream path: stock Open WebUI returns the SPA HTML shell
          # (200) for wrong routes like bare /api/chat or /v1/* — reject so
          # callers do not JSON.parse markup into nil choices.
          if response.respond_to?(:to_s)
            body_s = response.to_s
            raise "ERROR: Open WebUI returned HTML for #{rest_call} (wrong API path or unauthenticated SPA fallback)" if body_s.lstrip.start_with?('<!DOCTYPE', '<!doctype', '<html')
          end

          response
        rescue RestClient::TooManyRequests => e
          retry_after = e.response.headers[:retry_after]&.to_i ||= (0.5 * (retry_count + 1))
          sleep(retry_after + rand(0.3..5.0))
          retry_count += 1

          retry
        end
      rescue RestClient::ExceptionWithResponse => e
        # Never return nil here — chat_with_tools used to `return nil if response.nil?`
        # which made the agent loop print "[pwn-ai] engine returned no message"
        # with no actionable error. Raise so the caller / REPL surfaces the body.
        body = begin
          e.response.to_s[0, 800]
        rescue StandardError
          ''
        end
        raise "ERROR: Open WebUI #{e.message}: #{body}"
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          raise "#{e.message}: #{e.respond_to?(:response) ? e.response : e.message}"
        else
          raise e
        end
      ensure
        PWN::Plugins::TTYSpinner.stop(spin: spin)
      end

      # Pull a user-visible answer out of a reasoning/"thinking" channel.
      # Prefer text after common end markers; otherwise return the full
      # thinking string so the agent never surfaces a blank final.
      private_class_method def self.visible_from_thinking(opts = {})
        thinking = opts[:thinking].to_s
        return '' if thinking.strip.empty?

        markers = [
          %r{</think>}i,
          %r{</thinking>}i,
          /(?:\A|\n)\s*Final\s*Answer\s*:\s*/i,
          /(?:\A|\n)\s*Answer\s*:\s*/i,
          /Final\s*Answer\s*:\s*/i
        ]
        markers.each do |rx|
          if (m = thinking.match(rx))
            tail = thinking[(m.end(0))..].to_s.strip
            return tail unless tail.empty?
          end
        end
        thinking.strip
      end

      # Merge an Open WebUI streaming body (NDJSON proxied /ollama/api/chat OR
      # OpenAI-compat SSE on /api/v1/chat/completions) into a single JSON string
      # matching the non-stream response shape used by #chat / #chat_with_tools.
      private_class_method def self.assemble_openwebui_stream(opts = {})
        body = opts[:body].to_s
        rest_call = opts[:rest_call].to_s

        lines = body.each_line.map(&:strip).reject(&:empty?)
        # Strip SSE "data: " prefix when present; drop the terminal [DONE].
        payloads = lines.filter_map do |line|
          line = line.sub(/\Adata:\s*/, '')
          next if line.empty? || line == '[DONE]'

          begin
            JSON.parse(line, symbolize_names: true)
          rescue JSON::ParserError
            nil
          end
        end
        if payloads.empty?
          return {
            message: {
              role: 'assistant',
              content: '',
              error: 'empty_stream_payloads'
            },
            done: true,
            done_reason: 'error'
          }.to_json
        end

        openai_compat = rest_call.include?('/v1/') ||
                        rest_call.start_with?('v1/') ||
                        rest_call.include?('chat/completions') ||
                        payloads.any? { |p| p.key?(:choices) }

        if openai_compat
          assemble_openai_compat_stream(payloads: payloads)
        else
          assemble_native_chat_stream(payloads: payloads)
        end
      end

      # Proxied Ollama /ollama/api/chat NDJSON → single-object JSON string.
      private_class_method def self.assemble_native_chat_stream(opts = {})
        payloads = opts[:payloads]
        final = payloads.reverse.find { |p| p[:done] } || payloads.last
        content = +''
        thinking = +''
        tool_calls = []
        role = 'assistant'

        payloads.each do |p|
          msg = p[:message] || {}
          role = msg[:role] if msg[:role]
          content << msg[:content].to_s if msg[:content]
          thinking << msg[:thinking].to_s if msg[:thinking]
          thinking << msg[:reasoning_content].to_s if msg[:reasoning_content]
          Array(msg[:tool_calls]).each do |tc|
            tool_calls << tc unless tool_calls.any? { |existing| existing == tc }
          end
        end

        content = visible_from_thinking(thinking: thinking) if content.empty? && !thinking.empty? && tool_calls.empty?

        message = { role: role, content: content }
        message[:thinking] = thinking unless thinking.empty?
        message[:tool_calls] = tool_calls unless tool_calls.empty?

        merged = {
          model: final[:model],
          created_at: final[:created_at],
          message: message,
          done: true,
          done_reason: final[:done_reason],
          total_duration: final[:total_duration],
          load_duration: final[:load_duration],
          prompt_eval_count: final[:prompt_eval_count],
          prompt_eval_duration: final[:prompt_eval_duration],
          eval_count: final[:eval_count],
          eval_duration: final[:eval_duration]
        }.compact

        merged.to_json
      end

      # OpenAI-compat /api/v1/chat/completions SSE → single chat.completion JSON.
      private_class_method def self.assemble_openai_compat_stream(opts = {})
        payloads = opts[:payloads]
        base = payloads.first || {}
        content = +''
        thinking = +''
        role = 'assistant'
        tool_calls_by_idx = {}
        finish_reason = nil
        usage = nil

        payloads.each do |p|
          usage = p[:usage] if p[:usage]
          Array(p[:choices]).each do |ch|
            finish_reason = ch[:finish_reason] if ch[:finish_reason]
            delta = ch[:delta] || ch[:message] || {}
            role = delta[:role] if delta[:role]
            content << delta[:content].to_s if delta[:content]
            thinking << delta[:reasoning_content].to_s if delta[:reasoning_content]
            thinking << delta[:thinking].to_s if delta[:thinking]

            Array(delta[:tool_calls]).each do |tc|
              idx = tc[:index] || 0
              slot = tool_calls_by_idx[idx] ||= {
                id: nil,
                type: 'function',
                function: { name: +'', arguments: +'' }
              }
              slot[:id] = tc[:id] if tc[:id]
              slot[:type] = tc[:type] if tc[:type]
              fn = tc[:function] || {}
              slot[:function][:name] << fn[:name].to_s if fn[:name]
              slot[:function][:arguments] << fn[:arguments].to_s if fn[:arguments]
            end
          end
        end

        content = visible_from_thinking(thinking: thinking) if content.empty? && !thinking.empty? && tool_calls_by_idx.empty?

        message = { role: role, content: content }
        message[:thinking] = thinking unless thinking.empty?
        unless tool_calls_by_idx.empty?
          message[:tool_calls] = tool_calls_by_idx.keys.sort.map do |idx|
            tool_calls_by_idx[idx]
          end
        end

        merged = {
          id: base[:id],
          object: 'chat.completion',
          created: base[:created],
          model: base[:model],
          choices: [{
            index: 0,
            message: message,
            finish_reason: finish_reason || 'stop'
          }]
        }
        merged[:usage] = usage if usage
        merged.to_json
      end

      # Supported Method Parameters::
      # response = PWN::AI::OpenWebUI.get_models

      public_class_method def self.get_models
        # Prefer Open WebUI's own OpenAI-compat catalog; fall back to the
        # proxied Ollama tag list when needed.
        raw = openwebui_rest_call(rest_call: 'api/v1/models')
        parsed = JSON.parse(raw, symbolize_names: true)
        return parsed[:data] if parsed[:data].is_a?(Array)
        return parsed[:models] if parsed[:models].is_a?(Array)

        raw = openwebui_rest_call(rest_call: 'ollama/api/tags')
        JSON.parse(raw, symbolize_names: true)[:models]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # usage = PWN::AI::OpenWebUI.get_plan_usage
      #
      # Open WebUI is a local gateway with no subscription / plan-usage
      # endpoint. Always unavailable so the PS1 shows the infinity glyph.
      public_class_method def self.get_plan_usage(opts = {})
        _unused = opts
        { available: false, engine: :openwebui, unlimited: true }
      end

      # Coerce OpenAI-wire message history into Ollama-native shapes before
      # POST /api/chat (or Open WebUI /ollama/api/chat):
      # - function.arguments must be a Hash/Array object, not a JSON string
      #   (string args → HTTP 400 "can't find closing '}' symbol")
      # - assistant content nil + tool_calls → "" (Open WebUI form validation)
      private_class_method def self.parse_tool_arguments_object(opts = {})
        raw = opts[:arguments]
        case raw
        when Hash, Array then raw
        when nil then {}
        when String
          s = raw.strip
          return {} if s.empty?

          begin
            parsed = JSON.parse(s, symbolize_names: true)
            return parsed if parsed.is_a?(Hash) || parsed.is_a?(Array)
          rescue JSON::ParserError
            nil
          end
          { value: s }
        else
          { value: raw.to_s }
        end
      end

      private_class_method def self.normalize_messages_for_ollama(opts = {})
        Array(opts[:messages]).filter_map do |m|
          next unless m.is_a?(Hash)

          role = (m[:role] || m['role']).to_s
          out = { role: role }

          tcs = m[:tool_calls] || m['tool_calls']
          has_tcs = false
          if tcs
            wired = Array(tcs).filter_map do |tc|
              next unless tc.is_a?(Hash)

              fn = tc[:function] || tc['function'] || {}
              name = fn[:name] || fn['name'] || tc[:name] || tc['name']
              args = fn[:arguments] || fn['arguments'] || tc[:arguments] || tc['arguments']
              {
                id: (tc[:id] || tc['id'] || "call_#{SecureRandom.hex(4)}").to_s,
                type: (tc[:type] || tc['type'] || 'function').to_s,
                function: {
                  name: name.to_s,
                  arguments: parse_tool_arguments_object(arguments: args)
                }
              }
            end
            unless wired.empty?
              out[:tool_calls] = wired
              has_tcs = true
            end
          end

          if m.key?(:content) || m.key?('content')
            content = m.key?(:content) ? m[:content] : m['content']
            out[:content] = case content
                            when nil then has_tcs ? '' : nil
                            when String then content
                            when Hash, Array then JSON.generate(content)
                            else content.to_s
                            end
          elsif has_tcs
            out[:content] = ''
          end

          name = m[:name] || m['name']
          out[:name] = name.to_s if name && !name.to_s.empty?

          tcid = m[:tool_call_id] || m['tool_call_id']
          out[:tool_call_id] = tcid.to_s if tcid && !tcid.to_s.empty?

          out
        end
      end

      # Supported Method Parameters::
      # response = PWN::AI::OpenWebUI.chat_with_tools(
      #   messages: 'required - full OpenAI-format messages array (system/user/assistant/tool)',
      #   tools: 'optional - OpenAI tools array [{type:"function", function:{...}}]',
      #   tool_choice: 'optional - "auto" | "none" | {type:"function", function:{name:..}}',
      #   model: 'optional - overrides PWN::Env[:ai][:openwebui][:model]',
      #   temp: 'optional - temperature (defaults to PWN::Env[:ai][:openwebui][:temp] || 1)',
      #   timeout: 'optional - seconds (default 900)',
      #   spinner: 'optional - display spinner (default false)'
      # )
      #
      # Hits Open WebUI's PROXIED Ollama POST /ollama/api/chat so
      # options.num_ctx / num_predict / keep_alive take effect. Streaming is ON;
      # openwebui_rest_call assembles NDJSON chunks back into a single response.
      # Bare POST /api/chat is not an API route on stock Open WebUI (405).

      public_class_method def self.chat_with_tools(opts = {})
        engine   = PWN::Env[:ai][:openwebui]
        messages = normalize_messages_for_ollama(messages: opts[:messages])
        raise 'ERROR: messages array is required' if messages.nil? || messages.empty?

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' unless real_config_value?(value: model)

        temp = opts[:temp].to_f
        temp = engine[:temp].to_f.nonzero? || 1 if temp.zero?

        tools_present = opts[:tools] && !opts[:tools].empty?
        tool_temp     = (engine[:tool_temp] || 0.1).to_f
        num_ctx       = (engine[:num_ctx]   || 32_768).to_i
        num_predict   = (engine[:num_predict] || 4_096).to_i
        keep_alive    = engine[:keep_alive] || '30m'

        http_body = {
          model: model,
          messages: messages,
          stream: true,
          keep_alive: keep_alive,
          options: {
            num_ctx: num_ctx,
            num_predict: num_predict,
            temperature: tools_present ? tool_temp : temp
          }
        }
        if tools_present
          http_body[:tools] = opts[:tools]
          fmt = engine[:format]
          http_body[:format] = fmt unless fmt.nil? || fmt.to_s.empty?
        end
        http_body[:tool_choice] = opts[:tool_choice] if opts[:tool_choice]

        response = openwebui_rest_call(
          http_method: :post,
          rest_call: 'ollama/api/chat',
          http_body: http_body,
          timeout: opts[:timeout],
          spinner: opts[:spinner]
        )
        raise 'ERROR: Open WebUI chat_with_tools received empty response from openwebui_rest_call' if response.nil? || (response.respond_to?(:empty?) && response.empty?)

        json_resp = JSON.parse(response, symbolize_names: true)
        msg = json_resp[:message] || json_resp.dig(:choices, 0, :message)
        if msg.is_a?(Hash)
          content = msg[:content].to_s
          thinking = msg[:thinking].to_s
          thinking = msg[:reasoning_content].to_s if thinking.empty?
          tcalls = Array(msg[:tool_calls])
          msg = msg.merge(content: visible_from_thinking(thinking: thinking)) if content.strip.empty? && !thinking.strip.empty? && tcalls.empty?
        end
        json_resp[:choices] = [{ message: msg }] if msg && !json_resp.key?(:choices)
        json_resp[:assistant_message] = msg
        raise "ERROR: Open WebUI response missing message/choices: #{json_resp.inspect[0, 400]}" if msg.nil?

        json_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::AI::OpenWebUI.chat(
      #   request: 'required - message to Open WebUI'
      #   model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:openwebui][:model])',
      #   temp: 'optional - creative response float (deafults to PWN::Env[:ai][:openwebui][:temp])',
      #   system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:openwebui][:system_role_content])',
      #   response_history: 'optional - pass response back in to have a conversation',
      #   speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
      #   timeout: 'optional timeout in seconds (defaults to 900)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      public_class_method def self.chat(opts = {})
        engine = PWN::Env[:ai][:openwebui]
        request = opts[:request]
        max_prompt_length = engine[:max_prompt_length] ||= 1_000_000
        request_trunc_idx = ((max_prompt_length - 1) / 3.36).floor
        request = request[0..request_trunc_idx]

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' unless real_config_value?(value: model)

        temp = opts[:temp].to_f ||= engine[:temp].to_f
        temp = 1 if temp.zero?

        # Open WebUI OpenAI-compat path (NOT bare v1/* — that hits the SPA).
        rest_call = 'api/v1/chat/completions'

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
          stream: true
        }

        if response_history[:choices].length > 1
          response_history[:choices][1..].each do |message|
            http_body[:messages].push(message)
          end
        end

        http_body[:messages].push(user_role)

        timeout = opts[:timeout]
        spinner = opts[:spinner]

        response = openwebui_rest_call(
          http_method: :post,
          rest_call: rest_call,
          http_body: http_body,
          timeout: timeout,
          spinner: spinner
        )

        json_resp = JSON.parse(response, symbolize_names: true)
        assistant_resp = json_resp[:choices].first[:message]
        if assistant_resp.is_a?(Hash)
          content = assistant_resp[:content].to_s
          thinking = assistant_resp[:thinking].to_s
          thinking = assistant_resp[:reasoning_content].to_s if thinking.empty?
          assistant_resp = assistant_resp.merge(content: visible_from_thinking(thinking: thinking)) if content.strip.empty? && !thinking.strip.empty?
        end
        json_resp[:choices] = http_body[:messages]
        json_resp[:choices].push(assistant_resp)

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

          usage = #{self}.get_plan_usage

          response = #{self}.chat(
            request: 'required - message to Open WebUI',
            model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:openwebui][:model])',
            temp: 'optional - creative response float (defaults to PWN::Env[:ai][:openwebui][:temp])',
            system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:openwebui][:system_role_content])',
            response_history: 'optional - pass response back in to have a conversation',
            speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
            timeout: 'optional - timeout in seconds (defaults to 900)',
            spinner: 'optional - display spinner (defaults to false)'
          )

          response = #{self}.chat_with_tools(
            messages: 'required - OpenAI-format messages array',
            tools: 'optional - OpenAI tools array',
            model: 'optional - overrides PWN::Env[:ai][:openwebui][:model]',
            temp: 'optional - temperature',
            timeout: 'optional - seconds (default 900)',
            spinner: 'optional - display spinner (default false)'
          )

          #{self}.authors
        "
      end
    end
  end
end
