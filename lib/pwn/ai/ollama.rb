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
      #   timeout: 'optional timeout in seconds (defaults to 900)',
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
        timeout ||= 900

        spinner = opts[:spinner] || false
        stream = http_body.is_a?(Hash) && http_body[:stream] == true

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
            elsif stream
              # RestClient :block_response yields Net::HTTPResponse; we must
              # drain the body ourselves. Ollama emits NDJSON (native /api/*)
              # or SSE data: lines (OpenAI-compat /v1/*). Assemble into a
              # single non-stream JSON body so callers keep JSON.parse + the
              # same :message / :choices shape.
              #
              # IMPORTANT: do NOT RestClient::Response.create(..., request=nil).
              # AbstractResponse#history calls request.redirection_history and
              # raises NoMethodError, which previously escaped as a confusing
              # failure (or, when swallowed upstream, an empty agent reply).
              #
              # ABSOLUTE DEADLINE: Net::HTTP read_timeout only fires on *idle*
              # gaps between chunks. A thinking model that dribbles tokens
              # forever never idles out — the hung pwn-ai spinner on pts/8
              # (2026-07-23) had already received 17MB+ after 25 minutes.
              # Enforce a wall-clock deadline independent of chunk cadence.
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
                      stream_err = "ERROR: Ollama stream absolute timeout after #{timeout}s for #{rest_call} (received #{bytes} bytes - model likely stuck in unbounded thinking; lower num_ctx / set num_predict)"
                      # Stop reading; RestClient will tear down the socket.
                      raise stream_err
                    end
                    buf << chunk
                    bytes += chunk.bytesize
                  end
                  code = http_resp.code.to_i
                  unless code.between?(200, 299)
                    stream_err = "ERROR: Ollama HTTP #{code} for #{rest_call}: #{buf.to_s[0, 800]}"
                    return
                  end
                  if buf.to_s.strip.empty?
                    stream_err = "ERROR: Ollama empty stream body for #{rest_call} (HTTP #{code})"
                    return
                  end
                  assembled = assemble_ollama_stream(body: buf, rest_call: rest_call)
                end
              )
              raise stream_err if stream_err
              raise "ERROR: Ollama stream produced no assembled body for #{rest_call}" if assembled.nil?

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
        # Never return nil here — chat_with_tools used to `return nil if response.nil?`
        # which made the agent loop print "[pwn-ai] engine returned no message"
        # with no actionable error. Raise so the caller / REPL surfaces the body.
        body = begin
          e.response.to_s[0, 800]
        rescue StandardError
          ''
        end
        raise "ERROR: Ollama #{e.message}: #{body}"
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          raise "#{e.message}: #{e.respond_to?(:response) ? e.response : e.message}"
        else
          raise e
        end
      ensure
        spin.stop if spinner
      end

      # Pull a user-visible answer out of a reasoning/"thinking" channel.
      # Prefer text after common end markers; otherwise return the full
      # thinking string so the agent never surfaces a blank final.
      private_class_method def self.visible_from_thinking(opts = {})
        thinking = opts[:thinking].to_s
        return '' if thinking.strip.empty?

        # Common end-of-reasoning markers across distill/abliterated builds.
        markers = [
          %r{</think>}i,
          %r{</thinking>}i,
          /(?:\A|\n)\s*Final\s*Answer\s*:\s*/i,
          /(?:\A|\n)\s*Answer\s*:\s*/i,
          # Inline form: "... Final Answer: <text>"
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

      # Merge an Ollama streaming body (NDJSON native /api/chat OR OpenAI-compat
      # SSE on /v1/chat/completions) into a single JSON string matching the
      # non-stream response shape used by #chat / #chat_with_tools.
      private_class_method def self.assemble_ollama_stream(opts = {})
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
          # Preserve a parseable shape so callers don't NPE, but mark the
          # failure explicitly — blank NDJSON previously became {} → nil msg
          # → silent "[pwn-ai] engine returned no message".
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
                        payloads.any? { |p| p.key?(:choices) }

        if openai_compat
          assemble_openai_compat_stream(payloads: payloads)
        else
          assemble_native_chat_stream(payloads: payloads)
        end
      end

      # Native Ollama /api/chat NDJSON → single-object JSON string.
      # Each chunk carries message.content delta (and optionally tool_calls);
      # the final chunk has done:true plus timing/usage fields.
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
          Array(msg[:tool_calls]).each do |tc|
            # Tool calls typically arrive complete in one chunk; append uniques.
            tool_calls << tc unless tool_calls.any? { |existing| existing == tc }
          end
        end

        # Thinking-only models (Qwen3 / DeepSeek-R1 style via Ollama) often
        # emit message.thinking deltas with message.content left blank. The
        # agent loop only displays msg[:content], so that looked like "no
        # response". Promote thinking → content when there is nothing else
        # visible and no tool_calls to act on.
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

      # OpenAI-compat /v1/chat/completions SSE → single chat.completion JSON.
      private_class_method def self.assemble_openai_compat_stream(opts = {})
        payloads = opts[:payloads]
        base = payloads.first || {}
        content = +''
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

        message = { role: role, content: content }
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
      # response = PWN::AI::Ollama.get_models

      public_class_method def self.get_models
        models = ollama_rest_call(rest_call: 'ollama/api/tags')

        JSON.parse(models, symbolize_names: true)[:models]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::AI::Ollama.chat_with_tools(
      #   messages: 'required - full OpenAI-format messages array (system/user/assistant/tool)',
      #   tools: 'optional - OpenAI tools array [{type:"function", function:{...}}]',
      #   tool_choice: 'optional - "auto" | "none" | {type:"function", function:{name:..}}',
      #   model: 'optional - overrides PWN::Env[:ai][:ollama][:model]',
      #   temp: 'optional - temperature (defaults to PWN::Env[:ai][:ollama][:temp] || 1)',
      #   timeout: 'optional - seconds (default 900)',
      #   spinner: 'optional - display spinner (default false)'
      # )
      #
      # Returns a Hash with :choices / :assistant_message intact (including
      # :message[:tool_calls]) — used by PWN::AI::Agent::Loop.
      #
      # LOCAL-MODEL SCAFFOLDING
      # -----------------------
      # This hits Ollama's NATIVE /api/chat (not the OpenAI-compat shim) so
      # the following actually take effect:
      #   options.num_ctx     - Ollama defaults to 2048; the pwn-ai system
      #                         prompt alone blows that. Defaults here to
      #                         PWN::Env[:ai][:ollama][:num_ctx] || 32768.
      #   options.temperature - forced to 0.1 on tool-bearing turns for
      #                         deterministic tool selection; engine[:temp]
      #                         (creative) on the final text-only turn.
      #   format              - ONLY set when engine[:format] is explicitly
      #                         configured. Never default to 'json' when
      #                         tools: are present — that fights native
      #                         tool_calls and kills mid-loop tool use.
      #   keep_alive: '30m'   - avoids reload latency between iterations.
      # tool_calls come back with function.arguments as a Hash (not a JSON
      # string), which PWN::AI::Agent::Dispatch.parse_args handles.
      # Streaming is ON (stream: true): ollama_rest_call assembles NDJSON
      # chunks back into a single response so the return shape is unchanged.

      public_class_method def self.chat_with_tools(opts = {})
        engine   = PWN::Env[:ai][:ollama]
        messages = opts[:messages]
        raise 'ERROR: messages array is required' if messages.nil? || messages.empty?

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f
        temp = engine[:temp].to_f.nonzero? || 1 if temp.zero?

        tools_present = opts[:tools] && !opts[:tools].empty?
        tool_temp     = (engine[:tool_temp] || 0.1).to_f
        num_ctx       = (engine[:num_ctx]   || 32_768).to_i
        # Hard cap generation length. Thinking models (Qwen3 / R1-style)
        # otherwise stream unbounded message.thinking tokens until the
        # idle read_timeout (default 900s) — which looks like a 15–25 min
        # "stuck spinner" while bytes keep arriving on the socket.
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
          # 0.2 — omit format when tools are present unless the operator
          # explicitly set PWN::Env[:ai][:ollama][:format]. Forcing 'json'
          # races the native tool_calls sampler and produces "can't call tools"
          # mid-loop on many local models.
          fmt = engine[:format]
          http_body[:format] = fmt unless fmt.nil? || fmt.to_s.empty?
        end
        http_body[:tool_choice] = opts[:tool_choice] if opts[:tool_choice]

        response = ollama_rest_call(
          http_method: :post,
          rest_call: 'ollama/api/chat',
          http_body: http_body,
          timeout: opts[:timeout],
          spinner: opts[:spinner]
        )
        raise 'ERROR: Ollama chat_with_tools received empty response from ollama_rest_call' if response.nil? || (response.respond_to?(:empty?) && response.empty?)

        json_resp = JSON.parse(response, symbolize_names: true)
        # Normalise native /api/chat shape to what Loop.normalize_llm expects.
        msg = json_resp[:message] || json_resp.dig(:choices, 0, :message)
        if msg.is_a?(Hash)
          content = msg[:content].to_s
          thinking = msg[:thinking].to_s
          tcalls = Array(msg[:tool_calls])
          msg = msg.merge(content: visible_from_thinking(thinking: thinking)) if content.strip.empty? && !thinking.strip.empty? && tcalls.empty?
        end
        json_resp[:choices] = [{ message: msg }] if msg && !json_resp.key?(:choices)
        json_resp[:assistant_message] = msg
        raise "ERROR: Ollama response missing message/choices: #{json_resp.inspect[0, 400]}" if msg.nil?

        json_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::AI::Ollama.chat(
      #   request: 'required - message to Ollama'
      #   model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:ollama][:model])',
      #   temp: 'optional - creative response float (deafults to PWN::Env[:ai][:ollama][:temp])',
      #   system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:ollama][:system_role_content])',
      #   response_history: 'optional - pass response back in to have a conversation',
      #   speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
      #   timeout: 'optional timeout in seconds (defaults to 900)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      public_class_method def self.chat(opts = {})
        engine = PWN::Env[:ai][:ollama]
        request = opts[:request]
        max_prompt_length = engine[:max_prompt_length] ||= 1_000_000
        request_trunc_idx = ((max_prompt_length - 1) / 3.36).floor
        request = request[0..request_trunc_idx]

        model = opts[:model] ||= engine[:model]
        raise 'ERROR: Model is required.  Call #get_models method for details' if model.nil?

        temp = opts[:temp].to_f ||= engine[:temp].to_f
        temp = 1 if temp.zero?

        rest_call = 'ollama/v1/chat/completions'

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
            request: 'required - message to Ollama',
            model: 'optional - model to use for text generation (defaults to PWN::Env[:ai][:ollama][:model])',
            temp: 'optional - creative response float (defaults to PWN::Env[:ai][:ollama][:temp])',
            system_role_content: 'optional - context to set up the model behavior for conversation (Default: PWN::Env[:ai][:ollama][:system_role_content])',
            response_history: 'optional - pass response back in to have a conversation',
            speak_answer: 'optional speak answer using PWN::Plugins::Voice.text_to_speech (Default: nil)',
            timeout: 'optional - timeout in seconds (defaults to 900)',
            spinner: 'optional - display spinner (defaults to false)'
          )

          #{self}.authors
        "
      end
    end
  end
end
