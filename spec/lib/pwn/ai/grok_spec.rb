# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Grok do
  it 'should display information for authors' do
    authors_response = PWN::AI::Grok
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Grok
    expect(help_response).to respond_to :help
  end

  it 'loads one priced model without listing the catalog' do
    allow(described_class).to receive(:grok_rest_call).and_return('{"id":"grok-4.7","prompt_text_token_price":20000,"completion_text_token_price":60000}')
    row = described_class.get_model(name: 'grok-4.7')
    expect(row[:id]).to eq('grok-4.7')
    expect(described_class).to have_received(:grok_rest_call).once
    expect { described_class.get_model(name: ' ') }.to raise_error(RuntimeError, /Model name is required/)
  end

  it 'chat_with_tools sanitizes messages via Loop.openai_wire_messages' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/openai_wire_messages/)
  end

  describe 'hosted retrieval on a conversational turn' do
    include_context 'pwn tmp sandbox'

    let(:sid) { PWN::Sessions.create[:id] }
    let(:request) { 'What does the current public bulletin say? Answer here in chat.' }

    before do
      PWN::Env[:ai][:active] = :grok
      PWN::Env[:ai][:grok] = { model: 'fixture-model', system_role_content: 'Original role.', server_tools: %w[web_search code_interpreter] }
      expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    end

    it 'describes only the lookup on the wire and delivers its public output items' do
      expect(described_class).to receive(:grok_rest_call).once do |call|
        expect(call[:rest_call]).to eq('responses')
        body = call.fetch(:http_body)
        expect(body.fetch(:tools)).to eq([{ type: 'web_search' }])
        expect(body.fetch(:input).first.fetch(:content)).to start_with('Original role.')
        system = body.fetch(:input).filter_map { |row| row[:content] if row[:role] == 'system' }.join("\n")
        expect(system).to include('Original role.', 'web_search')
        expect(system).not_to include('No tools on this turn', 'code_interpreter')
        JSON.generate(output: [
                        { type: 'reasoning', summary: [{ text: 'private' }] },
                        { type: 'web_search_call', status: 'completed' },
                        { type: 'message', role: 'assistant', status: 'completed', content: [
                          { type: 'output_text', text: 'Public ' }, { type: 'output_text', text: 'reply.' }
                        ] }
                      ])
      end

      expect(PWN::AI::Agent::Loop.run(request: request, session_id: sid)).to eq('Public reply.')
      expect(PWN::Sessions.load(session_id: sid).last).to include(role: 'assistant', content: 'Public reply.')
    end

    it 'describes a missing source without offering one when the operator disables tools' do
      expect(described_class).to receive(:grok_rest_call).once do |call|
        expect(call[:rest_call]).to eq('chat/completions')
        body = call.fetch(:http_body)
        expect(body).not_to have_key(:tools)
        system = body.fetch(:messages).filter_map { |row| row[:content] if row[:role] == 'system' }.join("\n")
        expect(system).to include('No online source')
        expect(system).not_to include('web_search')
        reply = { pwn_turn: 'partial', text: 'Please supply the source text.', remaining: 'source' }
        JSON.generate(choices: [{ message: { role: 'assistant', content: JSON.generate(reply) } }])
      end

      outcome = nil
      text = PWN::AI::Agent::Loop.run(request: request, session_id: sid, enabled_toolsets: [], on_outcome: ->(row) { outcome = row })
      expect(text).to eq('Please supply the source text.')
      expect(outcome).to include(status: 'incomplete', goal_status: 'partial')
    end

    it 'does not accept unfinished hosted output as a public answer' do
      expect(described_class).to receive(:grok_rest_call).once.and_return(JSON.generate(status: 'incomplete', output_text: 'unfinished fixture'))
      expect do
        described_class.chat_with_tools(messages: [{ role: 'user', content: request }], server_tools: ['web_search'])
      end.to raise_error(RuntimeError, /hosted response did not complete/)
    end

    it 'does not stringify internal output when a hosted response has no public text' do
      raw = JSON.generate(output_text: { metadata: 'private' }, output: [{ type: 'reasoning', content: [{ text: 'private' }] }])
      expect(described_class).to receive(:grok_rest_call).once.and_return(raw)
      expect do
        described_class.chat_with_tools(messages: [{ role: 'user', content: request }], server_tools: ['web_search'])
      end.to raise_error(RuntimeError, /no public assistant text/)
    end
  end

  describe '.chat_with_tools HTTP failures' do
    let(:messages) { [{ role: 'user', content: 'hello' }] }
    let(:body) { '{"error":"Invalid schema: tools[0].function.parameters requires properties"}' }
    let(:response) { instance_double(RestClient::Response, code: 400, body: body, to_s: body) }
    let(:error) { RestClient::BadRequest.new(response) }

    before do
      stub_const('PWN::Env', { ai: { grok: { key: 'test-key', model: 'test-model' } } })
      allow(PWN::Plugins::TransparentBrowser).to receive(:open).with(browser_type: :rest).and_return(browser: RestClient)
      allow(PWN::AI::Agent::ToolGuard).to receive(:protect_http!)
      allow(PWN::AI::Agent::PromptCache).to receive(:enabled?).and_return(false)
      allow(PWN::Plugins::TTYSpinner).to receive(:stop)
      allow(RestClient::Request).to receive(:execute).and_raise(error)
    end

    it 'serializes explicit artifact_read branch types from the real registry' do
      tools = PWN::AI::Agent::Registry.definitions(core_only: true)
      allow(RestClient::Request).to receive(:execute).and_return(
        '{"choices":[{"message":{"role":"assistant","content":"hello"}}]}'
      )

      described_class.chat_with_tools(messages: messages, tools: tools)

      expect(RestClient::Request).to have_received(:execute) do |request|
        payload = JSON.parse(request[:payload])
        artifact_read = payload.fetch('tools').find { |tool| tool.dig('function', 'name') == 'artifact_read' }
        expect(artifact_read).not_to be_nil
        branches = artifact_read.fetch('function').fetch('parameters').fetch('anyOf')
        expect(branches).not_to be_empty
        expect(branches).to all(include('type' => 'object'))
      end
    end

    context 'when a model request is forbidden' do
      def denial(fields, effort: 'high', hosted: false, content_type: 'application/json')
        raw = fields.is_a?(String) ? fields : JSON.generate(fields)
        reply = instance_double(RestClient::Response, code: 403, body: raw, headers: { content_type: content_type })
        allow(RestClient::Request).to receive(:execute).and_raise(RestClient::Forbidden.new(reply))
        described_class.chat_with_tools(messages: messages, model: 'grok-4.7', reasoning_effort: effort, server_tools: (['web_search'] if hosted))
        raise 'expected the request to stay forbidden'
      rescue RestClient::Forbidden => e
        expect(e.response).to equal(reply)
        e.message
      end

      it 'distinguishes a model limitation from a subscription restriction' do
        ['The selected model does not support the requested reasoning_effort.', 'Model grok-4.7 does not support parameter reasoning_effort.'].each do |reason|
          text = denial({ error: { message: "#{reason} Check your subscription details." } })
          expect(text).to include('The selected Grok model does not support the "high" reasoning effort.')
          expect(text).not_to include('subscription')
        end
      end

      it 'reads the error parameter, provider message or explicit code without publishing any of them verbatim' do
        reasons = [
          { error: { param: 'reasoning.effort', message: 'Not available on your current plan. Private detail.' } },
          { code: 'permission-denied', error: 'Your subscription tier does not support high reasoning effort. Private detail.' },
          { error: { code: 'reasoning_effort_requires_higher_tier', message: 'Private detail.' } },
          { error: { param: 'reasoning_effort', code: 'subscription_required' } },
          { error: { code: 'insufficient_scope', message: 'This reasoning effort is not available for your subscription.' } },
          { error: 'The high reasoning effort is only available to SuperGrok Heavy subscribers.' }
        ]
        reasons.each do |fields|
          message = denial(fields)
          expect(message).to include('Your current Grok subscription does not include the "high" reasoning effort.')
          expect(message).not_to include('Private detail')
        end
      end

      it 'reports an unsupported effort without guessing who restricted it' do
        message = denial({ error: { code: 'unsupported_reasoning_effort' } })
        expect(message).to include('Grok rejected the "high" reasoning effort without specifying why.')
        expect(message).not_to include('subscription')
        explanation = denial({ error: { code: 'unsupported_reasoning_effort', message: 'Your plan does not allow high reasoning effort.' } })
        expect(explanation).to include('Your current Grok subscription')
      end

      it 'recognizes an explicit plain-text reason but not a proxy error page' do
        reason = 'Reasoning effort high is not included in your plan. Private fixture detail.'
        expect(denial(reason, content_type: 'text/plain; charset=utf-8')).to include('Your current Grok subscription')
        expect(denial(reason, content_type: 'text/html')).not_to match(/subscription|Private fixture detail/)
      end

      it 'names the serialized level even when it differs from the input option' do
        message = denial({ error: { param: 'reasoning_effort', message: 'Your plan does not include this setting.' } }, effort: 'none')
        expect(message).to include('Your current Grok subscription does not include the "low" reasoning effort.')
        expect(RestClient::Request).to have_received(:execute).once do |call|
          expect(JSON.parse(call.fetch(:payload)).fetch('reasoning_effort')).to eq('low')
        end
      end

      it 'does not infer an effort restriction from unrelated, ambiguous, or unreadable errors' do
        unrelated = [
          { error: { message: 'Your subscription does not include this model. Request contained reasoning_effort=high.' } },
          { error: { message: 'Your plan supports high reasoning effort. Access to this endpoint is denied.' } },
          { error: { param: 'model', message: 'Not available on your current plan.' } },
          { error: { message: 'Reasoning effort low is unavailable on this plan.' } },
          { error: { code: 'model_not_found', message: 'Reasoning effort high is not supported on your plan.' } },
          { error: { message: 'Your plan does not support reasoning effort reporting.' } },
          { error: { code: 'insufficient_quota', message: 'Private detail.' } },
          '{invalid', "\xff".b, JSON.generate(message: 'x' * 20_000)
        ]
        unrelated.each do |fields|
          expect(denial(fields)).to eq('Grok denied the request (HTTP 403). Check access to the selected model and endpoint.')
        end
      end

      it 'does not blame a configured effort on a hosted request that omitted it' do
        message = denial({ error: 'Reasoning effort high is not available on your current subscription.' }, hosted: true)
        expect(message).to include('HTTP 403')
        expect(message).not_to match(/subscription|effort/)
        expect(RestClient::Request).to have_received(:execute).once do |call|
          expect(call.fetch(:url)).to end_with('/responses')
          expect(JSON.parse(call.fetch(:payload)).keys).not_to include('reasoning', 'reasoning_effort')
        end
      end
    end

    context 'when rate limits exhaust the retry budget' do
      let(:body) { '{"error":"rate limit exceeded"}' }
      let(:response) { instance_double(RestClient::Response, code: 429, body: body, to_s: body, headers: { retry_after: '2' }) }
      let(:error) { RestClient::TooManyRequests.new(response) }

      it 'raises the HTTP error after five attempts and four Retry-After waits' do
        allow(described_class).to receive(:rand).with(0.3..5.0).and_return(0.5)
        allow(described_class).to receive(:sleep)
        allow(PWN::AI::HttpRetry).to receive(:report_event)

        expect do
          described_class.chat_with_tools(messages: messages)
        end.to raise_error(RestClient::TooManyRequests) { |raised|
          expect(raised.message).to include('HTTP 429', body)
        }
        expect(RestClient::Request).to have_received(:execute).exactly(5).times
        expect(described_class).to have_received(:sleep).with(2.5).exactly(4).times
      end
    end

    context 'when the request times out' do
      let(:error) { RestClient::Exceptions::ReadTimeout.new }

      it 'preserves the default five attempts and nil on exhaustion' do
        allow(PWN::AI::HttpRetry).to receive(:report_event)
        expect(described_class.chat_with_tools(messages: messages)).to be_nil
        expect(RestClient::Request).to have_received(:execute).with(hash_including(timeout: 180)).exactly(5).times
      end

      it 'keeps quiet sidecars single-shot and silent' do
        expect(PWN::AI::HttpRetry).not_to receive(:report_event)
        expect(described_class.chat_with_tools(messages: messages, quiet: true)).to be_nil
        expect(RestClient::Request).to have_received(:execute).once
      end

      it 'keeps short timeouts single-shot' do
        allow(PWN::AI::HttpRetry).to receive(:report_event)
        expect(described_class.chat_with_tools(messages: messages, timeout: 10)).to be_nil
        expect(RestClient::Request).to have_received(:execute).with(hash_including(timeout: 10)).once
      end

      it 'returns the successful response after a transient timeout' do
        calls = 0
        allow(RestClient::Request).to receive(:execute) do
          calls += 1
          raise error if calls == 1

          '{"choices":[{"message":{"role":"assistant","content":"hello"}}]}'
        end
        allow(PWN::AI::HttpRetry).to receive(:report_event)
        result = described_class.chat_with_tools(messages: messages)
        expect(result.dig(:assistant_message, :content)).to eq('hello')
        expect(RestClient::Request).to have_received(:execute).twice
      end
    end

    [false, true].each do |quiet|
      it "propagates actionable schema errors without printing (quiet=#{quiet})" do
        expect do
          expect do
            described_class.chat_with_tools(messages: messages, quiet: quiet)
          end.to raise_error(RestClient::BadRequest) { |raised|
            expect(raised.response).to equal(response)
            expect(raised.message).to include('Grok', 'HTTP 400', 'chat/completions', body)
          }
        end.not_to output.to_stdout
        expect(RestClient::Request).to have_received(:execute).once
        expect(PWN::Plugins::TTYSpinner).to have_received(:stop)
      end
    end
  end

  it 'does not expose get_plan_usage' do
    expect(described_class).not_to respond_to(:get_plan_usage)
  end

  it 'grok_rest_call swallows ReadTimeout quietly without ERROR: print' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/RestClient::Exceptions::Timeout/)
    expect(src).to match(/quiet: opts\[:quiet\]/)
    expect(src).to include('Timed out reading data from server')
    timeout_rescue = src[/rescue RestClient::Exceptions::Timeout.*?rescue RestClient::ExceptionWithResponse/m]
    expect(timeout_rescue).not_to match(/puts "ERROR:/)
    expect(timeout_rescue).to match(/opts\[:quiet\]/)
  end

  it 'chat_with_tools honors PromptCache when prompt_cache is on' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to include('PromptCache.openai_messages')
    expect(src).to include('x-grok-conv-id')
    expect(src).to include('enabled?(engine: :grok)')
  end

  it 'grok_rest_call stops the spinner via TTYSpinner (joins worker after response)' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to include('PWN::Plugins::TTYSpinner.start')
    expect(src).to include('PWN::Plugins::TTYSpinner.stop(spin: spin)')
    expect(src).not_to match(/spin\.stop if spinner/)
  end

  it 'does not nil+ on 429 without Retry-After and does not retry 429 forever' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).not_to match(/headers\[:retry_after\]&.to_i\s*\|\|=/)
    expect(src).to match(/HttpRetry\.retry_after_s|headers\[:retry_after\]\.to_i/)
    expect(src).to match(/HttpRetry\.max_attempts|max_attempts/)
  end

  it 'defaults chat REST timeout to 180s and retries ReadTimeout up to 5 times' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/HttpRetry|timeout \|\|= 180/)
    expect(src).not_to match(/timeout \|\|= 900/)
    expect(src).to match(/HttpRetry\.max_attempts|max_attempts/)
    inner = src[/retry_count = 0.*?rescue RestClient::Exceptions::Timeout/m]
    expect(inner).to include('TooManyRequests')
    expect(inner).to include('Exceptions::Timeout')
  end

  it 'tees grok timeout/429 warnings into the debug request log' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/HttpRetry\.report_event|Log\.progress/)
  end

  it 'keeps a device grant in the request runtime and does not print the tokens' do
    runtime = Class.new do
      def initialize
        @config = { grok: { oauth: { refresh_token: 'dead-refresh', bearer_token: 'expired-bearer' } } }
      end

      def provider_config(engine)
        Marshal.load(Marshal.dump(@config[engine.to_sym] || {}))
      end

      def update_provider_oauth(engine, oauth)
        @config[engine.to_sym][:oauth] = Marshal.load(Marshal.dump(oauth))
        :updated
      end
    end.new
    Thread.current[:pwn_request_runtime] = runtime
    allow(described_class).to receive(:sleep)
    allow(described_class).to receive(:persist_oauth_to_vault).and_return(false)
    allow(RestClient).to receive(:post).and_return(
      double(body: { device_code: 'dev', user_code: 'CODE', verification_uri: 'https://example.invalid/device', interval: 0, expires_in: 30 }.to_json),
      double(body: { access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600 }.to_json)
    )
    output = StringIO.new
    original = $stdout
    $stdout = output
    copy = runtime.provider_config(:grok)[:oauth]
    expect(described_class.obtain_oauth_bearer_token(copy)).to eq('new-access')
    expect(runtime.provider_config(:grok)[:oauth]).to include(bearer_token: 'new-access', refresh_token: 'new-refresh')
    expect(output.string).not_to include('new-access', 'new-refresh', 'dead-refresh')
    expect(output.string).to include('session only')
  ensure
    $stdout = original if original
    Thread.current[:pwn_request_runtime] = nil
  end
end
