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

  it 'chat_with_tools sanitizes messages via Loop.openai_wire_messages' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/openai_wire_messages/)
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
end
