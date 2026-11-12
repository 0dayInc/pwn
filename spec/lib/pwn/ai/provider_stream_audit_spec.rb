# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'net/http'

{
  PWN::AI::Ollama => :ollama,
  PWN::AI::OpenWebUI => :openwebui
}.each do |provider, key|
  RSpec.describe provider, 'stream error regressions' do
    before do
      stub_const('PWN::Env', { ai: { key => { model: 'fixture', key: 'fixture-key', base_uri: 'https://example.test' } } })
      allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
      provider.instance_variable_set(:@strict_system_cache, nil)
      allow(RestClient::Request).to receive(:execute) do |args|
        if args[:url].end_with?('/show')
          '{}'
        else
          response = instance_double(Net::HTTPResponse, code: '200')
          allow(response).to receive(:read_body).and_yield(@stream)
          args.fetch(:block_response).call(response)
        end
      end
    end

    after { provider.instance_variable_set(:@strict_system_cache, nil) }

    ['fixture backend failed', { message: 'fixture backend failed', type: 'server_error' }].each do |error|
      it "does not convert a native #{error.class} error frame to successful partial output" do
        @stream = [
          { message: { role: 'assistant', content: 'Partial answer' }, done: false }.to_json,
          { error: error }.to_json
        ].join("\n")
        expect do
          provider.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1)
        end.to raise_error(RuntimeError, /#{key == :ollama ? 'Ollama' : 'Open WebUI'}.*fixture backend failed/)
      end
    end

    if key == :openwebui
      it 'preserves an SSE provider error instead of returning a successful partial answer' do
        @stream = "data: #{JSON.generate(choices: [{ delta: { content: 'Partial' } }])}\n\n"
        @stream << "data: #{JSON.generate(error: { message: 'fixture backend failed' })}\n\n"
        expect { provider.chat(request: 'fixture', timeout: 1) }.to raise_error(RuntimeError, /Open WebUI.*fixture backend failed/)
      end
    end
  end
end
