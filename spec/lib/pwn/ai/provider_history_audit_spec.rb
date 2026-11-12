# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'net/http'

{ PWN::AI::OpenWebUI => :openwebui, PWN::AI::Ollama => :ollama }.each do |provider, key|
  RSpec.describe provider, 'history without token usage' do
    it 'continues the history returned by an SSE response with no usage frame' do
      stub_const('PWN::Env', { ai: { key => { model: 'fixture-history', key: 'fixture-key', base_uri: 'https://example.test' } } })
      allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
      described_class.instance_variable_set(:@strict_system_cache, nil)
      payloads = []
      allow(RestClient::Request).to receive(:execute) do |args|
        if args[:url].end_with?('/show')
          '{}'
        else
          payloads << JSON.parse(args.fetch(:payload))
          response = instance_double(Net::HTTPResponse, code: '200')
          stream = "data: #{JSON.generate(choices: [{ delta: { role: 'assistant', content: 'Fixture answer' }, finish_reason: 'stop' }])}\n\ndata: [DONE]\n\n"
          allow(response).to receive(:read_body).and_yield(stream)
          args.fetch(:block_response).call(response)
        end
      end
      first = described_class.chat(request: 'First fixture request')
      expect(first).not_to have_key(:usage)
      second = described_class.chat(request: 'Second fixture request', response_history: first)
      expect(second[:choices].last).to include(role: 'assistant', content: 'Fixture answer')
      expect(payloads.last.fetch('messages').map { |row| row['content'] }).to include('First fixture request', 'Fixture answer', 'Second fixture request')
    ensure
      described_class.instance_variable_set(:@strict_system_cache, nil)
    end
  end
end

RSpec.describe PWN::AI::Grok, 'quiet transport failure' do
  it 'preserves transport exceptions instead of masking them with NoMethodError' do
    stub_const('PWN::Env', { ai: { grok: { model: 'fixture', key: 'fixture-key' } } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    failure = IOError.new('fixture transport failure')
    allow(RestClient::Request).to receive(:execute).and_raise(failure)
    expect { described_class.chat(request: 'fixture', quiet: true) }.to(raise_error { |error| expect(error).to equal(failure) })
  end
end
