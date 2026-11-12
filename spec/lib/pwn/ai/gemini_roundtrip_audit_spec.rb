# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::AI::Gemini, 'native content round trips' do
  before do
    stub_const('PWN::Env', { ai: { gemini: { model: 'gemini-fixture', key: 'fixture-key' } } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
  end

  [false, true].each do |string_keys|
    it "retains native part metadata and strips only local call IDs (string_keys=#{string_keys})" do
      native = { functionCall: { name: 'fixture_tool', args: { value: 'source' } }, thoughtSignature: 'fixture-signature' }
      requests = []
      allow(RestClient::Request).to receive(:execute) do |args|
        requests << JSON.parse(args.fetch(:payload))
        body = { candidates: [{ content: { parts: [native] } }] }.to_json
        instance_double(RestClient::Response, body: body)
      end
      first = described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }])
      call_id = first.dig(:assistant_message, :tool_calls, 0, :id)
      history = [first[:assistant_message], { role: 'tool', tool_call_id: call_id, content: '{"ok":true}' }]
      history = JSON.parse(JSON.generate(history)) if string_keys
      original = Marshal.dump(history)
      described_class.chat_with_tools(messages: history)
      contents = requests.last.fetch('contents')
      expect(contents.first.fetch('parts')).to eq([JSON.parse(JSON.generate(native))])
      expect(contents.last.dig('parts', 0, 'functionResponse')).to eq('name' => 'fixture_tool', 'response' => { 'ok' => true })
      expect(Marshal.dump(history)).to eq(original)
    end
  end
end
