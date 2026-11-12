# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Grok, 'reasoning effort wire' do
  let(:completion) { { choices: [{ message: { role: 'assistant', content: 'ok' } }] }.to_json }

  before do
    allow(PWN::AI::HttpRetry).to receive(:provider_config).and_return(
      model: 'grok-4.6', temp: 1, system_role_content: 'fixture', max_prompt_length: 256_000
    )
    allow(PWN::AI::Agent::PromptCache).to receive(:enabled?).and_return(false)
    allow(described_class).to receive(:grok_rest_call).and_return(completion)
  end

  it 'maps reasoning_effort none to low for grok-4.6 chat' do
    described_class.chat(request: 'title', model: 'grok-4.6', reasoning_effort: 'none', quiet: true, spinner: false)
    expect(described_class).to have_received(:grok_rest_call).with(
      hash_including(http_body: hash_including(model: 'grok-4.6', reasoning_effort: 'low'))
    )
  end

  it 'maps reasoning_effort none to low for grok-4.7 chat' do
    described_class.chat(request: 'title', model: 'grok-4.7', reasoning_effort: 'none', quiet: true, spinner: false)
    expect(described_class).to have_received(:grok_rest_call).with(
      hash_including(http_body: hash_including(model: 'grok-4.7', reasoning_effort: 'low'))
    )
  end

  it 'omits reasoning_effort none for a Grok model with no effort menu' do
    described_class.chat(request: 'title', model: 'grok-4', reasoning_effort: 'none', quiet: true, spinner: false)
    expect(described_class).to have_received(:grok_rest_call).with(
      hash_including(http_body: satisfy { |body| !body.key?(:reasoning_effort) })
    )
  end

  it 'keeps an explicit supported effort' do
    described_class.chat(request: 'title', model: 'grok-4.6', reasoning_effort: 'high', quiet: true, spinner: false)
    expect(described_class).to have_received(:grok_rest_call).with(
      hash_including(http_body: hash_including(reasoning_effort: 'high'))
    )
  end
end
