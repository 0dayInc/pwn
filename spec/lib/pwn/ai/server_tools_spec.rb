# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::ServerTools do
  it 'does not invent a workspace for Ollama' do
    expect(described_class.catalog(engine: :ollama)).to include(workspace: false, tools: [])
    expect(described_class.call(name: 'web_search', request: 'today', engine: :ollama)).to include(available: false)
  end

  it 'keeps Ask Jev on Open WebUI when another model is active' do
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :openwebui).and_return({ base_uri: 'https://ow.example', key: 'token' })
    allow(PWN::Env).to receive(:dig).with(:ai, :active).and_return(:grok)
    allow(PWN::AI::OpenWebUI).to receive(:workspace_tools).and_return([{ id: 'ask_jev', name: 'Ask Jev' }])
    allow(PWN::AI::OpenWebUI).to receive(:chat).and_return({ choices: [{ role: 'assistant', content: 'yes 0.8' }], sources: [{ name: 'Ask Jev' }] })

    result = described_class.call(name: 'Ask Jev', request: 'Is the login bypassed?', engine: :grok)

    expect(result).to include(available: true, engine: :openwebui, content: 'yes 0.8')
    expect(PWN::AI::OpenWebUI).to have_received(:chat).with(hash_including(server_tools: ['Ask Jev'], request: 'Is the login bypassed?'))
  end

  it 'appends a hosted tool beside client function tools' do
    body = described_class.attach(
      engine: :anthropic,
      http_body: { tools: [{ name: 'shell', input_schema: { type: 'object' } }] },
      request: { server_tools: ['web_search'] }
    )
    expect(body[:tools].last).to include(type: 'web_search_20250305', name: 'web_search')
    expect(body[:tools].first[:name]).to eq('shell')
  end

  it 'refuses to mix OpenAI hosted tools into a chat-completions body' do
    expect do
      described_class.attach(engine: :openai, http_body: { messages: [] }, request: { server_tools: ['web_search'] })
    end.to raise_error(ArgumentError, /Responses API/)
  end
end
