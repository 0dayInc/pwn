# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Open WebUI workspace tools' do
  before do
    Thread.current[:pwn_openwebui_workspace_tools] = nil
    allow(PWN::AI::HttpRetry).to receive(:provider_config).with(engine: :openwebui).and_return(
      { model: 'llama', temp: 1, max_prompt_length: 10_000, system_role_content: 'sys' }
    )
    allow(PWN::AI::OpenWebUI).to receive(:strict_system_template?).and_return(false)
    allow(PWN::AI::OpenWebUI).to receive(:workspace_tools).and_return([{ id: 'ask_jev', name: 'Ask Jev' }])
  end

  it 'asks the server to run Ask Jev and does not send client tools' do
    captured = nil
    allow(PWN::AI::OpenWebUI).to receive(:openwebui_rest_call) do |opts|
      captured = opts[:http_body]
      { choices: [{ message: { role: 'assistant', content: '0.82 yes' } }], sources: [] }.to_json
    end

    result = PWN::AI::OpenWebUI.chat(request: 'Is the login bypassed?', server_tools: ['Ask Jev'], spinner: false)

    expect(captured[:tool_ids]).to eq(['ask_jev'])
    expect(captured[:params]).to eq({ function_calling: 'legacy' })
    expect(captured[:stream]).to be(false)
    expect(captured).not_to have_key(:tools)
    expect(result[:choices].last[:content]).to eq('0.82 yes')
  end

  it 'does not run workspace tools on the proxied Ollama chat path' do
    expect do
      PWN::AI::OpenWebUI.chat_with_tools(messages: [{ role: 'user', content: 'hi' }], server_tools: ['Ask Jev'])
    end.to raise_error(ArgumentError, /proxied Ollama/)
  end
end
