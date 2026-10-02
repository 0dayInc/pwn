# frozen_string_literal: true

require 'spec_helper'

describe 'Ollama and Open WebUI system-message placement' do
  it 'puts a later Ollama system message first so the chat template does not 500' do
    engine = { model: 'mini-mythos-mission-ready', num_ctx: 2048, keep_alive: '1m', temp: 0.1, tool_temp: 0.1 }
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:ai).and_return({ ollama: engine, active: 'ollama' })
    captured = nil
    allow(PWN::AI::Ollama).to receive(:ollama_rest_call) do |**kwargs|
      captured = kwargs[:http_body]
      '{"message":{"role":"assistant","content":"ok"}}'
    end
    PWN::AI::Ollama.chat_with_tools(
      model: 'mini-mythos-mission-ready',
      messages: [
        { role: 'user', content: 'hello' },
        { role: 'system', content: 'must lead' },
        { role: 'developer', content: 'also lead' }
      ]
    )
    expect(captured[:messages].map { |row| row[:role] }).to eq(%w[system user])
    expect(captured[:messages][0][:content]).to include('must lead', 'also lead')
  end

  it 'folds Open WebUI system text into the user message when the template rejects a second system role' do
    engine = { model: 'mini-mythos-mission-ready:latest', num_ctx: 2048, keep_alive: '1m', temp: 0.1, tool_temp: 0.1 }
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:ai).and_return({ openwebui: engine, active: 'openwebui' })
    PWN::AI::OpenWebUI.instance_variable_set(:@strict_system_cache, nil)
    captured = nil
    allow(PWN::AI::OpenWebUI).to receive(:openwebui_rest_call) do |**kwargs|
      if kwargs[:rest_call].to_s.end_with?('show')
        { template: "raise_exception('System message must be at the beginning.')" }.to_json
      else
        captured = kwargs[:http_body]
        '{"message":{"role":"assistant","content":"ok"}}'
      end
    end
    PWN::AI::OpenWebUI.chat_with_tools(
      model: 'mini-mythos-mission-ready:latest',
      messages: [
        { role: 'system', content: 'operator rules' },
        { role: 'user', content: 'ping' },
        { role: 'system', content: 'ENGAGEMENT MEMORY' }
      ]
    )
    expect(captured[:messages].map { |row| row[:role] }).to eq(%w[user])
    expect(captured[:messages][0][:content]).to include('operator rules', 'ENGAGEMENT MEMORY', 'ping')
  end
end
