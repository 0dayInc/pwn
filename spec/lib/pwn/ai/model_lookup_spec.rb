# frozen_string_literal: true

require 'spec_helper'

describe 'provider get_model routes' do
  it 'asks each engine for one model on that engine route' do
    allow(PWN::AI::Anthropic).to receive(:anthropic_rest_call).and_return('{"id":"claude-mythos-5","type":"model"}')
    expect(PWN::AI::Anthropic.get_model(name: 'claude-mythos-5')[:id]).to eq('claude-mythos-5')
    expect(PWN::AI::Anthropic).to have_received(:anthropic_rest_call).with(hash_including(rest_call: 'models/claude-mythos-5'))

    allow(PWN::AI::Gemini).to receive(:gemini_rest_call).and_return('{"name":"models/gemini-2.5-pro"}')
    expect(PWN::AI::Gemini.get_model(name: 'models/gemini-2.5-pro')[:name]).to eq('models/gemini-2.5-pro')
    expect(PWN::AI::Gemini).to have_received(:gemini_rest_call).with(hash_including(rest_call: 'models/gemini-2.5-pro'))

    allow(PWN::AI::Ollama).to receive(:ollama_rest_call).and_return('{"name":"llama3.2","model":"llama3.2"}')
    expect(PWN::AI::Ollama.get_model(name: 'llama3.2')[:model]).to eq('llama3.2')
    expect(PWN::AI::Ollama).to have_received(:ollama_rest_call).with(hash_including(http_method: :post, rest_call: 'api/show'))

    allow(PWN::AI::OpenAI).to receive(:open_ai_rest_call).and_return('{"slug":"gpt-5.5"}')
    expect(PWN::AI::OpenAI.get_model(name: 'gpt-5.5')[:slug]).to eq('gpt-5.5')
    expect(PWN::AI::OpenAI).to have_received(:open_ai_rest_call).with(hash_including(rest_call: 'models/gpt-5.5'))

    allow(PWN::AI::OpenWebUI).to receive(:openwebui_rest_call).and_return('{"id":"proxy-model"}')
    expect(PWN::AI::OpenWebUI.get_model(name: 'proxy-model')[:id]).to eq('proxy-model')
    expect(PWN::AI::OpenWebUI).to have_received(:openwebui_rest_call).with(hash_including(rest_call: 'api/v1/models/proxy-model'))
  end
end
