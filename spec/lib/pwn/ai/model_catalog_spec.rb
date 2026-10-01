# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::ModelCatalog do
  it 'finds a named row across provider catalog shapes' do
    grok = described_class.find_row(models: [{ id: 'grok-4.7', aliases: ['grok-latest'] }], name: 'grok-latest')
    expect(grok[:id]).to eq('grok-4.7')

    openai = described_class.find_row(models: { models: [{ slug: 'gpt-5.5' }] }, name: 'gpt-5.5')
    expect(openai[:slug]).to eq('gpt-5.5')

    gemini = described_class.find_row(models: [{ name: 'models/gemini-2.5-pro' }], name: 'gemini-2.5-pro')
    expect(gemini[:name]).to eq('models/gemini-2.5-pro')

    ollama = described_class.find_row(models: { models: [{ name: 'llama3.2', model: 'llama3.2:latest' }] }, name: 'llama3.2')
    expect(ollama[:model]).to eq('llama3.2:latest')
  end

  it 'rejects error strings and keeps a short non-interactive lookup' do
    expect(described_class.parse_row(raw: 'ERROR: timed out')).to be_nil
    expect(described_class.model_row?(row: { error: 'missing' })).to be false
    expect(described_class.lookup_opts(timeout: 8)[:non_interactive]).to be true
    expect(described_class.lookup_opts(timeout: 8)[:timeout]).to eq(8)
  end
end
