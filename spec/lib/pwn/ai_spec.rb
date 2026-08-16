# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI do
  it 'should return data for help method' do
    help_response = PWN::AI.help
    expect(help_response).not_to be_nil
  end

  it 'normalizes used/limit into a clamped percentage' do
    usage = described_class.normalize_plan_usage(used: 19, limit: 100, engine: :grok)
    expect(usage[:available]).to be true
    expect(usage[:percent]).to eq(19)
  end

  it 'returns the infinity glyph for ollama and openwebui' do
    expect(described_class.plan_usage_glyph(engine: :ollama)).to eq("\u221E")
    expect(described_class.plan_usage_glyph(engine: :openwebui)).to eq("\u221E")
  end

  it 'returns a percent glyph when usage data is available' do
    glyph = described_class.plan_usage_glyph(
      engine: :grok,
      usage: { available: true, percent: 19 }
    )
    expect(glyph).to eq('19%')
  end

  it 'returns infinity when a hosted engine has no usage data' do
    expect(described_class.plan_usage_glyph(engine: :gemini, usage: { available: false })).to eq("\u221E")
  end
end
