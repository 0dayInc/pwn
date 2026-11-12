# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Metrics, 'persisted model usage' do
  include_context 'pwn tmp sandbox'

  it 'accumulates repeated model calls after the JSON key roundtrip' do
    described_class.record_tokens(model: 'fixture-model', tokens: 10, cost: 0.1)
    described_class.record_tokens(model: 'fixture-model', tokens: 20, cost: 0.2)
    described_class.record_tokens(model: 'other-model', tokens: 7, cost: 0.0)
    usage = described_class.usage
    expect(usage).to include(tokens: 37, calls: 3)
    expect(usage[:by_model][:'fixture-model']).to include(tokens: 30, calls: 2)
    expect(usage[:by_model][:'fixture-model'][:cost]).to be_within(0.000001).of(0.3)
    expect(usage[:by_model][:'other-model']).to include(tokens: 7, calls: 1)
    raw = JSON.parse(File.read(described_class::METRICS_FILE))
    expect(raw['usage']['by_model'].keys).to contain_exactly('fixture-model', 'other-model')
  end
end
