# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL::AIConsoleUsage do
  it 'counts provider tokens once and estimates only configured USD rates' do
    tracker = described_class::Tracker.new
    tracker.record(engine: :openai, model: 'priced', usage: { input_tokens: 1_000_000, output_tokens: 1_000, input_tokens_details: { cached_tokens: 100 } }, rates: { input_per_million: 2, output_per_million: 8, cache_read_per_million: 1 })
    priced = tracker.snapshot
    expect(priced[:input_tokens]).to eq(1_000_000)
    expect(priced[:cached_tokens]).to eq(100)
    expect(priced[:total_tokens]).to eq(1_001_000)
    expect(priced[:estimated_cost_usd]).to be_within(0.001).of((2 * 0.9999) + 0.0001 + 0.008)
    tracker.record(engine: :openai, model: 'unknown', usage: { prompt_tokens: 10, completion_tokens: 5 })
    mixed = tracker.snapshot
    expect(mixed[:calls]).to eq(2)
    expect(mixed[:cost_status]).to include('partial')
    expect(described_class.estimate(usage: { input_tokens: 5 }, rates: nil)).to be_nil
  end

  it 'receives one Loop completion even when provider config is frozen' do
    tracker = described_class::Tracker.new
    Thread.current[:pwn_usage_observer] = tracker.method(:record)
    PWN::AI::Agent::Loop.send(:publish_usage, response: { model: 'offline', usage: { input_tokens: 3, output_tokens: 4 } }, engine: :missing)
    expect(tracker.snapshot[:total_tokens]).to eq(7)
  ensure
    Thread.current[:pwn_usage_observer] = nil
  end
end
