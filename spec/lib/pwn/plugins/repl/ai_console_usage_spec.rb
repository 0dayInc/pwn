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
    allow(PWN::AI::OpenAI).to receive(:get_model).and_return(id: 'unknown')
    tracker.record(engine: :openai, model: 'unknown', usage: { prompt_tokens: 10, completion_tokens: 5 })
    mixed = tracker.snapshot
    expect(mixed[:calls]).to eq(2)
    expect(mixed[:cost_status]).to include('partial')
    expect(described_class.estimate(usage: { input_tokens: 5 }, rates: nil)).to be_nil
  end

  it 'prices tokens from each provider model record and does not invent a missing price' do
    described_class.send(:catalog_cache).clear
    allow(PWN::AI::Grok).to receive(:get_model).and_return(
      id: 'grok-4.7',
      prompt_text_token_price: 20_000,
      completion_text_token_price: 60_000,
      cached_prompt_text_token_price: 5_000,
      prompt_text_token_price_long_context: 40_000,
      completion_text_token_price_long_context: 120_000,
      long_context_threshold: 200_000
    )
    usage = { input_tokens: 100_000, output_tokens: 1_000, input_tokens_details: { cached_tokens: 10_000 } }
    grok = described_class.estimate(engine: :grok, model: 'grok-4.7', usage: usage)
    expect(grok).to be_within(0.0001).of(0.18 + 0.005 + 0.006)
    long = described_class.estimate(engine: :grok, model: 'grok-4.7', usage: { input_tokens: 200_000, output_tokens: 0 })
    expect(long).to be_within(0.0001).of(0.8)
    expect(PWN::AI::Grok).to have_received(:get_model).once.with(hash_including(name: 'grok-4.7', timeout: 8, fallback: false, non_interactive: true))

    allow(PWN::AI::Grok).to receive(:get_model).and_return(id: 'unpublished', prompt_text_token_price: 0, completion_text_token_price: 0)
    expect(described_class.estimate(engine: :grok, model: 'unpublished', usage: { input_tokens: 10, output_tokens: 1 })).to be_nil

    allow(PWN::AI::OpenAI).to receive(:get_model).and_return(slug: 'gpt-5.5', pricing: { input: 5, output: 30, cached_input: 0.5 })
    expect(described_class.estimate(engine: :openai, model: 'gpt-5.5', usage: { input_tokens: 2_000_000, output_tokens: 0 })).to be_within(0.0001).of(10)

    allow(PWN::AI::OpenWebUI).to receive(:get_model).and_return(
      id: 'proxy-model',
      info: { meta: { pricing: { input_cost_per_token: 0.000002, output_cost_per_token: 0.000008 } } }
    )
    webui = described_class.estimate(engine: :openwebui, model: 'proxy-model', usage: { prompt_tokens: 1_000_000, completion_tokens: 1_000 })
    expect(webui).to be_within(0.0001).of(2.008)

    allow(PWN::AI::Ollama).to receive(:get_model).and_return(name: 'llama3.2', details: { family: 'llama' })
    expect(described_class.estimate(engine: :ollama, model: 'llama3.2', usage: { input_tokens: 10, output_tokens: 2 })).to be_nil

    allow(PWN::AI::Gemini).to receive(:get_model).and_return(name: 'models/gemini-2.5-pro', inputTokenLimit: 1_000_000)
    expect(described_class.estimate(engine: :gemini, model: 'gemini-2.5-pro', usage: { input_tokens: 8, output_tokens: 1 })).to be_nil

    allow(PWN::AI::Anthropic).to receive(:get_model).and_return(id: 'claude-mythos-5', display_name: 'Mythos')
    stub_const('PWN::Env', { ai: { anthropic: { pricing: { 'claude-mythos-5' => { input_per_million: 10, output_per_million: 50 } } } } })
    fallback = described_class.estimate(engine: :anthropic, model: 'claude-mythos-5', usage: { input_tokens: 1_000_000, output_tokens: 0 })
    expect(fallback).to be_within(0.0001).of(10)

    tracker = described_class::Tracker.new
    tracker.record(engine: :grok, model: 'grok-4.7', usage: usage)
    expect(tracker.snapshot[:cost_status]).to include('provider model pricing')
    expect(tracker.snapshot[:estimated_cost_usd]).to be_within(0.0001).of(0.191)
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
