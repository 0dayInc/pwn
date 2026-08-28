# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe 'scoreboard roadmap gates' do
  it 'heuristic judge never stamps solved 0.9 from overlap' do
    v = PWN::AI::Agent::Reward.send(
      :heuristic_judge,
      request: 'how does the feedback loop work in pwn-ai',
      final: 'The feedback loop in pwn-ai works via a keep-working harness. ' * 8,
      trace: ['{"success":false,"error":"PATH=/usr/bin"}']
    )
    expect(v[:source].to_s).to eq('heuristic')
    expect(v[:score].to_f).to be < 0.9
    expect(v[:score].to_f).to be <= 0.70
  end

  it 'promote_to_success requires two of ORM, verify, critic' do
    expect(PWN::AI::Agent::Reward.promote_to_success?(orm: true, verify: false, critic: false)).to be false
    expect(PWN::AI::Agent::Reward.promote_to_success?(orm: true, verify: true, critic: false)).to be true
    expect(PWN::AI::Agent::Reward.promote_to_success?(orm: false, verify: true, critic: true)).to be true
  end

  it 'calibration_green? is overconfidence at or below 0.08 with enough samples' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'metrics.json'))
    PWN::AI::Agent::Metrics.reset
    expect(PWN::AI::Agent::Metrics.calibration_green?).to be false
    12.times { PWN::AI::Agent::Metrics.record_calibration(predicted: 0.52, actual: 0.50, brier: 0.0004, engine: :grok) }
    expect(PWN::AI::Agent::Metrics.calibration_green?).to be true
    12.times { PWN::AI::Agent::Metrics.record_calibration(predicted: 0.87, actual: 0.49, brier: 0.1444, engine: :ollama) }
    expect(PWN::AI::Agent::Metrics.calibration_green?).to be false
  end

  it 'policy is off when calibration is red' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'metrics.json'))
    PWN::AI::Agent::Metrics.reset
    12.times { PWN::AI::Agent::Metrics.record_calibration(predicted: 0.87, actual: 0.49, brier: 0.1444, engine: :grok) }
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:agent] ||= {}
    PWN::Env[:ai][:agent][:policy] = true
    expect(PWN::AI::Agent::Policy.enabled?).to be false
  end

  it 'mistakes to_context defaults to fixes only' do
    src = File.read(PWN::AI::Agent::Mistakes.method(:to_context).source_location.first)
    expect(src).to match(/fixes_only|KNOWN FIXES/)
    expect(src).to match(/include_open|full/)
  end

  it 'skills catalog is names only without skill bodies' do
    src = File.read(PWN::AI::Agent::PromptBuilder.method(:build).source_location.first)
    expect(src).to match(/skills_block/)
    expect(src).not_to match(/meta\[:content\]\.to_s\[0,\s*1200\]/)
  end

  it 'curriculum reclassify_backlog exists' do
    expect(PWN::AI::Agent::Curriculum).to respond_to(:reclassify_backlog)
  end
end
