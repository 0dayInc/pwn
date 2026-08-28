# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Metrics do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Metrics
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Metrics
    expect(help_response).to respond_to :help
  end

  it 'records tool telemetry and summarises effectiveness' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'metrics.json'))
    PWN::AI::Agent::Metrics.reset
    PWN::AI::Agent::Metrics.record(name: 'shell', success: true,  duration: 0.10)
    PWN::AI::Agent::Metrics.record(name: 'shell', success: false, duration: 0.20, error: 'boom')
    rows = PWN::AI::Agent::Metrics.summary
    row  = rows.find { |r| r[:name] == 'shell' }
    expect(row[:calls]).to eq 2
    expect(row[:success_rate]).to eq 0.5
    expect(PWN::AI::Agent::Metrics.to_context).to include('shell')
  end
  it 'judge_rate weights llm_orm above heuristic overlap' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'metrics.json'))
    PWN::AI::Agent::Metrics.reset
    8.times { PWN::AI::Agent::Metrics.record_judge(name: 'shell', score: 0.9, confidence: 0.35, source: :heuristic) }
    8.times { PWN::AI::Agent::Metrics.record_judge(name: 'shell', score: 0.2, confidence: 0.85, source: :llm_orm) }
    rate = PWN::AI::Agent::Metrics.judge_rate(name: 'shell')
    # unweighted mean would be 0.55; ORM-weighted mean is closer to 0.2
    expect(rate).to be < 0.45
    expect(rate).to be > 0.2
  end

  it 'temperature-scales overconfident predictions toward realised actual' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'metrics.json'))
    described_class.reset
    12.times { described_class.record_calibration(predicted: 0.87, actual: 0.49, brier: 0.1444, engine: :grok) }
    scaled = described_class.scale_prediction(predicted: 0.87, engine: :grok)
    expect(scaled).to be < 0.87
    expect(scaled).to be > 0.35
    board = described_class.scoreboard
    expect(board).to include(:tool_ok, :task_ok, :judge_ok)
    line = described_class.health_line
    expect(line).to match(/tool_ok=/)
    expect(line).to match(/task_ok=/)
    expect(line).to match(/judge_ok=/)
  end
end
