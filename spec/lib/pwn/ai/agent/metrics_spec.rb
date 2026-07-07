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
end
