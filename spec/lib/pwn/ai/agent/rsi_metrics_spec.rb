# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe 'RSI exploit and attack rates' do
  let(:dir) { Dir.mktmpdir('pwn-rsi-') }

  before do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(dir, 'metrics.json'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(dir, 'learning.jsonl'))
    PWN::AI::Agent::Metrics.reset
  end

  after { FileUtils.remove_entry(dir) if dir && Dir.exist?(dir) }

  it 'computes ESR as verified exploit tools over vulnerable tools and ASR as successful attacks over attempts' do
    PWN::AI::Agent::Metrics.record_attempt(kind: 'exploit', tool: 'ret2libc', vulnerable_tool: 'libc', vulnerable: true, success: false)
    PWN::AI::Agent::Metrics.record_attempt(kind: 'exploit', tool: 'rop', vulnerable_tool: 'nginx', vulnerable: true, success: true)
    PWN::AI::Agent::Metrics.record_attempt(kind: 'exploit', tool: 'rop', vulnerable_tool: 'nginx', vulnerable: true, success: true)
    PWN::AI::Agent::Metrics.record_attempt(kind: 'attack', success: true, technique: 'chain', finding_id: 'c1')
    PWN::AI::Agent::Metrics.record_attempt(kind: 'attack', success: false, technique: 'chain', finding_id: 'c2')
    esr = PWN::AI::Agent::Metrics.esr
    asr = PWN::AI::Agent::Metrics.asr
    expect(esr[:verified_exploit_tools]).to eq(1)
    expect(esr[:vulnerable_tools]).to eq(2)
    expect(esr[:rate]).to eq(0.5)
    expect(asr[:successful_attacks]).to eq(1)
    expect(asr[:total_attack_attempts]).to eq(2)
    expect(asr[:rate]).to eq(0.5)
    expect(PWN::AI::Agent::Metrics.scoreboard[:esr]).to eq(0.5)
    expect(PWN::AI::Agent::Metrics.scoreboard[:asr]).to eq(0.5)
    expect(PWN::AI::Agent::Metrics.to_context).to include('ESR=0.5')
  end

  it 'writes an RSI lesson when the measured exploit rate falls' do
    expect(PWN::AI::Agent::PolicyEvaluation).not_to receive(:evaluate)
    expect(PWN::AI::Agent::PolicyEvaluation).not_to receive(:promote)
    expect(PWN::AI::Agent::PolicyEvaluation).not_to receive(:rollback)
    expect(PWN::AI::Agent::Loop).not_to receive(:run)
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    PWN::AI::Agent::Metrics.record_attempt(kind: 'exploit', tool: 'ret2libc', vulnerable_tool: 'libc', vulnerable: true, success: true)
    PWN::AI::Agent::Learning.rsi_tick(request: 'measure exploit rate')
    PWN::AI::Agent::Metrics.record_attempt(kind: 'exploit', tool: 'rop', vulnerable_tool: 'nginx', vulnerable: true, success: false)
    tick = PWN::AI::Agent::Learning.rsi_tick(request: 'measure exploit rate')
    expect(tick[:regressed]).to eq(true)
    expect(PWN::AI::Agent::Learning.outcomes.map { |row| row[:tags] }.flatten).to include('rsi')
  end
end
