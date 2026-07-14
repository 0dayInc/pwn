# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Curriculum do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Curriculum
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Curriculum
    expect(help_response).to respond_to :help
  end

  it 'calibrate computes brier and records to Metrics' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'm.json'))
    r = described_class.calibrate(predicted: 0.8, actual: 1.0, engine: :ollama)
    expect(r[:brier]).to eq 0.04
    cal = PWN::AI::Agent::Metrics.calibration(engine: :ollama)
    expect(cal[:n]).to eq 1
  end

  it 'practice dry_run generates reproducers without self-play' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
    stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', File.join(tmp, 'curr'))
    PWN::AI::Agent::Mistakes.record(tool: 'shell', error: 'nmpa: command not found')
    r = described_class.practice(limit: 1, dry_run: true)
    expect(r[:dry_run]).to be true
    expect(r[:practiced]).to eq 1
    expect(r[:results].first[:prompts]).not_to be_empty
  end

  it 'train_and_gate dry_run exports datasets and manual CLI' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'l.jsonl'))
    stub_const('PWN::AI::Agent::Learning::FINETUNE_DIR', tmp)
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(tmp, 'p.jsonl'))
    stub_const('PWN::AI::Agent::Reward::DPO_DIR', tmp)
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'm.json'))
    stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', File.join(tmp, 'c'))
    stub_const('PWN::AI::Agent::Curriculum::MODELS_FILE', File.join(tmp, 'c', 'models.json'))

    r = described_class.train_and_gate(dry_run: true)
    expect(r[:dry_run]).to be true
    expect(r[:manual_cli]).to be_an(Array)
    expect(r[:version]).to eq 1
  end

  it 'critic returns pass when disabled' do
    r = described_class.critic(request: 'x', final: 'y')
    expect(r[:verdict]).to eq :pass
  end
end
