# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Reward do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Reward
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Reward
    expect(help_response).to respond_to :help
  end

  it 'semantic_ok classifies benign non-zero exits' do
    grep = '{"success":true,"result":{"stdout":"","stderr":"","exit":1}}'
    r = described_class.semantic_ok(name: 'shell', raw: grep, args: '{"command":"grep foo bar.txt"}')
    expect(r[:semantic_ok]).to be true
    expect(r[:benign]).to be true

    real = '{"success":true,"result":{"stdout":"","stderr":"nmap: command not found","exit":127}}'
    r2 = described_class.semantic_ok(name: 'shell', raw: real, args: '{"command":"nmap -sV"}')
    expect(r2[:semantic_ok]).to be false

    disp = '{"success":false,"error":"RuntimeError: boom"}'
    r3 = described_class.semantic_ok(name: 'pwn_eval', raw: disp)
    expect(r3[:semantic_ok]).to be false
  end

  it 'records and exports preference pairs' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(tmp, 'prefs.jsonl'))
    stub_const('PWN::AI::Agent::Reward::DPO_DIR', tmp)

    described_class.record_preference(prompt: 'p', rejected: 'bad', chosen: 'good', source: :user_correction)
    described_class.record_preference(prompt: 'p2', rejected: 'x', chosen: 'y', source: :mistakes_resolve)
    expect(described_class.preferences.length).to eq 2
    expect(described_class.preferences(source: 'user_correction').length).to eq 1

    info = described_class.export_dpo(out: File.join(tmp, 'dpo.jsonl'))
    expect(info[:pairs]).to eq 2
    expect(File.read(info[:path])).to include('"chosen":"good"')
  end

  it 'judge falls back to heuristic when reflection is off' do
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(Dir.mktmpdir, 's.json'))
    v = described_class.judge(request: 'do X', final: 'done X', trace: ['{"success":true,"result":{"exit":0}}'], commit: false)
    expect(v[:score]).to be_between(0.0, 1.0)
    expect(v).to have_key(:verdict)
  end

  it 'sentinel reports insufficient below window' do
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(Dir.mktmpdir, 's.json'))
    expect(described_class.sentinel[:status]).to eq :insufficient
  end
end
