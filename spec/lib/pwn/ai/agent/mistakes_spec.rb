# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Mistakes do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Mistakes
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Mistakes
    expect(help_response).to respond_to :help
  end

  it 'fingerprints, counts and resolves recurring failures' do
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(Dir.mktmpdir, 'mistakes.json'))
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(Dir.mktmpdir, 'prefs.jsonl')) if defined?(PWN::AI::Agent::Reward)
    stub_const('PWN::Memory::MEMORY_FILE', File.join(Dir.mktmpdir, 'memory.json')) if defined?(PWN::Memory)
    PWN::AI::Agent::Mistakes.reset
    a = PWN::AI::Agent::Mistakes.record(tool: 'shell', error: 'nmpa: command not found at /tmp/x:42')
    b = PWN::AI::Agent::Mistakes.record(tool: 'shell', error: 'nmpa: command not found at /var/y:99')
    expect(a[:signature]).to eq b[:signature]
    top = PWN::AI::Agent::Mistakes.top
    expect(top.first[:count]).to eq 2
    expect(PWN::AI::Agent::Mistakes.to_context).to include('shell')
    PWN::AI::Agent::Mistakes.resolve(signature: a[:signature], fix: 'use `nmap`, not `nmpa`')
    expect(PWN::AI::Agent::Mistakes.top(unresolved_only: true)).to be_empty
    # recurrence re-opens
    PWN::AI::Agent::Mistakes.record(tool: 'shell', error: 'nmpa: command not found')
    expect(PWN::AI::Agent::Mistakes.top(unresolved_only: true).length).to eq 1
  end

  it 'detects user-correction language' do
    expect(PWN::AI::Agent::Mistakes.correction?(request: "no that's wrong, try again")).to be true
    expect(PWN::AI::Agent::Mistakes.correction?(request: 'please scan 10.0.0.0/24')).to be false
  end

  it 'supports park and practiceable_only filter (2.5)' do
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(Dir.mktmpdir, 'mistakes.json'))
    described_class.reset if described_class.respond_to?(:reset)
    m = described_class.record(tool: 'shell', error: 'needs engineer fix XYZ unique')
    described_class.park(signature: m[:signature], reason: 'needs_code_change')
    open_all = described_class.top(limit: 10, unresolved_only: true)
    open_prac = described_class.top(limit: 10, unresolved_only: true, practiceable_only: true)
    expect(open_all.map { |r| r[:signature] }).to include(m[:signature])
    expect(open_prac.map { |r| r[:signature] }).not_to include(m[:signature])
  end

  it 'stores structured_fix on resolve (2.3)' do
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(Dir.mktmpdir, 'mistakes.json'))
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(Dir.mktmpdir, 'prefs.jsonl')) if defined?(PWN::AI::Agent::Reward)
    stub_const('PWN::Memory::MEMORY_FILE', File.join(Dir.mktmpdir, 'memory.json')) if defined?(PWN::Memory)
    described_class.reset if described_class.respond_to?(:reset)
    m = described_class.record(tool: 'shell', error: 'typo binary nmpa unique')
    described_class.resolve(
      signature: m[:signature],
      fix: 'use nmap',
      structured: { strategy: 'typo', tool: 'shell', args_template: { command: 'nmap' }, holdout_tests: %w[a b] }
    )
    got = described_class.find(signature: m[:signature])
    expect(got[:structured_fix][:strategy]).to eq 'typo'
    expect(got[:structured_fix][:holdout_tests].length).to eq 2
  end
end
