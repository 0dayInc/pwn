# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

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
    expect(PWN::AI::Agent::Mistakes.to_context).not_to include('nmpa')
    PWN::AI::Agent::Mistakes.resolve(signature: a[:signature], fix: 'use `nmap`, not `nmpa`')
    expect(PWN::AI::Agent::Mistakes.to_context).to include('shell')
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

  it 'enforces SAMPLE_ARGS_MAX SNIPPET_MAX ERROR_MAX SESSIONS_KEEP on record' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 'mistakes.json')
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', path)
    FileUtils.rm_f(path)
    long_err = 'E' * (PWN::AI::Agent::Mistakes::ERROR_MAX + 200)
    long_args = 'A' * (PWN::AI::Agent::Mistakes::SAMPLE_ARGS_MAX + 80)
    m = nil
    5.times do |i|
      m = PWN::AI::Agent::Mistakes.record(
        tool: 'shell',
        error: long_err,
        args: long_args,
        session_id: "sess_#{i}"
      )
    end
    expect(m[:snippet].to_s.bytesize).to be <= PWN::AI::Agent::Mistakes::SNIPPET_MAX
    expect(m[:error].to_s.bytesize).to be <= PWN::AI::Agent::Mistakes::ERROR_MAX
    expect(m[:sample_args].to_s.bytesize).to be <= PWN::AI::Agent::Mistakes::SAMPLE_ARGS_MAX
    expect(Array(m[:sessions]).length).to be <= PWN::AI::Agent::Mistakes::SESSIONS_KEEP
    expect(m[:count]).to eq(5)
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'lean! keeps unresolved and REPEATING scars; caps resolved via MAX_RESOLVED_KEPT' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 'mistakes.json')
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', path)
    stub_const('PWN::AI::Agent::Mistakes::MAX_RESOLVED_KEPT', 2)
    stub_const('PWN::AI::Agent::Mistakes::RESOLVED_MIN_AGE_DAYS', 0)
    FileUtils.rm_f(path)

    open_m = PWN::AI::Agent::Mistakes.record(tool: 'open_tool', error: 'still broken open')
    rep = nil
    3.times { rep = PWN::AI::Agent::Mistakes.record(tool: 'rep_tool', error: 'repeat me') }
    expect(rep[:count]).to be >= PWN::AI::Agent::Mistakes::REPEAT_THRESHOLD

    resolved_sigs = []
    4.times do |i|
      m = PWN::AI::Agent::Mistakes.record(tool: "done_#{i}", error: "once #{i}")
      PWN::AI::Agent::Mistakes.resolve(signature: m[:signature], fix: "fix #{i}")
      # age resolved_at into the past for drop eligibility
      store = PWN::AI::Agent::Mistakes.load
      store[m[:signature].to_sym][:resolved_at] = (Time.now.utc - (40 * 86_400)).iso8601
      store[m[:signature].to_sym][:count] = 1
      PWN::AI::Agent::Mistakes.save(store: store)
      resolved_sigs << m[:signature]
    end

    res = PWN::AI::Agent::Mistakes.lean!
    store = PWN::AI::Agent::Mistakes.load
    expect(store.keys.map(&:to_s)).to include(open_m[:signature], rep[:signature])
    resolved_left = store.values.count { |e| e[:resolved] && e[:fix].to_s != '' }
    expect(resolved_left).to be <= 2
    expect(res[:remaining]).to be <= store.size
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'resolve clamps fix to FIX_MAX' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 'mistakes.json')
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', path)
    FileUtils.rm_f(path)
    m = PWN::AI::Agent::Mistakes.record(tool: 't', error: 'e')
    long_fix = 'F' * (PWN::AI::Agent::Mistakes::FIX_MAX + 50)
    got = PWN::AI::Agent::Mistakes.resolve(signature: m[:signature], fix: long_fix)
    expect(got[:fix].bytesize).to eq(PWN::AI::Agent::Mistakes::FIX_MAX)
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end
  it 'extinguish! resolves recoverable repeating shell shapes' do
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(Dir.mktmpdir, 'mistakes.json'))
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(Dir.mktmpdir, 'prefs.jsonl')) if defined?(PWN::AI::Agent::Reward)
    stub_const('PWN::Memory::MEMORY_FILE', File.join(Dir.mktmpdir, 'memory.json')) if defined?(PWN::Memory)
    described_class.reset if described_class.respond_to?(:reset)
    m = nil
    3.times { m = described_class.record(tool: 'shell', error: 'argumenterror: command is required', shape: 'handler_error') }
    out = described_class.extinguish!(signature: m[:signature], shape: 'handler_error', force: true)
    expect(out[:resolved]).to be true
    expect(out[:fix].to_s).to match(/command is required|uname -r/)
    expect(described_class.top(unresolved_only: true).map { |r| r[:signature] }).not_to include(m[:signature])
  end

  it 'extinguish! does not close budget-exhaustion handler_error scars' do
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(Dir.mktmpdir, 'mistakes.json'))
    described_class.reset if described_class.respond_to?(:reset)
    m = described_class.record(tool: 'assistant_answer', error: 'critic: [pwn-ai] iteration budget exhausted', shape: 'handler_error')
    out = described_class.extinguish!(signature: m[:signature], shape: 'handler_error', force: true)
    expect(out[:resolved]).not_to eq(true)
    expect(described_class.find(signature: m[:signature])[:resolved]).not_to eq(true)
  end

  it 'extinguish_parked! closes recoverable inbox scars' do
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(Dir.mktmpdir, 'mistakes.json'))
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(Dir.mktmpdir, 'prefs.jsonl')) if defined?(PWN::AI::Agent::Reward)
    stub_const('PWN::Memory::MEMORY_FILE', File.join(Dir.mktmpdir, 'memory.json')) if defined?(PWN::Memory)
    described_class.reset if described_class.respond_to?(:reset)
    m = described_class.record(tool: 'shell', error: 'argumenterror: command is required', shape: 'handler_error')
    described_class.park(signature: m[:signature], reason: 'needs_human leftover')
    out = described_class.extinguish_parked!(limit: 10)
    expect(out[:extinguished]).to be >= 1
    expect(described_class.find(signature: m[:signature])[:resolved]).to be true
  end

  it 'to_context downranks budget-exhaustion scars on unrelated requests' do
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(Dir.mktmpdir, 'mistakes.json'))
    described_class.reset if described_class.respond_to?(:reset)
    described_class.record(
      tool: 'agent_loop',
      error: '[pwn-ai] iteration budget exhausted',
      shape: 'budget_exhausted'
    )
    described_class.record(tool: 'shell', error: 'nmpa: command not found unique-host')
    ctx = described_class.to_context(request: 'what is my hostname?', limit: 2)
    expect(ctx).not_to match(/iteration budget exhausted/)
    ctx_full = described_class.to_context(request: 'what is my hostname?', include_open: true, limit: 2)
    expect(ctx_full).to include('shell')
    expect(ctx_full).not_to match(/iteration budget exhausted/)
  end

  it 'does not classify or extinguish scars as unauthorized recon' do
    src = File.read(described_class.method(:extinguish!).source_location.first)
    expect(src).not_to match(/unauthorized_recon/)
    expect(src).not_to match(/recon_blocked/)
    expect(src).not_to match(/auth_gate/)
  end
end
