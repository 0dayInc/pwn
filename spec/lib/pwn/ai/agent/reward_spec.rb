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

  it 'does NOT treat empty-stderr exit 1 as benign without BENIGN_EXIT match (2.1)' do
    bare = '{"success":true,"result":{"stdout":"","stderr":"","exit":1}}'
    r = described_class.semantic_ok(name: 'shell', raw: bare, args: '{"command":"false"}')
    expect(r[:semantic_ok]).to be false
    expect(r[:benign]).to be false
  end

  it 'recoverable_shape classifies common failure classes (2.2)' do
    expect(described_class.recoverable_shape(exit_code: 127, err: 'nmap: command not found')).to eq :exit127
    expect(described_class.recoverable_shape(err: 'No such file or directory')).to eq :enoent
    expect(described_class.recoverable_shape(err: 'Permission denied')).to eq :eacces
  end

  it 'heuristic_judge penalises empty and polite finals (1.4)' do
    v = described_class.judge(request: 'list files in /tmp', final: '', trace: [], commit: false)
    expect(v[:score]).to eq 0.0
    v2 = described_class.judge(request: 'list files in /tmp', final: 'Sure! Happy to help.', trace: [], commit: false)
    expect(v2[:score]).to be < 0.3
  end

  it 'sentinel ring-buffer keeps proxy mean in [0,1] and distrust only on real gap' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(tmp, 's.json'))

    # 40 samples: proxy always 1.0, judge always 0.7 → gap 0.3 > 0.15
    40.times do
      described_class.send(:record_sentinel, proxy: true, judge: 0.7)
    end
    r = described_class.sentinel
    expect(r[:status]).to be_nil
    expect(r[:proxy]).to be_between(0.0, 1.0)
    expect(r[:proxy]).to eq 1.0
    expect(r[:judge]).to be_within(0.01).of(0.7)
    expect(r[:gap_proxy_judge]).to be_within(0.02).of(0.3)
    expect(r[:reward_hacked]).to be true
    d = r[:proxy_distrust].to_f
    expect(d).to be >= 0.3
    expect(d).to be <= 1.0

    # window caps at SENTINEL_WINDOW — more samples do not inflate mean above 1
    20.times { described_class.send(:record_sentinel, proxy: true, judge: 0.7) }
    s = JSON.parse(File.read(File.join(tmp, 's.json')), symbolize_names: true)
    expect(s[:window].length).to eq PWN::AI::Agent::Reward::SENTINEL_WINDOW
    expect(s[:proxy_sum].to_f / s[:proxy_n]).to be_between(0.0, 1.0)
  end

  it 'set_proxy_distrust refuses proxy means outside [0,1] (legacy decay bug guard)' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(tmp, 's.json'))
    File.write(File.join(tmp, 's.json'), JSON.generate(window: [], proxy_distrust: 0.0))

    factor = described_class.set_proxy_distrust(gap: 3.0, proxy: 3.72, judge: 0.71)
    expect(factor).to eq 0.0
    expect(described_class.proxy_distrust).to eq 0.0
  end

  it 'normalize_sentinel clears stuck distrust from corrupt legacy sum file' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 's.json')
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', path)
    # Reproduce live bug shape: proxy_sum/proxy_n >> 1 after decay×to_i
    File.write(path, JSON.generate(
      samples: 101,
      judge_sum: 71.9,
      proxy_sum: 82.0,
      proxy_n: 22,
      proxy_distrust: 1.0,
      distrust_at: Time.now.utc.iso8601,
      distrust_meta: { proxy: 3.72, judge: 0.71, gap: 3.01 }
    ))
    s = described_class.send(:load_sentinel)
    expect(s[:window]).to eq []
    expect(s[:proxy_distrust].to_f).to eq 0.0
    expect(described_class.proxy_distrust).to eq 0.0
    expect(described_class.sentinel[:status]).to eq :insufficient
  end

  it 'reset_sentinel wipes the file without touching preferences' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(tmp, 's.json'))
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(tmp, 'prefs.jsonl'))
    File.write(File.join(tmp, 's.json'), '{"window":[]}')
    File.write(File.join(tmp, 'prefs.jsonl'), "{}\n")
    described_class.reset_sentinel
    expect(File.exist?(File.join(tmp, 's.json'))).to be false
    expect(File.exist?(File.join(tmp, 'prefs.jsonl'))).to be true
  end
end
