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
    # P21/P25 — mistakes_resolve requires a trajectory shape
    described_class.record_preference(
      prompt: 'p2', rejected: 'failing shell args',
      chosen: "STRATEGY: x\nWINNING_TRACE:\nshell → uname -r\n#{'t' * 40}",
      source: :mistakes_resolve, shape: :winning_trace
    )
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

  it 'treats handler timeout after Ns as not semantic_ok even when success is true' do
    raw = '{"success":true,"result":{"stdout":"","error":"timeout after 20s","exit":null}}'
    r = described_class.semantic_ok(name: 'pwn_eval', raw: raw)
    expect(r[:semantic_ok]).to be false
    expect(r[:shape]).to eq(:timeout)
    r2 = described_class.semantic_ok(
      name: 'shell',
      raw: '{"success":true,"result":{"stdout":"","stderr":"","exit":null,"error":"timeout after 30s"}}'
    )
    expect(r2[:semantic_ok]).to be false
    expect(r2[:shape]).to eq(:timeout)
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
    legacy = {
      samples: 101,
      judge_sum: 71.9,
      proxy_sum: 82.0,
      proxy_n: 22,
      proxy_distrust: 1.0,
      distrust_at: Time.now.utc.iso8601,
      distrust_meta: { proxy: 3.72, judge: 0.71, gap: 3.01 }
    }
    File.write(path, JSON.generate(legacy))
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
  it 'write_source_quota and weak pair geometry (P9)' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(tmp, 'prefs.jsonl'))
    r = described_class.record_preference(prompt: 'p', rejected: 'a', chosen: 'CORRECTION: no', source: :critic)
    expect(r[:skipped]).to eq :weak_pair_geometry
    11.times do |i|
      described_class.record_preference(prompt: "p#{i}", rejected: "r#{i}", chosen: "c#{i}", source: :mistakes_resolve, force: true)
    end
    q = described_class.write_source_quota(source: 'mistakes_resolve')
    expect(q[:over_cap]).to be true
  end

  it 'warm_sentinel fills from learning outcomes (P10)' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(tmp, 's.json'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'l.jsonl'))
    50.times do |i|
      PWN::AI::Agent::Learning.note_outcome(task: "t#{i}", success: true, score: 0.8, details: 'd')
    end
    r = described_class.warm_sentinel(limit: 60)
    expect(r[:added]).to be > 0
  end

  it 'scrub_preferences and usable_preference? (P15)' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(tmp, 'prefs.jsonl'))
    described_class.record_preference(
      prompt: 'p', rejected: 'long rejected text ' * 20,
      chosen: 'CORRECTION: no', source: :critic, force: true
    )
    described_class.record_preference(
      prompt: 'q', rejected: 'bad',
      chosen: "WINNING_TRACE:\n#{'shell ok ' * 30}",
      source: :curriculum, shape: :winning_trace, force: true
    )
    dry = described_class.scrub_preferences(dry_run: true)
    expect(dry[:dropped]).to be >= 1
    wet = described_class.scrub_preferences(dry_run: false)
    expect(wet[:after]).to be < wet[:before]
    bal = described_class.preference_balance(scrub: true)
    expect(bal).to have_key(:trajectory_fraction)
  end

  it 'export_dpo reports geometry_dropped (P15)' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(tmp, 'prefs.jsonl'))
    stub_const('PWN::AI::Agent::Reward::DPO_DIR', tmp)
    described_class.record_preference(
      prompt: 'p', rejected: 'r' * 500, chosen: 'CORRECTION: x', source: :mistakes_resolve, force: true
    )
    described_class.record_preference(
      prompt: 'q', rejected: 'r', chosen: "WINNING_TRACE:\n#{'t' * 100}",
      source: :counterfactual, shape: :real_dispatch, force: true
    )
    info = described_class.export_dpo(out: File.join(tmp, 'd.jsonl'))
    expect(info[:geometry_dropped]).to be >= 1
    expect(info[:scrubbed]).to be true
  end

  it 'plan_coverage scores soft task coverage for W3 / Learning tags' do
    plan = [
      'locate the TaskSummarizer source',
      'fix the truncation bug',
      'run rspec to verify'
    ]
    good = described_class.plan_coverage(
      plan: plan,
      final: 'Located TaskSummarizer, fixed the truncation bug, rspec is green.',
      request: 'fix truncation',
      trace: ['shell → rg TaskSummarizer', 'shell → bundle exec rspec']
    )
    expect(good[:total]).to eq 3
    expect(good[:score]).to be >= 0.4
    expect(good[:tag]).to match(/plan_cover_/)

    bad = described_class.plan_coverage(
      plan: plan,
      final: 'hello world',
      request: 'x',
      trace: []
    )
    expect(bad[:score]).to be < good[:score]
    expect(bad[:missing]).not_to be_empty
  end
  it 'judge_sample_weight ranks llm_orm above heuristic overlap' do
    expect(described_class.judge_sample_weight(source: :llm_orm)).to eq 1.0
    expect(described_class.judge_sample_weight(source: :heuristic)).to be < 0.5
    expect(described_class.judge_sample_weight(source: :error)).to be < described_class.judge_sample_weight(source: :heuristic)
  end

  it 'llm_judge prefers cheap engine chat over heuristic overlap' do
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(Dir.mktmpdir, 's.json'))
    allow(described_class).to receive(:reflect_available?).and_return(true)
    allow(described_class).to receive(:reflect_on_ready?).and_return(false)
    allow(described_class).to receive(:engine_chat_cheap).and_return(
      '{"score":0.82,"verdict":"solved","rationale":"final matches request","key_step":1}'
    )
    v = described_class.judge(
      request: 'print kernel release',
      final: 'completely unrelated marketing blurb',
      trace: ['{"success":true,"result":{"exit":0}}'],
      commit: false
    )
    expect(v[:source].to_s).to eq 'llm_orm'
    expect(v[:score]).to be_within(0.01).of(0.82)
    expect(v[:confidence]).to be >= 0.8
    expect(v[:rationale].to_s).not_to match(/heuristic overlap/)
  end

  it 'sentinel window_means weights llm_orm above heuristic overlap' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(tmp, 's.json'))
    20.times { described_class.send(:record_sentinel, proxy: true, judge: 0.9, source: :heuristic) }
    20.times { described_class.send(:record_sentinel, proxy: true, judge: 0.2, source: :llm_orm) }
    means = described_class.send(:window_means, window: described_class.send(:load_sentinel)[:window])
    # equal counts: unweighted mean would be 0.55; ORM-weighted mean is closer to 0.2
    expect(means[:judge]).to be < 0.45
    expect(means[:judge]).to be > 0.2
  end
  it 'parse_llm_judge reads fenced JSON and Grok chat hashes' do
    fenced = described_class.send(
      :parse_llm_judge,
      resp: "```json\n{\"score\":0.71,\"verdict\":\"partial\",\"rationale\":\"usable but open plan\",\"key_step\":2}\n```"
    )
    expect(fenced[:source].to_s).to eq 'llm_orm'
    expect(fenced[:score]).to be_within(0.01).of(0.71)

    hashed = described_class.send(
      :parse_llm_judge,
      resp: { choices: [{ role: 'system', content: 'sys' }, { role: 'assistant', content: '{"score":0.66,"verdict":"partial","rationale":"ok","key_step":1}' }] }
    )
    expect(hashed[:score]).to be_within(0.01).of(0.66)
  end

  it 'evidence_prior beats token-overlap on truncated finals' do
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(Dir.mktmpdir, 's.json'))
    allow(described_class).to receive(:reflect_available?).and_return(false)
    v = described_class.judge(
      request: 'Briefly describe the strengths and weaknesses of the pwn-ai RL loop',
      final: 'The loop is a live tabular overlay, not deep RL. Strengths. It treats each turn as one MDP step. Weaknesses. The tables are cold and',
      trace: ['{"success":true,"result":{"exit":0}}'],
      commit: false
    )
    expect(v[:source].to_s).to eq 'heuristic'
    expect(v[:rationale].to_s).to match(/heuristic/)
    expect(v[:score]).to be < 0.6
  end

  it 'recalibrated distrust never full-haircuts a normal gap' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(tmp, 's.json'))
    File.write(File.join(tmp, 's.json'), JSON.generate(window: [], proxy_distrust: 0.0))
    factor = described_class.set_proxy_distrust(gap: 0.30, proxy: 1.0, judge: 0.70)
    expect(factor).to be <= 0.85
    expect(factor).to be >= 0.2
    expect(described_class.proxy_distrust).to be <= 0.85
    described_class.set_proxy_distrust(gap: 0.60, proxy: 1.0, judge: 0.30)
    expect(described_class.proxy_distrust).to eq 0.85
  end

  it 'cheap_orm_chat does not retry engine_chat_cheap after a timeout' do
    src = File.read(File.join(__dir__, '../../../../../lib/pwn/ai/agent/reward.rb'))
    expect(src).to include('return nil if timeout_error?(err: e)')
    expect(src).to include('quiet: true')
  end
end

describe 'PWN::AI::Agent::Reward vs TUI plan' do
  it 'does not let a TUI plan_cover_low haircut a high-evidence original-request answer' do
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(Dir.mktmpdir, 's.json'))
    allow(PWN::AI::Agent::Reward).to receive(:reflect_available?).and_return(false)
    plan = [
      'Load and review rules of engagement, submission criteria, and the full in-scope subdomain list',
      'Inventory applicable unauthenticated testing skills and techniques',
      'Enumerate and resolve all in-scope subdomains and map reachable services',
      'Fingerprint stacks, configurations, and exposure on every subdomain',
      'Run exhaustive unauthenticated analysis across the full attack surface',
      'Prioritize and deep-dive each promising lead to confirm exploitability',
      'Develop evidence-backed proof-of-concept demonstrations',
      'Combine related weaknesses into higher-impact attack chains',
      'Assign evidence-backed severity and filter to submission-eligible issues',
      'Use graphical applications where they improve validation',
      'Compile submission-ready writeups with reproduction steps',
      'Re-verify each finding still reproduces and present the final set'
    ]
    final = <<~TXT
      Path-backed answer for the original request. Hosts scanned: 10.9.8.7 and 10.9.8.8.
      Verified complete. Evidence in /tmp/pwn-eval-hosts.json. 12 hosts live. rspec passed.
    TXT
    klass = PWN::AI::Agent::Reward
    v = klass.judge(
      request: 'what live hosts can you find on this box and write /tmp/pwn-eval-hosts.json',
      final: final,
      plan: plan,
      trace: [
        '{"success":true,"result":{"stdout":"10.9.8.7 up","exit":0},"effect":"eval"}',
        '{"success":true,"result":{"stdout":"wrote /tmp/pwn-eval-hosts.json","exit":0},"effect":"write"}'
      ],
      commit: false
    )
    expect(v[:source].to_s).to eq 'heuristic'
    expect(v[:score]).to be >= 0.6
    expect(v[:verdict].to_s).to eq 'solved'
    args = {
      request: 'what live hosts can you find on this box and write /tmp/pwn-eval-hosts.json',
      final: final,
      trace: [
        '{"success":true,"result":{"stdout":"10.9.8.7 up","exit":0},"effect":"eval"}',
        '{"success":true,"result":{"stdout":"wrote /tmp/pwn-eval-hosts.json","exit":0},"effect":"write"}'
      ]
    }
    base = klass.send(:evidence_prior, **args)
    mixed = klass.send(:evidence_prior, **args, plan: plan)
    expect(mixed[:score]).to eq(base[:score])
  end

  it 'always grades the original request even when a stub compass or TUI plan is supplied' do
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(Dir.mktmpdir, 's.json'))
    allow(PWN::AI::Agent::Reward).to receive(:reflect_available?).and_return(false)
    klass = PWN::AI::Agent::Reward
    src = File.read(klass.method(:judge).source_location.first)
    expect(src).not_to include('llm_judge(request: request, final: final, trace: trace, plan: opts[:plan])')
    expect(src).not_to include('heuristic_judge(request: request, final: final, trace: trace, plan: opts[:plan])')
    request = 'using hping3 what live hosts can you find in this subnet and write /tmp/x.json'
    final = 'Live hosts: 10.1.2.3. Verified. Wrote /tmp/x.json. 4 hosts up. rspec passed.'
    trace = [
      '{"success":true,"result":{"stdout":"10.1.2.3 up","exit":0},"effect":"eval"}',
      '{"success":true,"result":{"stdout":"wrote /tmp/x.json","exit":0},"effect":"write"}'
    ]
    a = klass.judge(request: request, final: final, trace: trace, commit: false)
    b = klass.judge(request: request, final: final, trace: trace, plan: ['Carry out the core work'], commit: false)
    c = klass.judge(request: request, final: final, trace: trace, plan: ['Enumerate subdomains', 'Compile writeups'], commit: false)
    expect(a[:score]).to eq(b[:score])
    expect(b[:score]).to eq(c[:score])
    expect(a[:score]).to be >= 0.6
    expect(a[:verdict].to_s).to eq('solved')
  end

  it 'does not drag a long analytical PASS to partial on zero token overlap' do
    klass = PWN::AI::Agent::Reward
    allow(klass).to receive(:llm_judge).and_return(nil)
    req = 'Analyze the harness in which you currently reside and provide a summary of strengths / weaknesses.'
    final = ('The control loop architecture is strong. Q-learning, calibration, anti-stall gates. ' * 20)
    v = klass.judge(request: req, final: final, trace: ['{"success":true,"result":{"exit":0}}'], commit: false)
    expect(v[:score]).to be > 0.35
  end

  it 'floors verified PASS analytical answers at 0.6' do
    src = File.read(PWN::AI::Agent::Reward.method(:judge).source_location.first)
    expect(src).to include('[score, 0.6].max')
    expect(src).to include('\bPASS\b')
  end

  it 'prefers model_routes.judge when selecting a judge model' do
    allow(PWN::Env).to receive(:is_a?).and_return(true)
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :model_routes, :judge).and_return('local-judge')
    m = PWN::AI::Agent::Reward.send(:judge_model)
    expect(m).to eq('local-judge')
  end
end
