# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Reward do
  describe 'completion accounting' do
    include_context 'pwn tmp sandbox'

    it 'preserves a refuted completion claim through resolution and durable learning' do
      request = 'Write answer.txt'
      report = PWN::AI::Agent::Verification.run(request: request, requirements: [request], root: @tmp,
                                                checks: [{ requirement: request, kind: :file, path: 'answer.txt', expected: 'correct' }])
      result = described_class.resolve_outcome(outcome: { score: 0.95, source: :llm_orm, claimed_completion: true, verification: report })
      expect(result).to include(verified_completion: false, false_completion: true)
      expect(described_class.resolve_outcome(outcome: result)).to eq(result)
      row = PWN::AI::Agent::Learning.note_outcome(task: request, outcome: result)
      expect(row).to include(claimed_completion: true, verified_completion: false, false_completion: true)
      expect(PWN::AI::Agent::Learning.stats).to include(completion_claims: 1, false_completions: 1, verified_completions: 0)
    end

    it 'keeps unverified claims unknown rather than labeling them false or verified' do
      result = described_class.resolve_outcome(outcome: { score: 0.95, source: :llm_orm, claimed_completion: true })
      expect(result).to include(verified_completion: nil, false_completion: nil)
    end
  end

  describe 'labeled transcript calibration' do
    include_context 'pwn tmp sandbox'

    it 'does not promote a lone successful check without full-request coverage' do
      result = described_class.resolve_outcome(outcome: {
                                                 score: 0.36, source: :heuristic, rationale: 'missing service validation',
                                                 verification: { checks: [{ criterion: 'file exists', passed: true, evidence: '/tmp/answer.json' }] }
                                               })
      expect(result[:success]).not_to be true
      expect(result[:score]).to eq(0.36)
      expect(result[:training_score]).to be_nil
    end

    it 'does not floor heuristic scores from a prose PASS label' do
      allow(described_class).to receive(:llm_judge).and_return(nil)
      allow(described_class).to receive(:verify_as_reward).and_return(nil)
      allow(described_class).to receive(:evidence_prior).and_return(score: 0.2, confidence: 0.6)
      result = described_class.judge(request: 'Write report and validate every section', final: 'PASS',
                                     trace: ['{"success":true,"result":{"exit":0}}'], commit: false)
      expect(result[:score]).to be < 0.6
      expect(result[:training_score]).to be_nil
    end

    it 'preserves quality and rationale while an executed full request PASS determines success' do
      request = 'Write the answer and validate its JSON'
      sid = PWN::Sessions.create(title: request)[:id]
      PWN::Sessions.append(session_id: sid, role: 'user', content: request)
      File.write(File.join(@tmp, 'answer.json'), '{"answer":42}')
      contract = {
        root: @tmp, requirements: ['Write the answer', 'validate its JSON'],
        checks: [
          { requirement: 'Write the answer', kind: :file, path: 'answer.json', expected: '{"answer":42}' },
          { requirement: 'validate its JSON', kind: :json, path: 'answer.json', expected: { answer: 42 } }
        ]
      }
      allow(described_class).to receive(:llm_judge).and_return(score: 0.36, source: :heuristic, rationale: 'terse answer; weak lexical overlap')
      allow(described_class).to receive(:verify_as_reward).and_return(nil)
      PWN::Env[:ai][:reward] = { verifier_precedence: false }
      result = described_class.judge(request: request, session_id: sid, final: 'Written.', trace: ['{"success":true}'],
                                     verification_contract: contract, persist_components: true, critic_pass: false)
      expect(result).to include(success: true, quality_score: 0.36, judge_score: 0.36, rationale: 'terse answer; weak lexical overlap')
      expect(result[:score]).to be >= 0.6
      row = PWN::AI::Agent::Learning.outcomes.first
      expect(row).to include(success: true, quality_score: 0.36, rationale: 'terse answer; weak lexical overlap')
    end
  end
end

describe PWN::AI::Agent::Reward do
  describe 'executed request verification' do
    include_context 'pwn tmp sandbox'

    it 'keeps a stale executed contract unknown until it is checked again' do
      request = 'Write the answer'
      sid = PWN::Sessions.create(title: 'fresh checks')[:id]
      PWN::Sessions.append(session_id: sid, role: 'user', content: request)
      File.write(File.join(@tmp, 'answer'), 'ok')
      contract = { root: @tmp, requirements: [request], checks: [{ requirement: request, kind: :file, path: 'answer', expected: 'ok' }] }
      described_class.run_verification(request: request, session_id: sid, contract: contract)
      PWN::Sessions.append(session_id: sid, role: 'tool', content: 'later mutation')
      allow(described_class).to receive(:llm_judge).and_return(score: 0.99, source: :llm_orm)
      allow(described_class).to receive(:verify_as_reward).and_return(nil)
      result = described_class.judge(request: request, session_id: sid, final: 'PASS', commit: false)
      expect(result[:training_score]).to be_nil
    end

    it 'keeps partially covered requests unknown even when the model judge awards a high score' do
      request = 'Write the answer and validate the service'
      sid = PWN::Sessions.create(title: 'coverage')[:id]
      PWN::Sessions.append(session_id: sid, role: 'user', content: request)
      File.write(File.join(@tmp, 'answer'), 'ok')
      contract = { root: @tmp, requirements: ['Write the answer', 'validate the service'],
                   checks: [{ requirement: 'Write the answer', kind: :file, path: 'answer', expected: 'ok' }] }
      allow(described_class).to receive(:llm_judge).and_return(score: 0.99, source: :llm_orm)
      allow(described_class).to receive(:verify_as_reward).and_return(nil)
      result = described_class.judge(request: request, session_id: sid, final: 'PASS', verification_contract: contract, commit: false)
      expect(result[:training_score]).to be_nil
      expect(result[:success]).to be_nil
      expect(result.dig(:verification, :missing)).to eq(['validate the service'])
    end
  end

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

  it 'sentinel window_means weights llm_orm above verified heuristic outcomes' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE', File.join(tmp, 's.json'))
    20.times { described_class.send(:record_sentinel, proxy: true, judge: 0.9, source: :heuristic, training_score: 0.9) }
    20.times { described_class.send(:record_sentinel, proxy: true, judge: 0.2, source: :llm_orm) }
    window = described_class.send(:load_sentinel)[:window]
    expect(window.length).to eq(40)
    means = described_class.send(:window_means, window: window)
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

describe 'PWN::AI::Agent::Reward request verification' do
  include_context 'pwn tmp sandbox'

  it 'invalidates verification when another tool runs after the checks' do
    klass = PWN::AI::Agent::Reward
    session = PWN::Sessions.create(title: 'changed artifact')[:id]
    request = 'write the correct report'
    PWN::Sessions.append(session_id: session, role: 'user', content: request)
    klass.record_verification(request: request, session_id: session,
                              checks: [{ criterion: request, passed: true, evidence: 'independent readback' }])
    PWN::Sessions.append(session_id: session, role: 'tool', content: '{"success":true,"effect":"write"}')
    allow(klass).to receive(:llm_judge).and_return(score: 0.2, source: :llm_orm, rationale: 'report changed')
    allow(klass).to receive(:verify_as_reward).and_return(nil)
    v = klass.judge(request: request, session_id: session, final: 'PASS', commit: false)
    expect(v[:verification]).to be_nil
    expect(v[:success]).to be false
  end

  it 'does not calibrate or persist a heuristic guess as a known outcome' do
    klass = PWN::AI::Agent::Reward
    allow(klass).to receive(:llm_judge).and_return(score: 0.9, source: :heuristic, rationale: 'overlap')
    allow(klass).to receive(:verify_as_reward).and_return(nil)
    expect(PWN::AI::Agent::Curriculum).not_to receive(:calibrate)
    v = klass.judge(request: 'write a report', final: 'PASS report written',
                    trace: ['{"success":true}'], persist_components: true)
    row = PWN::AI::Agent::Learning.outcomes.first
    expect(row[:verdict].to_s).to eq('unknown')
    expect(row[:confidence]).to eq(v[:confidence])
    expect(row[:training_score]).to be_nil
  end

  it 'keeps unknown live judgments out of sentinel calibration and routing distrust' do
    klass = PWN::AI::Agent::Reward
    allow(klass).to receive(:llm_judge).and_return(score: 0.1, source: :heuristic, rationale: 'overlap')
    allow(klass).to receive(:verify_as_reward).and_return(nil)
    allow(PWN::AI::Agent::Curriculum).to receive(:calibrate)

    klass::SENTINEL_WINDOW.times do
      v = klass.judge(request: 'write a report', final: 'unrelated', proxy_ok: true)
      expect(v).to include(verdict: :unknown, training_score: nil)
    end
    snapshot = klass.sentinel

    expect(snapshot).to include(samples: 0, status: :insufficient)
    expect(PWN::AI::Agent::Curriculum).not_to have_received(:calibrate)
    expect(klass.proxy_distrust).to eq(0.0)
  end

  it 'does not warm the sentinel from unknown canonical or legacy heuristic outcomes' do
    klass = PWN::AI::Agent::Reward
    unknowns = [
      klass.resolve_outcome(outcome: { score: 0.1, source: :heuristic }),
      klass.resolve_outcome(outcome: { score: 0.9, source: :llm_orm }, critic_pass: false),
      klass.resolve_outcome(outcome: { source: :error }),
      { score: 0.1, success: true, judge_source: 'heuristic' },
      { score: 0.1, success: true, verdict: 'unknown' }
    ]
    File.write(PWN::AI::Agent::Learning::LEARNING_FILE, (unknowns * klass::SENTINEL_WINDOW).map(&:to_json).join("\n"))
    allow(PWN::AI::Agent::Curriculum).to receive(:calibrate)

    result = klass.warm_sentinel(limit: 200)

    expect(result).to include(added: 0, samples: 0)
    expect(klass.sentinel).to include(samples: 0, status: :insufficient)
    expect(PWN::AI::Agent::Curriculum).not_to have_received(:calibrate)
    expect(klass.proxy_distrust).to eq(0.0)
  end

  it 'warms known legacy engine scores and canonical verified failures' do
    klass = PWN::AI::Agent::Reward
    failed = klass.resolve_outcome(outcome: {
                                     score: 0.0, source: :heuristic,
                                     verification: { checks: [{ criterion: 'report', passed: false, evidence: 'report absent' }] }
                                   })
    rows = [{ score: 0.7, success: true, judge_source: 'llm_orm' }, failed]
    File.write(PWN::AI::Agent::Learning::LEARNING_FILE, rows.map(&:to_json).join("\n"))

    expect(klass.warm_sentinel).to include(added: 2, samples: 2)
    expect(klass.send(:load_sentinel)[:window].map { |row| row[:judge] }).to contain_exactly(0.0, 0.7)
  end

  it 'removes unknown persisted sentinel rows and their stale routing distrust' do
    klass = PWN::AI::Agent::Reward
    window = [
      { judge: 0.7, proxy: 1.0, source: 'llm_orm' },
      { judge: 0.1, proxy: 1.0, source: 'heuristic' },
      { judge: 0.9, proxy: 1.0, source: 'llm_orm', training_score: nil, decision_version: 1 },
      { judge: 0.1, proxy: 1.0, verdict: 'unknown' }
    ]
    File.write(klass::SENTINEL_FILE, JSON.generate(window: window, proxy_distrust: 0.85, distrust_at: Time.now.utc.iso8601))

    expect(klass.sentinel).to include(samples: 1, status: :insufficient)
    expect(klass.send(:load_sentinel)[:window]).to eq([window.first])
    expect(klass.proxy_distrust).to eq(0.0)
  end

  it 'keeps verified heuristic failures in the live sentinel and calibration' do
    klass = PWN::AI::Agent::Reward
    request = 'write the required report'
    session = PWN::Sessions.create(title: request)[:id]
    PWN::Sessions.append(session_id: session, role: 'user', content: request)
    klass.record_verification(request: request, session_id: session,
                              checks: [{ criterion: request, passed: false, evidence: 'required report is absent' }])
    allow(klass).to receive(:llm_judge).and_return(score: 0.9, source: :heuristic, rationale: 'overlap')
    allow(klass).to receive(:verify_as_reward).and_return(nil)
    allow(PWN::AI::Agent::Curriculum).to receive(:calibrate)

    v = klass.judge(request: request, session_id: session, final: 'report written', proxy_ok: true)

    expect(v).to include(success: false, training_score: 0.2)
    expect(klass.sentinel).to include(samples: 1, status: :insufficient)
    expect(PWN::AI::Agent::Curriculum).to have_received(:calibrate).with(hash_including(actual: 0.2))
  end

  it 'uses only a verifier record bound to the current request and session' do
    klass = PWN::AI::Agent::Reward
    session = PWN::Sessions.create(title: 'verified request')[:id]
    request = 'write the exact report content'
    PWN::Sessions.append(session_id: session, role: 'user', content: request)
    path = File.join(@tmp, 'report.txt')
    File.write(path, 'checked content')
    checks = [{ criterion: request, passed: File.read(path) == 'checked content', evidence: path }]
    klass.record_verification(request: request, session_id: session, checks: checks)
    allow(klass).to receive(:llm_judge).and_return(score: 0.0, source: :heuristic, rationale: 'weak overlap')
    allow(klass).to receive(:verify_as_reward).and_return(nil)
    v = klass.judge(request: request, session_id: session, final: 'Report written.', commit: false)
    expect(v[:success]).to be true
    expect(v[:verdict]).to eq(:solved)
    expect(v[:judge_score]).to eq(0.0)
    expect(v[:confidence]).to eq(1.0)
    expect(v[:training_score]).to be >= 0.6
    expect(v[:verification][:checks]).to eq(checks)

    PWN::Sessions.append(session_id: session, role: 'user', content: 'another task')
    stale = klass.judge(request: request, session_id: session, final: 'PASS', commit: false)
    expect(stale[:success]).not_to be true
    expect(stale[:verification]).to be_nil
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
    expect(v[:verdict].to_s).to eq 'unknown'
    expect(v[:training_score]).to be_nil
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
    expect(a[:verdict].to_s).to eq('unknown')
    expect(a[:training_score]).to be_nil
  end

  it 'does not drag a long analytical PASS to partial on zero token overlap' do
    klass = PWN::AI::Agent::Reward
    allow(klass).to receive(:llm_judge).and_return(nil)
    req = 'Analyze the harness in which you currently reside and provide a summary of strengths / weaknesses.'
    final = ('The control loop architecture is strong. Q-learning, calibration, anti-stall gates. ' * 20)
    v = klass.judge(request: req, final: final, trace: ['{"success":true,"result":{"exit":0}}'], commit: false)
    expect(v[:score]).to be > 0.35
  end

  it 'does not turn self-reported PASS or an unrelated successful command into verification' do
    klass = PWN::AI::Agent::Reward
    allow(klass).to receive(:llm_judge).and_return(
      { score: 0.2, source: :llm_orm, verdict: :wrong, rationale: 'missing requested artifact' }
    )
    allow(klass).to receive(:verify_as_reward).and_return(nil)
    v = klass.judge(request: 'write the requested report', final: 'PASS all done',
                    trace: ['{"success":true,"result":{"exit":0}}'], commit: false)
    expect(v[:score]).to eq(0.2)
    expect(v[:success]).to be false
    expect(v[:verifier_verdict]).to be_nil
  end

  it 'prefers model_routes.judge when selecting a judge model' do
    allow(PWN::Env).to receive(:is_a?).and_return(true)
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :model_routes, :judge).and_return('local-judge')
    m = PWN::AI::Agent::Reward.send(:judge_model)
    expect(m).to eq('local-judge')
  end

  it 'does not accept an unbound verifier PASS option as completion evidence' do
    allow(PWN::AI::Agent::Reward).to receive(:llm_judge).and_return(
      { score: 0.0, source: 'heuristic', verdict: :wrong, rationale: 'overlap=0.01', confidence: 0.3 }
    )
    v = PWN::AI::Agent::Reward.judge(
      request: 'write /tmp/x',
      final: 'PASS file exists',
      trace: ['{"success":true}'],
      commit: false,
      verifier_verdict: :pass
    )
    expect(v[:success]).not_to eq(true)
    expect(v[:verifier_verdict]).to be_nil
    expect(v[:judge_score]).to be < 0.6
  end

  it 'tags tool-backed heuristics without treating PASS prose as verification' do
    allow(PWN::AI::Agent::Reward).to receive(:llm_judge).and_return(nil)
    v = PWN::AI::Agent::Reward.judge(
      request: 'write /tmp/x and verify',
      final: 'PASS file exists',
      trace: ['{"success":true,"result":{"exit":0}}'],
      commit: false
    )
    expect(v[:heuristic_class].to_s).to eq('toolbacked')
    expect(v[:score]).to be < 0.6
    expect(v[:training_score]).to be_nil
  end

  it 'floors success when a verification block has PASS plus evidence, without using unbound verifier_verdict' do
    allow(PWN::AI::Agent::Reward).to receive(:llm_judge).and_return(
      { score: 0.4, source: 'heuristic', verdict: :partial, rationale: 'overlap=0.2', confidence: 0.4 }
    )
    v = PWN::AI::Agent::Reward.judge(
      request: 'write /tmp/x and verify',
      final: 'wrote /tmp/x',
      trace: ['{"success":true,"result":{"exit":0}}'],
      commit: false,
      verification: { verdict: :pass, evidence: 'stat /tmp/x size=120 sha256=aaaaaaaaaaaaaaaaaaaaaaaa' }
    )
    expect(v[:score_quality].to_f).to be < 0.6
    expect(v[:score].to_f).to be >= 0.6
    expect(v[:success]).to eq(true)
    expect(v[:rationale].to_s).to include('verification_floor')
  end
end
