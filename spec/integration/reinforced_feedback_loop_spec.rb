# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

# ─────────────────────────────────────────────────────────────────────────────
#  Reinforced-feedback-loop integration spec (documentation/Reinforcement-
#  Learning.md). NON-BLOCKING by construction: every LLM / persona / browser /
#  extrospection call-site is stubbed, every persistent path is redirected
#  into a per-example Dir.mktmpdir, and PWN::Env[:ai][:module_reflection] is
#  forced OFF so Reward/Curriculum/Learning fall through to their calibrated
#  heuristic branches. The suite therefore runs in < 1 s under `rake spec`
#  with no engine, no ~/.pwn side-effects, and no external dependencies.
#
#  Each `describe` maps 1-to-1 onto a tier / feature-id in the RL doc so a
#  regression pinpoints exactly which requirement broke.
# ─────────────────────────────────────────────────────────────────────────────

# rubocop:disable Metrics/BlockLength
RSpec.describe 'PWN::AI::Agent reinforced feedback loop', :aggregate_failures do
  let(:reward)     { PWN::AI::Agent::Reward     }
  let(:curriculum) { PWN::AI::Agent::Curriculum }
  let(:learning)   { PWN::AI::Agent::Learning   }
  let(:metrics)    { PWN::AI::Agent::Metrics    }
  let(:mistakes)   { PWN::AI::Agent::Mistakes   }
  let(:loop_mod)   { PWN::AI::Agent::Loop       }
  let(:registry)   { PWN::AI::Agent::Registry   }

  let(:ok_trace)  { '{"success":true,"result":{"stdout":"3 hosts up","stderr":"","exit":0}}' }
  let(:bad_trace) { '{"success":false,"error":"RuntimeError: nmap: command not found"}' }
  let(:grep_miss) { '{"success":true,"result":{"stdout":"","stderr":"","exit":1}}' }

  # ── shared non-blocking sandbox ──────────────────────────────────────────
  before do
    @tmp = Dir.mktmpdir('pwn_rl_spec')
    # every persistent artefact of the feedback loop → tmp
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE',    File.join(@tmp, 'learning.jsonl'))
    stub_const('PWN::AI::Agent::Learning::FINETUNE_DIR',     File.join(@tmp, 'finetune'))
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE',      File.join(@tmp, 'metrics.json'))
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE',    File.join(@tmp, 'mistakes.json'))
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE',   File.join(@tmp, 'preferences.jsonl'))
    stub_const('PWN::AI::Agent::Reward::SENTINEL_FILE',      File.join(@tmp, 'sentinel.json'))
    stub_const('PWN::AI::Agent::Reward::DPO_DIR',            File.join(@tmp, 'finetune'))
    stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', File.join(@tmp, 'curriculum'))
    stub_const('PWN::AI::Agent::Curriculum::MODELS_FILE',    File.join(@tmp, 'curriculum', 'models.json'))
    stub_const('PWN::Sessions::SESSIONS_DIR',                File.join(@tmp, 'sessions'))
    stub_const('PWN::Memory::MEMORY_FILE',                   File.join(@tmp, 'memory.json'))
    stub_const('PWN::MemoryIndex::INDEX_FILE',               File.join(@tmp, 'memory.idx')) if defined?(PWN::MemoryIndex)

    # controllable env — agent flags start OFF; individual examples flip on
    @agent_cfg = {}
    @env_prev  = PWN::Env[:ai]
    PWN::Env[:ai] = { active: :ollama, module_reflection: false, agent: @agent_cfg }

    # kill every side-channel that could block / touch the real host
    allow(PWN::MemoryIndex).to receive(:available?).and_return(false) if defined?(PWN::MemoryIndex)
    allow(PWN::AI::Agent::Extrospection).to receive(:auto_extrospect).and_return(nil)
    allow(PWN::AI::Agent::Extrospection).to receive(:drift).and_return(changed: [], added: [], removed: [])

    Thread.current[:pwn_pending_pref] = nil
    Thread.current[:pwn_curriculum]   = nil
    Thread.current[:pwn_swarm_depth]  = nil
  end

  after do
    PWN::Env[:ai] = @env_prev
    Thread.current[:pwn_pending_pref] = nil
    Thread.current[:pwn_curriculum]   = nil
    FileUtils.remove_entry(@tmp) if @tmp && Dir.exist?(@tmp)
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Tier 1 — Reward signal
  # ═══════════════════════════════════════════════════════════════════════

  describe 'R1 · Reward.judge (Outcome Reward Model)' do
    it 'scores {0..1, verdict:} via heuristic fallback and feeds the sentinel' do
      v = reward.judge(request: 'scan the host', final: 'done — 3 hosts up',
                       trace: [ok_trace, ok_trace], proxy_ok: true)
      expect(v[:score]).to be_between(0.0, 1.0)
      expect(%i[solved partial wrong unknown]).to include(v[:verdict])
      expect(v[:success]).to eq(v[:score] >= 0.6)
      expect(JSON.parse(File.read(reward::SENTINEL_FILE))['samples']).to eq 1
    end

    it 'floors self-reported failure language at 0.0' do
      v = reward.judge(request: 'x', final: 'I was unable to complete the scan',
                       trace: [ok_trace], commit: false)
      expect(v[:score]).to eq 0.0
      expect(v[:success]).to be false
    end
  end

  describe 'R2 · Reward.prm (Process Reward Model)' do
    it 'assigns per-step {-1,0,1} and annotates the session with :step_reward (C4 feed)' do
      s = PWN::Sessions.create(title: 'prm')
      PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'scan')
      PWN::Sessions.append(session_id: s[:id], role: 'tool', content: ok_trace)
      PWN::Sessions.append(session_id: s[:id], role: 'tool', content: bad_trace)

      steps = reward.prm(request: 'scan', session_id: s[:id])
      expect(steps.map { |h| h[:reward] }).to eq [1, -1]

      reloaded = PWN::Sessions.load(session_id: s[:id]).select { |e| e[:role] == 'tool' }
      expect(reloaded.map { |e| e[:step_reward] }).to eq [1, -1]
    end
  end

  describe 'R3 · Reward.sentinel (reward-hacking guard)' do
    it 'flags proxy↔judge divergence >SENTINEL_GAP as a Mistake(tool: reward_signal)' do
      stub_const('PWN::AI::Agent::Reward::SENTINEL_WINDOW', 5)
      5.times do
        reward.judge(request: 'x', final: 'ok', trace: [bad_trace, bad_trace], proxy_ok: true)
      end
      r = reward.sentinel
      expect(r[:reward_hacked]).to be true
      expect((r[:proxy] - r[:judge]).abs).to be > reward::SENTINEL_GAP
      expect(mistakes.for_tool(tool: 'reward_signal')).not_to be_empty
    end
  end

  describe 'R4 · Loop.record_metrics × Reward.semantic_ok' do
    it 'benign non-zero exits count as Metrics :ok and do NOT open a Mistake' do
      loop_mod.send(:record_metrics, name: 'shell', started: Time.now, raw: grep_miss,
                                     args: '{"command":"grep needle haystack"}')
      row = metrics.summary.find { |r| r[:name] == 'shell' }
      expect(row[:success_rate]).to eq 1.0
      expect(mistakes.top(unresolved_only: true)).to be_empty
    end

    it 'real semantic failures record Metrics :ok=false AND a Mistake' do
      tele = loop_mod.send(:record_metrics, name: 'shell', started: Time.now, raw: bad_trace,
                                            args: '{"command":"nmap -sV 10.0.0.1"}')
      expect(tele[:ok]).to be false
      expect(tele[:mistake]).not_to be_nil
      expect(metrics.summary.find { |r| r[:name] == 'shell' }[:success_rate]).to eq 0.0
      expect(mistakes.top.first[:tool]).to eq 'shell'
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Tier 2 — Credit assignment & replay
  # ═══════════════════════════════════════════════════════════════════════

  describe 'C1 · Metrics bandit + Registry.rank' do
    it 'UCB gives an untried tool an exploration bonus over a saturated one' do
      20.times { metrics.record(name: 'shell', success: true, duration: 0.01) }
      expect(metrics.ucb(name: 'shell')).to be < metrics.ucb(name: 'never_called')
    end

    it 'advantage is positive for a tool that outperforms the fleet' do
      10.times { metrics.record(name: 'winner', success: true,  duration: 0.01) }
      10.times { metrics.record(name: 'loser',  success: false, duration: 0.01) }
      expect(metrics.advantage(name: 'winner')).to be > 0.0
      expect(metrics.advantage(name: 'loser')).to  be < 0.0
    end

    it 'Registry.rank folds advantage/UCB into keyword similarity without blocking' do
      registry.discover
      ranked = registry.rank(query: 'run a shell command on the host')
      expect(ranked).not_to be_empty
      expect(ranked.first.name).to eq 'shell'
    end
  end

  describe 'C2 · Learning.exemplars_for (prioritized replay)' do
    it 'orders by judge_score × recency × keyword_sim' do
      lo = PWN::Sessions.create(title: 'lo')
      hi = PWN::Sessions.create(title: 'hi')
      [lo, hi].each do |s|
        PWN::Sessions.append(session_id: s[:id], role: 'user',      content: 'nmap sweep the target')
        PWN::Sessions.append(session_id: s[:id], role: 'tool',      content: ok_trace)
        PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: 'done')
      end
      learning.note_outcome(task: 'nmap sweep the target', success: true, score: 0.20, session_id: lo[:id])
      learning.note_outcome(task: 'nmap sweep the target', success: true, score: 0.95, session_id: hi[:id])

      msgs = learning.exemplars_for(request: 'nmap sweep the target subnet', limit: 2)
      expect(msgs).not_to be_empty
      expect(msgs.first[:content]).to include('[exemplar]')
    end
  end

  describe 'C3 · Curriculum.hindsight (HER)' do
    it 'relabels a failed trajectory as a success under the achieved-goal' do
      PWN::Env[:ai][:module_reflection] = true
      allow(PWN::AI::Agent::Reflect).to receive(:on).and_return('enumerated open ports on 10.0.0.1')

      r = curriculum.hindsight(request: 'get root on 10.0.0.1', final: 'ports 22,80,443 open',
                               session_id: 'sid_her')
      expect(r[:achieved]).to eq 'enumerated open ports on 10.0.0.1'
      row = learning.outcomes(tag: 'hindsight').first
      expect(row[:success]).to be true
      expect(row[:task]).to eq 'enumerated open ports on 10.0.0.1'
    end
  end

  describe 'C4 · minimal sufficient trace' do
    it 'compress_exemplar keeps only step_reward > 0 tool steps' do
      s = PWN::Sessions.create(title: 'c4')
      PWN::Sessions.append(session_id: s[:id], role: 'user',      content: 'scan')
      PWN::Sessions.append(session_id: s[:id], role: 'tool',      content: ok_trace)
      PWN::Sessions.append(session_id: s[:id], role: 'tool',      content: bad_trace)
      PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: 'done')
      reward.prm(request: 'scan', session_id: s[:id]) # writes :step_reward

      msgs = learning.send(:compress_exemplar, session_id: s[:id], max_msgs: 6)
      tool_msgs = msgs.select { |m| m[:content].start_with?('[exemplar tool]') }
      expect(tool_msgs.length).to eq 1
      expect(tool_msgs.first[:content]).to include('3 hosts up')
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Tier 3 — Memory hygiene
  # ═══════════════════════════════════════════════════════════════════════

  describe 'M3 · consolidate evicts by (age/ttl)/(importance×confidence), not oldest-first' do
    it 'keeps the important/confident lesson and drops heuristic noise' do
      old = (Time.now.utc - (400 * 86_400)).iso8601
      mem = {
        keep_me: { value: 'gold', category: 'lesson', timestamp: old,
                   importance: 0.95, confidence: 0.95, source: 'human' },
        drop_a: { value: 'noise a', category: 'lesson', timestamp: old,
                  importance: 0.10, confidence: 0.10, source: 'heuristic' },
        drop_b: { value: 'noise b', category: 'lesson', timestamp: old,
                  importance: 0.10, confidence: 0.10, source: 'heuristic' }
      }
      PWN::Memory.save(mem: mem)
      learning.consolidate(max_entries: 1)
      expect(PWN::Memory.load.keys).to eq [:keep_me]
    end
  end

  describe 'M4 · note_outcome does NOT pollute PWN::Memory' do
    it 'writes learning.jsonl only; :lesson entries are reserved for reflect/resolve/human' do
      learning.note_outcome(task: 'probe', success: true, details: 'x')
      expect(File.exist?(learning::LEARNING_FILE)).to be true
      expect(PWN::Memory.load).to be_empty
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Tier 4 — Curriculum & self-play
  # ═══════════════════════════════════════════════════════════════════════

  describe 'S2 · Curriculum.counterfactual' do
    it 'forks an alt-persona branch, judges both, and emits a (loser,winner) DPO pair' do
      @agent_cfg[:counterfactual] = true
      allow(curriculum).to receive(:ensure_persona).and_return(nil)
      allow(curriculum).to receive(:ask_persona).and_return('pwn_eval(code: "PWN::Plugins::NmapIt.scan(...)")')
      allow(curriculum).to receive(:score_branch) { |o| o[:branch].include?('pwn_eval') ? 0.80 : 0.30 }

      r = curriculum.counterfactual(request: 'scan 10.0.0.1', name: 'shell',
                                    args: '{"command":"nmpa -sV"}', error: 'nmpa: not found',
                                    hint: 'retry shell with nmap')
      expect(r[:branch]).to eq :b
      expect(r[:content]).to include('pwn_eval')
      pref = reward.preferences(source: 'counterfactual').first
      expect(pref[:chosen]).to include('pwn_eval')
      expect(pref[:rejected]).to include('retry shell')
    end
  end

  describe 'S3 · Curriculum.critic' do
    it 'records a Mistake(assistant_answer) when the critic finds a flaw' do
      @agent_cfg[:critic] = true
      allow(curriculum).to receive(:ensure_persona).and_return(nil)
      allow(curriculum).to receive(:ask_persona).and_return('FLAW: cited CVE does not exist')

      v = curriculum.critic(request: 'which CVE?', final: 'CVE-2099-0001 is critical')
      expect(v[:verdict]).to eq :flaw
      expect(mistakes.for_tool(tool: 'assistant_answer').first[:error]).to include('cve does not exist')
    end

    it 'short-circuits to :pass when recursing (no infinite critic-of-critic)' do
      @agent_cfg[:critic] = true
      Thread.current[:pwn_curriculum] = true
      expect(curriculum.critic(request: 'x', final: 'y')[:verdict]).to eq :pass
    end
  end

  describe 'S4 · Curriculum.red_team_plan' do
    it 'returns a pre-emptive hint grounded in host telemetry' do
      @agent_cfg[:red_team_plan] = true
      allow(curriculum).to receive(:ensure_persona).and_return(nil)
      allow(curriculum).to receive(:ask_persona).and_return('step 2 will fail — shell success_rate 0%')

      hint = curriculum.red_team_plan(request: 'goal', plan: "1. shell nmap\n2. shell msfconsole")
      expect(hint).to start_with('[pwn-ai/red_team]')
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Tier 5 — Close the weight loop
  # ═══════════════════════════════════════════════════════════════════════

  describe 'W1 · preference-pair generation' do
    it 'Mistakes.resolve emits a (rejected: failing action, chosen: fix) pair' do
      m = mistakes.record(tool: 'shell', error: 'nmpa: command not found')
      mistakes.resolve(signature: m[:signature], fix: 'use `nmap`, not `nmpa`')
      pair = reward.preferences(source: 'mistakes_resolve').first
      expect(pair[:chosen]).to include('nmap')
      expect(PWN::Memory.load.keys.map(&:to_s)).to include("mistake_fix_#{m[:signature]}")
    end

    it 'user-correction: check_user_correction flips the last outcome, stashes the pref, ' \
       'and auto_introspect completes it on the next final' do
      s = PWN::Sessions.create(title: 'w1')
      PWN::Sessions.append(session_id: s[:id], role: 'user',      content: 'what version is nmap?')
      PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: 'nmap is v9.99')
      learning.note_outcome(task: 'what version is nmap?', success: true, session_id: s[:id])

      mistakes.check_user_correction(request: "no that's wrong, it is 7.95", session_id: s[:id])
      expect(learning.outcomes.first[:success]).to be false
      expect(learning.outcomes.first[:flipped_by]).to eq 'user_correction'
      expect(Thread.current[:pwn_pending_pref][:rejected]).to eq 'nmap is v9.99'

      @agent_cfg[:auto_introspect] = true
      allow(reward).to receive(:judge).and_return(score: 0.9, verdict: :solved, rationale: 'stub', success: true)
      allow(reward).to receive(:prm).and_return([])
      allow(reward).to receive(:sentinel).and_return(status: :insufficient)
      allow(learning).to receive(:reflect).and_return(count: 0)

      learning.auto_introspect(session_id: s[:id], request: "no that's wrong, it is 7.95",
                               final: 'You are right — nmap is 7.95')
      pair = reward.preferences(source: 'user_correction').first
      expect(pair[:rejected]).to eq 'nmap is v9.99'
      expect(pair[:chosen]).to include('7.95')
      expect(Thread.current[:pwn_pending_pref]).to be_nil
    end
  end

  describe 'W3 · plan-confidence calibration' do
    it 'tracks per-engine Brier + overconfidence' do
      curriculum.calibrate(predicted: 0.9, actual: 0.3, engine: :ollama)
      curriculum.calibrate(predicted: 0.9, actual: 0.3, engine: :ollama)
      cal = metrics.calibration(engine: :ollama)
      expect(cal[:n]).to eq 2
      expect(cal[:brier]).to be_within(0.001).of(0.36)
      expect(cal[:overconfidence]).to be_within(0.001).of(0.6)
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Tier 6 — intro↔extro join
  # ═══════════════════════════════════════════════════════════════════════

  describe 'E1 · CUSUM changepoint × cause: :env_drift' do
    it 'trips a changepoint after a run of failures on a previously-good tool' do
      stub_const('PWN::AI::Agent::Metrics::CUSUM_H', 0.3)
      8.times { metrics.record(name: 'nmap', success: true,  duration: 0.01) }
      6.times { metrics.record(name: 'nmap', success: false, duration: 0.01) }
      expect(metrics.changepoints.map { |c| c[:name] }).to include('nmap')
    end

    it 'env-drift-attributed failures increment :drift_count only and never reach [REPEATING]' do
      4.times { mistakes.record(tool: 'shell', error: 'nmap: not found', cause: :env_drift) }
      m = mistakes.for_tool(tool: 'shell').first
      expect(m[:count]).to eq 0
      expect(m[:drift_count]).to eq 4
      expect(mistakes.to_context).not_to include('REPEATING')
      expect(mistakes.to_context).to include('ENV_DRIFT')
    end

    it 'Loop.attribute_cause blames the world when changepoint AND toolchain drift coincide' do
      allow(metrics).to receive(:changepoints).and_return([{ name: 'shell', at: Time.now.utc.iso8601 }])
      allow(PWN::AI::Agent::Extrospection).to receive(:drift)
        .and_return(changed: [{ path: 'toolchain.nmap' }], added: [], removed: [])
      expect(loop_mod.send(:attribute_cause, name: 'shell')).to eq :env_drift
    end
  end

  describe 'E3 · Reward.verify_as_reward' do
    it 'a browser-refuted claim caps judge score at 0.2' do
      @agent_cfg[:verify_as_reward] = true
      allow(PWN::AI::Agent::Extrospection).to receive(:verify)
        .and_return(verdict: :refuted, confidence: 0.9)

      v = reward.judge(request: 'which CVE?', final: 'CVE-2099-0001 is critical',
                       trace: [ok_trace], commit: false)
      expect(v[:grounded][:verdict]).to eq :refuted
      expect(v[:score]).to be <= 0.2
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Full pipeline — Learning.auto_introspect orchestrates R1/R2/R3/S3/C3/W3
  # without touching an engine, a browser, or ~/.pwn.
  # ═══════════════════════════════════════════════════════════════════════

  describe 'auto_introspect end-to-end (non-blocking)' do
    it 'drives judge→outcome→prm→sentinel→calibrate→extrospect on a solved turn' do
      @agent_cfg[:auto_introspect] = true
      s = PWN::Sessions.create(title: 'e2e')
      PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'enumerate hosts')
      PWN::Sessions.append(session_id: s[:id], role: 'tool', content: "shell → #{ok_trace}")

      expect(reward).to      receive(:judge).and_call_original
      expect(reward).to      receive(:prm).and_call_original
      expect(reward).to      receive(:sentinel).and_call_original
      expect(curriculum).to  receive(:calibrate).and_call_original
      allow(learning).to     receive(:reflect).and_return(count: 0)
      expect(PWN::AI::Agent::Extrospection).to receive(:auto_extrospect)

      learning.auto_introspect(session_id: s[:id], request: 'enumerate hosts',
                               final: '3 hosts up on 10.0.0.0/24', predicted: 0.8)

      row = learning.outcomes.first
      expect(row[:success]).to be true
      expect(row[:tags]).to include('auto', 'solved')
      expect(row[:score]).to be >= 0.6
      expect(metrics.calibration(engine: :ollama)[:n]).to eq 1
    end

    it 'a critic :flaw caps the recorded score ≤ 0.3 and triggers HER on failure' do
      @agent_cfg[:auto_introspect] = true
      @agent_cfg[:critic]          = true
      allow(curriculum).to receive(:critic).and_return(verdict: :flaw, flaw: 'wrong CVE')
      allow(reward).to receive(:judge).and_return(score: 0.9, verdict: :solved, rationale: '', success: true)
      allow(reward).to receive(:sentinel).and_return(status: :insufficient)
      expect(curriculum).to receive(:hindsight)

      s = PWN::Sessions.create(title: 'e2e_flaw')
      learning.auto_introspect(session_id: s[:id], request: 'x', final: 'CVE-2099-0001')
      row = learning.outcomes.first
      expect(row[:success]).to be false
      expect(row[:score]).to be <= 0.3
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Repeat circuit-breaker — the negative-feedback edge that stops the loop
  # burning its iteration budget re-learning a recorded lesson.
  # ═══════════════════════════════════════════════════════════════════════

  describe 'guard_repeated_failure' do
    it 'injects the DO-NOT-RETRY guard once cross-session count ≥ REPEAT_THRESHOLD' do
      out = loop_mod.send(:guard_repeated_failure, name: 'shell', count: mistakes::REPEAT_THRESHOLD,
                                                   hint: '[pwn-ai/mistakes] KNOWN FIX: use nmap',
                                                   result: '{"success":false}')
      expect(out).to include('REPEATED FAILURE')
      expect(out).to include('KNOWN FIX: use nmap')
    end

    it 'passes the raw result through below the threshold' do
      out = loop_mod.send(:guard_repeated_failure, name: 'shell', count: 1, hint: '', result: 'raw')
      expect(out).to eq 'raw'
    end
  end
end
# rubocop:enable Metrics/BlockLength
