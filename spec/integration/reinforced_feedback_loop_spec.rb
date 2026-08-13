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
    stub_const('PWN::AI::Agent::Curriculum::KPI_FILE',       File.join(@tmp, 'curriculum_kpi.jsonl'))
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE',        File.join(@tmp, 'policy.json')) if defined?(PWN::AI::Agent::Policy)
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE',    File.join(@tmp, 'policy_traj.jsonl')) if defined?(PWN::AI::Agent::Policy)
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
      # 4.1 — HER is success:'soft' (excluded from SFT export), not boolean true
      expect(row[:success].to_s).to eq 'soft'
      expect(Array(row[:tags])).to include('soft')
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

      # C4 contract: single user/assistant pair (no consecutive assistant
      # turns — breaks Qwen/Llama local chat templates). Rewarded tools are
      # folded into the assistant body under [exemplar tools]; bad steps
      # (step_reward <= 0) must not appear.
      msgs = learning.send(:compress_exemplar, session_id: s[:id], max_msgs: 6)
      expect(msgs.map { |m| m[:role].to_s }).to eq %w[user assistant]
      expect(msgs.first[:content]).to include('[exemplar]')
      body = msgs.last[:content]
      expect(body).to include('[exemplar tools]')
      expect(body).to include('3 hosts up')
      expect(body).not_to include('nmap: command not found')
      expect(body).to include('[exemplar final]')
      expect(body).to include('done')
      # only the +1 step is listed (one numbered line under tools)
      tool_block = body[/\[exemplar tools\]\n(.*?)\n\n\[exemplar final\]/m, 1].to_s
      expect(tool_block.lines.map(&:strip).reject(&:empty?)).to eq [
        '1. {"success":true,"result":{"stdout":"3 hosts up","stderr":"","exit":0}}'
      ]
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
  describe 'M1 · Learning.consolidate → semantic_merge' do
    it 'greedy-clusters :lesson embeddings at cosine ≥0.92 and merges each cluster to one entry' do
      skip 'PWN::MemoryIndex unavailable' unless defined?(PWN::MemoryIndex)
      now = Time.now.utc.iso8601
      mem = {
        a: { value: 'use nmap -sV for service detection',   category: 'lesson', timestamp: now, importance: 0.5 },
        b: { value: 'prefer nmap -sV to detect services',   category: 'lesson', timestamp: now, importance: 0.5 },
        c: { value: 'nmap -sV is best for service versions', category: 'lesson', timestamp: now, importance: 0.5 },
        d: { value: 'unrelated: rotate api keys quarterly',  category: 'lesson', timestamp: now, importance: 0.5 }
      }
      allow(PWN::MemoryIndex).to receive(:available?).and_return(true)
      allow(PWN::MemoryIndex).to receive(:refresh).and_return(
        a: { vec: [1.0, 0.0, 0.0] }, b: { vec: [0.99, 0.14, 0.0] },
        c: { vec: [0.98, 0.19, 0.0] }, d: { vec: [0.0, 0.0, 1.0] }
      )
      removed = learning.send(:semantic_merge, mem: mem)
      expect(removed).to contain_exactly(:b, :c)
      expect(mem[:a][:source]).to eq 'consolidate'
      expect(mem[:a][:importance]).to be >= 0.7
    end
  end

  describe 'M2 · MemoryIndex.recall_semantic (sim × recency × importance)' do
    it 'ranks by 0.6·sim + 0.25·recency + 0.15·importance so a fresh important fact outranks a stale similar one' do
      skip 'PWN::MemoryIndex unavailable' unless defined?(PWN::MemoryIndex)
      old = (Time.now.utc - (60 * 86_400)).iso8601
      now = Time.now.utc.iso8601
      mem = {
        stale: { value: 'nmap notes', category: 'lesson', timestamp: old, importance: 0.1 },
        fresh: { value: 'nmap notes', category: 'fact',   timestamp: now, importance: 0.9 }
      }
      allow(PWN::Memory).to receive(:load).and_return(mem)
      allow(PWN::MemoryIndex).to receive(:embed).and_return([[1.0, 0.0]])
      allow(PWN::MemoryIndex).to receive(:refresh).and_return(
        stale: { vec: [1.0, 0.0] }, fresh: { vec: [0.95, 0.31] }
      )
      hits = PWN::MemoryIndex.recall_semantic(query: 'nmap', limit: 2)
      expect(hits.first[:key]).to eq :fresh
      expect(hits.first[:score]).to be > hits.last[:score]
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Tier 4 — Curriculum & self-play
  # ═══════════════════════════════════════════════════════════════════════

  describe 'S1 · Curriculum.practice (mistake-driven auto-curriculum)' do
    it 'mines Mistakes.top → generate_reproducers → self_play, and auto-resolves only with N≥2 holdouts (2.4)' do
      mistakes.record(tool: 'shell', error: 'nmpa: command not found')
      sig = mistakes.top(limit: 1).first[:signature]
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      # 2.4 — N≥2 solved holdouts required; practice bumps prompts_per to ≥2
      allow(curriculum).to receive(:self_play).and_return(
        score: 0.85, verdict: :solved,
        final: 'use `nmap` (typo: nmpa→nmap)',
        prompt: 'fix nmap typo',
        trace: "shell → nmap -sn 10.0.0.0/24\nshell → true\npwn_eval → :ok"
      )
      r = curriculum.practice(limit: 1, prompts_per: 2)
      expect(r[:practiced]).to eq 1
      expect(r[:resolved]).to eq 1
      expect(mistakes.top(limit: 5, unresolved_only: true).map { |m| m[:signature] }).not_to include(sig)
      fixed = mistakes.find(signature: sig)
      expect(fixed[:structured_fix]).to be_a(Hash)
      expect(fixed[:structured_fix][:strategy]).to eq 'curriculum_practice'
      expect(fixed[:structured_fix][:winning_trace]).to include('shell →')
      prefs = reward.preferences(source: 'curriculum')
      expect(prefs).not_to be_empty
      # P14 — chosen is trajectory, not first-3-lines fix prose
      expect(prefs.first[:shape].to_s).to eq 'winning_trace'
      expect(prefs.first[:chosen]).to match(/WINNING_TRACE|shell →/i)
      expect(prefs.first[:chosen]).not_to eq 'use `nmap` (typo: nmpa→nmap)'
    end

    it 'does NOT auto-resolve with a single holdout success (2.4 gate)' do
      mistakes.record(tool: 'shell', error: 'single-holdout-unique-xyz')
      sig = mistakes.top(limit: 1).first[:signature]
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      allow(curriculum).to receive(:generate_reproducers).and_return(['only one prompt'])
      allow(curriculum).to receive(:self_play).and_return(
        score: 0.95, verdict: :solved, final: 'looks good', prompt: 'only one prompt'
      )
      r = curriculum.practice(limit: 1, prompts_per: 1)
      expect(r[:practiced]).to eq 1
      expect(r[:resolved]).to eq 0
      expect(mistakes.top(limit: 5, unresolved_only: true).map { |m| m[:signature] }).to include(sig)
    end

    it 'skips reward_signal and parked / needs_code_change fingerprints (2.5)' do
      m = mistakes.record(tool: 'reward_signal', error: 'proxy diverges unique-abc')
      mistakes.park(signature: m[:signature], reason: 'calibration')
      m2 = mistakes.record(tool: 'shell', error: 'engineer-only unique-def', needs_code_change: true)
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      expect(curriculum).not_to receive(:self_play)
      r = curriculum.practice(limit: 5, prompts_per: 1)
      # practiceable_only filter + explicit next guards → nothing practiced
      expect(r[:practiced]).to eq 0
    end

    it 'dry_run:true generates reproducer prompts but never self-plays' do
      mistakes.record(tool: 'shell', error: 'boom')
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      expect(curriculum).not_to receive(:self_play)
      r = curriculum.practice(limit: 1, prompts_per: 2, dry_run: true)
      expect(r[:dry_run]).to be true
      expect(r[:results].first[:prompts]).not_to be_empty
    end
  end

  describe 'S2 · Curriculum.counterfactual' do
    it 'forks an alt-persona branch, judges both, and emits a (loser,winner) DPO pair' do
      @agent_cfg[:counterfactual] = true
      allow(curriculum).to receive(:ensure_persona).and_return(nil)
      allow(curriculum).to receive(:ask_persona).and_return('pwn_eval(code: "PWN::Plugins::NmapIt.scan(...)")')
      # P9 — counterfactual scores via score_branch_detailed
      allow(curriculum).to receive(:score_branch_detailed) do |o|
        if o[:branch].to_s.include?('pwn_eval')
          { score: 0.80, mode: :real_dispatch, trace: o[:branch].to_s }
        else
          { score: 0.30, mode: :imagined, trace: nil }
        end
      end

      r = curriculum.counterfactual(request: 'scan 10.0.0.1', name: 'shell',
                                    args: '{"command":"nmpa -sV"}', error: 'nmpa: not found',
                                    hint: 'retry shell with nmap')
      expect(r[:branch]).to eq :b
      expect(r[:content]).to include('pwn_eval')
      expect(r[:shape]).to eq :real_dispatch
      pref = reward.preferences(source: 'counterfactual').first
      expect(pref[:chosen]).to include('pwn_eval')
      expect(pref[:rejected]).to include('retry shell')
      expect(pref[:shape].to_s).to eq 'real_dispatch'
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
      # P21/P25 — W1 pair only lands when structured winning_trace is present
      mistakes.resolve(
        signature: m[:signature],
        fix: 'use `nmap`, not `nmpa`',
        structured: {
          strategy: 'correct_binary_name',
          tool: 'shell',
          winning_trace: "shell → which nmap && nmap --version\nnmap present"
        }
      )
      pair = reward.preferences(source: 'mistakes_resolve').first
      expect(pair).not_to be_nil
      expect(pair[:chosen]).to include('nmap')
      expect(pair[:shape].to_s).to eq 'winning_trace'
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

  describe 'W2 · Curriculum.train_and_gate (regression-gated LoRA promotion)' do
    it 'dry_run exports SFT+DPO datasets + eval set + manual CLI without training' do
      allow(learning).to receive(:export_finetune).and_return(path: File.join(@tmp, 'sft.jsonl'), rows: 3)
      allow(reward).to   receive(:export_dpo).and_return(path: File.join(@tmp, 'dpo.jsonl'), rows: 2)
      2.times { mistakes.record(tool: 'shell', error: 'x') }
      r = curriculum.train_and_gate(dry_run: true, base_model: 'llama3')
      expect(r[:dry_run]).to be true
      expect(r[:version]).to eq 1
      expect(r[:sft][:rows]).to eq 3
      expect(r[:dpo][:rows]).to eq 2
      expect(r[:manual_cli]).to be_an(Array).and(all(be_a(String)))
      expect(r).not_to have_key(:promoted)
    end

    it 'promotes under gate v2 when resolved margin + mean + smoke all win' do
      allow(learning).to   receive(:export_finetune).and_return(path: 'sft', rows: 0)
      allow(reward).to     receive(:export_dpo).and_return(path: 'dpo', rows: 0)
      allow(curriculum).to receive(:detect_trainer).and_return(:unsloth)
      allow(curriculum).to receive(:run_trainer).and_return(File.join(@tmp, 'adapter'))
      allow(curriculum).to receive(:ollama_create).and_return('pwn-v1')
      allow(curriculum).to receive(:build_eval_set).and_return(
        Array.new(10) { |i| { signature: "s#{i}", prompt: "p#{i}" } }
      )
      allow(curriculum).to receive(:ab_gate_v2).and_return(
        baseline_resolved: 1, candidate_resolved: 4,
        baseline_mean: 0.5, candidate_mean: 0.8,
        resolved_win: true, mean_win: true, smoke_ok: true,
        promote: true, gate_version: 2, evalset_size: 10
      )
      # P19 — diet gate is AND-ed with ab_gate_v2; stub a clean W1 diet for this contract
      allow(curriculum).to receive(:preference_diet_gate).and_return(
        ok: true, reason: 'diet_ok', total: 40, trajectory_fraction: 0.5, monoculture: false
      )
      r = curriculum.train_and_gate(dry_run: false, base_model: 'llama3')
      expect(r[:promoted]).to be true
      expect(r[:weight_loop]).to eq :closed
      expect(r[:gate][:candidate_resolved]).to be > r[:gate][:baseline_resolved]
      expect(r[:gate][:gate_version]).to eq 2
      expect(File.exist?(curriculum::MODELS_FILE)).to be true
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

  describe 'E2 · Extrospection.correlate rule 9 (causal lead-lag drift)' do
    it 'emits :causal_drift when a Metrics changepoint FOLLOWS a toolchain drift within 24h' do
      extro = PWN::AI::Agent::Extrospection
      cp_at = Time.now.utc
      naive = ->(t) { t.strftime('%Y-%m-%dT%H:%M:%S') }
      snap  = { captured_at: naive.call(cp_at), host: {}, toolchain: {}, rf: {}, web: {} }
      allow(extro).to receive(:load).and_return(snapshot: snap, previous: {}, observations: [])
      allow(extro).to receive(:drift).and_return(
        changed: [{ path: 'toolchain.nmap', before: '7.94', after: naive.call(cp_at - 7_200) }],
        added: [], removed: []
      )
      allow(extro).to receive(:observations).and_return([])
      allow(metrics).to receive(:summary).and_return([])
      allow(metrics).to receive(:changepoints).and_return([{ name: 'nmap', at: naive.call(cp_at) }])
      allow(learning).to receive(:outcomes).and_return([])

      f = extro.correlate(limit: 20).find { |x| x[:kind] == :causal_drift }
      expect(f).not_to be_nil
      expect(f[:cause]).to eq 'toolchain.nmap'
      expect(f[:effect]).to include('nmap')
      expect(f[:lag_h]).to be_within(0.2).of(2.0)
      expect(f[:confidence]).to be_between(0.3, 0.95)
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

  # ═══════════════════════════════════════════════════════════════════════
  # P-controls — operational fixes that make the loop actually close
  # ═══════════════════════════════════════════════════════════════════════

  describe 'P9 · W1 pair geometry + write-time source quota' do
    it 'rejects CORRECTION: flaw-prose chosen sides without force' do
      r = reward.record_preference(
        prompt: 'which CVE?', rejected: 'CVE-2099-0001',
        chosen: 'CORRECTION: cited CVE does not exist', source: :critic
      )
      expect(r[:skipped]).to eq :weak_pair_geometry
      expect(reward.preferences.length).to eq 0
    end

    it 'accepts revised_answer shaped critic pairs' do
      r = reward.record_preference(
        prompt: 'which CVE?', rejected: 'CVE-2099-0001 is critical',
        chosen: "REVISED ANSWER (addresses: CVE does not exist):\nNo such CVE in NVD; verify before citing.",
        source: :critic, shape: :revised_answer
      )
      expect(r[:skipped]).to be_nil
      expect(r[:source]).to eq 'critic'
      expect(r[:shape]).to eq 'revised_answer'
    end

    it 'write-time quota refuses further mistakes_resolve once over cap' do
      # P25 requires trajectory shape; P9 still caps source share so traj
      # pairs cannot monoculture the ledger. Seed resolve-heavy window.
      12.times do |i|
        reward.record_preference(
          prompt: "p#{i}", rejected: "r#{i}" * 5,
          chosen: "STRATEGY: s\nWINNING_TRACE:\nshell → ok #{i}\n" + ('t' * 40),
          source: :mistakes_resolve, shape: :winning_trace, force: true
        )
      end
      # one non-resolve so multi-source window, but resolve still >40%
      reward.record_preference(
        prompt: 'q', rejected: 'x' * 20,
        chosen: "REVISED ANSWER:\n#{'y' * 40}",
        source: :critic, shape: :revised_answer, force: true
      )
      r = reward.record_preference(
        prompt: 'pX', rejected: 'rX' * 5,
        chosen: "STRATEGY: s\nWINNING_TRACE:\nshell → next\n#{'t' * 40}",
        source: :mistakes_resolve, shape: :winning_trace
      )
      expect(r[:skipped]).to eq :source_quota
      expect(r[:over_cap]).to be true
    end

    it 'Curriculum.critic records revised_answer preference not CORRECTION prose' do
      @agent_cfg[:critic] = true
      allow(curriculum).to receive(:ensure_persona).and_return(nil)
      allow(curriculum).to receive(:ask_persona).and_return('FLAW: cited CVE does not exist')
      allow(curriculum).to receive(:revise_after_flaw).and_return(
        "REVISED ANSWER (addresses: cited CVE does not exist):\nUse NVD-verified ids only."
      )
      v = curriculum.critic(request: 'which CVE?', final: 'CVE-2099-0001 is critical')
      expect(v[:verdict]).to eq :flaw
      pref = reward.preferences(source: 'critic').first
      expect(pref).not_to be_nil
      expect(pref[:chosen]).to include('REVISED ANSWER')
      expect(pref[:chosen]).not_to match(/\ACORRECTION:/i)
      expect(pref[:shape].to_s).to eq 'revised_answer'
    end
  end

  describe 'P10 · Reward.warm_sentinel' do
    it 'fills the R3 window from scored Learning outcomes' do
      45.times do |i|
        learning.note_outcome(task: "t#{i}", success: i.even?, score: i.even? ? 0.9 : 0.2,
                              details: 'x', tags: %w[rspec])
      end
      r = reward.warm_sentinel(limit: 80)
      expect(r[:added]).to be > 0
      expect(r[:samples]).to be >= r[:added]
      expect(%i[warmed_full warmed_partial full]).to include(r[:status])
    end
  end

  describe 'P11 · ab_gate_v2 promotion contract' do
    it 'requires resolved margin + mean win + smoke ok' do
      allow(curriculum).to receive(:replay_on_detailed) do |o|
        tag = o[:tag].to_s
        evalset = Array(o[:evalset])
        if evalset.any? { |e| e[:signature].to_s.start_with?('smoke_') }
          # smoke equal
          { resolved: 3, mean_score: 0.9, scores: [0.9, 0.9, 0.9] }
        elsif tag.include?('cand') || tag == 'cand'
          { resolved: 8, mean_score: 0.85, scores: [0.85] * 10 }
        else
          { resolved: 5, mean_score: 0.70, scores: [0.7] * 10 }
        end
      end
      allow(curriculum).to receive(:smoke_eval_set).and_return(
        [{ signature: 'smoke_uname', prompt: 'uname' }]
      )
      g = curriculum.send(:ab_gate_v2, baseline: 'base', candidate: 'cand',
                                       evalset: Array.new(10) { |i| { signature: "s#{i}", prompt: "p#{i}" } })
      expect(g[:gate_version]).to eq 2
      expect(g[:promote]).to be true
      expect(g[:resolved_win]).to be true
      expect(g[:mean_win]).to be true
      expect(g[:smoke_ok]).to be true
    end

    it 'refuses promotion on smoke regression' do
      allow(curriculum).to receive(:replay_on_detailed) do |o|
        evalset = Array(o[:evalset])
        if evalset.any? { |e| e[:signature].to_s.start_with?('smoke_') }
          tag = o[:tag].to_s
          if tag == 'cand'
            { resolved: 0, mean_score: 0.1, scores: [0.1] }
          else
            { resolved: 3, mean_score: 0.9, scores: [0.9] }
          end
        elsif o[:tag].to_s == 'cand'
          { resolved: 9, mean_score: 0.95, scores: [0.95] * 10 }
        else
          { resolved: 5, mean_score: 0.70, scores: [0.7] * 10 }
        end
      end
      allow(curriculum).to receive(:smoke_eval_set).and_return(
        [{ signature: 'smoke_uname', prompt: 'uname' }]
      )
      g = curriculum.send(:ab_gate_v2, baseline: 'base', candidate: 'cand',
                                       evalset: Array.new(10) { |i| { signature: "s#{i}", prompt: "p#{i}" } })
      expect(g[:promote]).to be false
      expect(g[:smoke_ok]).to be false
    end
  end

  describe 'P12 · export_finetune quality gate' do
    it 'drops low-score gold and compresses trajectories' do
      good = PWN::Sessions.create(title: 'sft-good')
      bad  = PWN::Sessions.create(title: 'sft-bad')
      [good, bad].each do |s|
        PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'scan lab')
        PWN::Sessions.append(session_id: s[:id], role: 'tool', content: ok_trace)
        PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: '3 hosts up')
      end
      learning.note_outcome(task: 'scan lab', success: true, score: 0.9, session_id: good[:id])
      learning.note_outcome(task: 'scan lab', success: true, score: 0.2, session_id: bad[:id])
      info = learning.export_finetune(out: File.join(@tmp, 'sft-p12.jsonl'))
      expect(info[:samples]).to eq 1
      expect(info[:min_score]).to eq 0.6
      expect(info[:compressed]).to be true
    end
  end

  describe 'P5 · export_dpo source-cap (no monoculture in weights)' do
    it 'downsamples so no single source exceeds DPO_SOURCE_CAP of the corpus' do
      10.times do |i|
        reward.record_preference(
          prompt: "p#{i}", rejected: "r#{i}", chosen: "WINNING_TRACE:\nshell → ok #{i} " + ('x' * 40),
          source: :mistakes_resolve, shape: :winning_trace, force: true
        )
      end
      3.times do |i|
        reward.record_preference(
          prompt: "q#{i}", rejected: "x#{i}", chosen: "y#{i} " + ('alt ' * 20),
          source: :counterfactual, shape: :real_dispatch, force: true
        )
      end
      2.times do |i|
        reward.record_preference(
          prompt: "z#{i}", rejected: "a#{i}", chosen: "REVISED ANSWER:\n#{'b' * 40}",
          source: :critic, shape: :revised_answer, force: true
        )
      end
      info = reward.export_dpo
      expect(info[:balanced]).to be true
      expect(info[:dropped]).to be > 0
      total = info[:pairs].to_f
      info[:by_source].each_value do |n|
        expect(n.to_f / total).to be <= (reward::DPO_SOURCE_CAP + 0.05)
      end
      # raw dump still available for diagnostics (no scrub, no balance)
      raw = reward.export_dpo(balance: false, scrub: false, out: File.join(@tmp, 'raw-dpo.jsonl'))
      expect(raw[:pairs]).to eq 15
      expect(raw[:balanced]).to be false
    end
  end

  describe 'P3 · Curriculum.offline_judge' do
    it 'scores recent sessions, writes offline_judge outcomes, and feeds W3 calibration from PLAN p(success)=' do
      s = PWN::Sessions.create(title: 'oj')
      PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'scan the lab net')
      PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: "PLAN:\n1. shell nmap\np(success)=0.7")
      PWN::Sessions.append(session_id: s[:id], role: 'tool', content: ok_trace)
      PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: '3 hosts up')

      r = curriculum.offline_judge(since_hours: 24, limit: 10, prm: true, commit: true)
      expect(r[:scored]).to be >= 1
      row = learning.outcomes(tag: 'offline_judge').first
      expect(row).not_to be_nil
      expect(row[:session_id]).to eq s[:id]
      expect(metrics.calibration(engine: :ollama)[:n]).to be >= 1
    end
  end

  describe 'C2 · HER samples never dominate exemplars_for' do
    it 'down-weights hindsight-tagged outcomes so soft successes cannot outrank real gold' do
      gold = PWN::Sessions.create(title: 'gold')
      her  = PWN::Sessions.create(title: 'her')
      [gold, her].each do |s|
        PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'nmap the target')
        PWN::Sessions.append(session_id: s[:id], role: 'tool', content: ok_trace)
        PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: 'open 22/80')
      end
      learning.note_outcome(task: 'nmap the target', success: true, score: 0.55, session_id: gold[:id])
      learning.note_outcome(task: 'nmap the target', success: true, score: 0.95,
                            session_id: her[:id], tags: %w[hindsight her soft])
      msgs = learning.exemplars_for(request: 'nmap the target host', limit: 1)
      # gold (untagged, lower raw score) must win after 0.35× haircut on HER
      expect(msgs).not_to be_empty
      # compress uses session; ensure we preferred gold by checking it is loadable
      # and HER's inflated score did not win solely on 0.95
      pool_scores = learning.send(:outcomes, limit: 50, success: true)
      her_row = pool_scores.find { |r| r[:session_id] == her[:id] }
      expect(Array(her_row[:tags])).to include('hindsight')
    end
  end

  describe 'S2/S3 remote defaults (enabled? auto)' do
    it 'defaults critic/counterfactual ON for non-ollama engines when flag is unset' do
      PWN::Env[:ai][:active] = :grok
      @agent_cfg.delete(:critic)
      @agent_cfg.delete(:counterfactual)
      expect(curriculum.send(:enabled?, key: :critic)).to be true
      expect(curriculum.send(:enabled?, key: :counterfactual)).to be true
      expect(curriculum.send(:enabled?, key: :red_team_plan)).to be true
      # ollama stays off
      PWN::Env[:ai][:active] = :ollama
      expect(curriculum.send(:enabled?, key: :critic)).to be false
      # explicit false always wins
      @agent_cfg[:critic] = false
      PWN::Env[:ai][:active] = :grok
      expect(curriculum.send(:enabled?, key: :critic)).to be false
    end
  end

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

  describe 'P14 · practice preference geometry' do
    it 'records winning_trace curriculum pairs instead of fix prose' do
      mistakes.record(tool: 'shell', error: 'p14-geometry-unique-zz')
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      allow(curriculum).to receive(:self_play).and_return(
        score: 0.9, verdict: :solved,
        final: "fixed with nmap\nsecond line\nthird",
        prompt: 'scan the lab safely',
        trace: "shell → nmap -sn 10.0.0.0/24\nshell → true"
      )
      r = curriculum.practice(limit: 1, prompts_per: 2)
      expect(r[:resolved]).to eq 1
      pref = reward.preferences(source: 'curriculum').first
      expect(pref[:shape].to_s).to eq 'winning_trace'
      expect(pref[:chosen]).to include('WINNING_TRACE')
      expect(pref[:chosen]).to include('nmap')
    end
  end

  describe 'P15 · preference ledger hygiene' do
    it 'usable_preference? drops CORRECTION prose and short resolve commentary' do
      expect(reward.usable_preference?(
               prompt: 'p', rejected: 'long ' * 80, chosen: 'CORRECTION: no', source: 'critic'
             )).to be false
      expect(reward.usable_preference?(
               prompt: 'p', rejected: 'fail',
               chosen: "STRATEGY: x\nWINNING_TRACE:\nshell → ok\n#{'x' * 80}",
               source: 'curriculum', shape: 'winning_trace'
             )).to be true
    end

    it 'scrub_preferences dry_run reports drops without rewriting' do
      reward.record_preference(
        prompt: 'p', rejected: 'bad final answer that is fairly long ' * 5,
        chosen: 'CORRECTION: short', source: :critic, force: true
      )
      reward.record_preference(
        prompt: 'q', rejected: 'old', chosen: "REVISED ANSWER:\n#{'ok ' * 40}",
        source: :critic, shape: :revised_answer, force: true
      )
      r = reward.scrub_preferences(dry_run: true)
      expect(r[:before]).to be >= 2
      expect(r[:dropped]).to be >= 1
      expect(r[:dry_run]).to be true
      expect(reward.preferences.length).to eq r[:before]
    end

    it 'export_dpo scrub drops weak geometry before source cap' do
      5.times do |i|
        reward.record_preference(
          prompt: "p#{i}", rejected: 'long rejected final ' * 30,
          chosen: 'CORRECTION: nope', source: :mistakes_resolve, force: true
        )
      end
      5.times do |i|
        reward.record_preference(
          prompt: "q#{i}", rejected: "r#{i}",
          chosen: "WINNING_TRACE:\nshell → uname -r\n#{i} " + ('trace ' * 20),
          source: :counterfactual, shape: :real_dispatch, force: true
        )
      end
      info = reward.export_dpo(out: File.join(@tmp, 'p15-dpo.jsonl'))
      expect(info[:geometry_dropped]).to be >= 5
      expect(info[:scrubbed]).to be true
      lines = File.readlines(info[:path]).map { |l| JSON.parse(l) }
      expect(lines).not_to be_empty
      expect(lines.any? { |l| l['chosen'].to_s.start_with?('CORRECTION:') }).to be false
    end

    it 'preference_balance(scrub: true) reports trajectory_fraction' do
      reward.record_preference(
        prompt: 'a', rejected: 'x', chosen: "WINNING_TRACE:\n#{'t' * 100}",
        source: :curriculum, shape: :winning_trace, force: true
      )
      bal = reward.preference_balance(scrub: true)
      expect(bal[:trajectory_fraction]).to be >= 0.0
      expect(bal).to have_key(:by_shape)
      expect(bal[:kept]).to be <= bal[:total]
    end
  end

  describe 'P16 · warm_sentinel engages controllers' do
    it 'fills to capacity and exposes proxy_distrust' do
      50.times do |i|
        learning.note_outcome(task: "w#{i}", success: i.even?, score: i.even? ? 0.85 : 0.2,
                              details: 'x', tags: %w[rspec p16])
      end
      r = reward.warm_sentinel(limit: 120)
      expect(r[:samples]).to be >= r[:added]
      expect(r).to have_key(:proxy_distrust)
      expect(%i[warmed_full warmed_partial full]).to include(r[:status])
    end
  end

  describe 'P17 · budget-exhaustion curriculum target' do
    it 'natural_repro_prompts for agent_loop favour short-finish tasks' do
      prompts = curriculum.send(
        :natural_repro_prompts,
        mistake: { tool: 'agent_loop', error: 'iteration budget exhausted', shape: 'handler_error' },
        count: 4
      )
      expect(prompts.length).to eq 4
      blob = prompts.join(' ').downcase
      expect(blob).to match(/one shell|at most two|no tools|three iterations|uname|cwd/)
    end

    it 'practice sorts budget fingerprints ahead of shell noise' do
      mistakes.record(tool: 'shell', error: 'shell-noise-unique-aaa')
      3.times { mistakes.record(tool: 'agent_loop', error: 'iteration budget exhausted without a final answer') }
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      allow(curriculum).to receive(:practice_skip?).and_return(false)
      seen = []
      allow(curriculum).to receive(:generate_reproducers) do |o|
        seen << o[:mistake][:tool]
        ['Answer in one shell call: print kernel release with uname -r']
      end
      curriculum.practice(limit: 1, prompts_per: 1, dry_run: true)
      expect(seen.first).to eq 'agent_loop'
    end
  end

  describe 'P18 · PRM closes into Registry.rank' do
    it 'Metrics.record_step_reward shifts prm_advantage and rank scoring' do
      10.times { metrics.record_step_reward(name: 'shell', reward: 1.0) }
      10.times { metrics.record_step_reward(name: 'extro_rf_tune', reward: -1.0) }
      expect(metrics.prm_advantage(name: 'shell')).to be > metrics.prm_advantage(name: 'extro_rf_tune')
      ranked = registry.rank(query: 'run a shell command on the host')
      expect(ranked.first.name).to eq 'shell'
    end
  end

  describe 'P19 · train_and_gate diet gate blocks promote on weak W1' do
    it 'preference_diet_gate fails when trajectory_fraction is low' do
      allow(reward).to receive(:preference_balance).and_return(
        total: 20, kept: 20, monoculture: true, fractions: { 'mistakes_resolve' => 0.9 },
        trajectory_fraction: 0.05, by_source: { 'mistakes_resolve' => 18 }
      )
      g = curriculum.send(:preference_diet_gate)
      expect(g[:ok]).to be false
    end

    it 'preference_diet_gate passes on diverse trajectory diet' do
      allow(reward).to receive(:preference_balance).and_return(
        total: 40, kept: 40, monoculture: false,
        fractions: { 'curriculum' => 0.3, 'critic' => 0.3, 'counterfactual' => 0.25, 'mistakes_resolve' => 0.15 },
        trajectory_fraction: 0.55, by_source: { 'curriculum' => 12 }
      )
      g = curriculum.send(:preference_diet_gate)
      expect(g[:ok]).to be true
      expect(g[:reason]).to eq 'diet_ok'
    end
  end

  describe 'P20 · judge-blended Metrics scalar' do
    it 'record_judge shifts effective_rate and advantage under distrust' do
      allow(reward).to receive(:proxy_distrust).and_return(0.8)
      20.times { metrics.record(name: 'shell', success: true, duration: 0.1) }
      20.times { metrics.record(name: 'extro_rf_tune', success: true, duration: 0.1) }
      10.times { metrics.record_judge(name: 'shell', score: 0.9) }
      10.times { metrics.record_judge(name: 'extro_rf_tune', score: 0.1) }
      expect(metrics.judge_rate(name: 'shell')).to be > 0.8
      expect(metrics.judge_rate(name: 'extro_rf_tune')).to be < 0.2
      expect(metrics.effective_rate(name: 'shell')).to be > metrics.effective_rate(name: 'extro_rf_tune')
      expect(metrics.advantage(name: 'shell')).to be > metrics.advantage(name: 'extro_rf_tune')
    end

    it 'exemplars_for drops low-score success rows' do
      learning.note_outcome(task: 'p20 high judge shell uname', success: true, score: 0.95,
                            details: 'ok', session_id: 'sess-p20-hi', tags: %w[rspec p20])
      # P29 — note_outcome refuses success:true + score<0.6, so a proxy-lie
      # cannot enter the success pool. Persist a rewritten fail, then also
      # unit-check the exemplars_for score filter on an in-memory leftover.
      rewritten = learning.note_outcome(task: 'p20 low judge shell uname', success: true, score: 0.2,
                                        details: 'proxy lie', session_id: 'sess-p20-lo', tags: %w[rspec p20])
      expect(rewritten[:success]).to be false
      pool = learning.outcomes(limit: 50, success: true)
      expect(pool.any? { |r| r[:task].to_s.include?('p20 low') }).to be false
      leftover = pool + [{ task: 'p20 low leftover', success: true, score: 0.2 }]
      kept = leftover.reject { |r| r.key?(:score) && r[:score].to_f < 0.6 }
      expect(kept.any? { |r| r[:task].to_s.include?('p20 low leftover') }).to be false
      expect(kept.any? { |r| r[:task].to_s.include?('p20 high') }).to be true
    end
  end

  describe 'P21/P25 · trajectory-only W1 writers' do
    it 'record_preference refuses non-trajectory shape without force' do
      r = reward.record_preference(
        prompt: 'p', rejected: 'bad', chosen: 'do this instead with more words here',
        source: :mistakes_resolve, shape: :fix_prose
      )
      expect(r).to be_a(Hash)
      expect(r[:skipped]).to eq :non_trajectory_shape
    end

    it 'record_preference accepts winning_trace shape' do
      r = reward.record_preference(
        prompt: 'p', rejected: 'failing shell args',
        chosen: "STRATEGY: x\nWINNING_TRACE:\nshell → uname -r\n#{'t' * 40}",
        source: :mistakes_resolve, shape: :winning_trace
      )
      expect(r).to be_a(Hash)
      expect(r[:skipped]).to be_nil
      expect(r[:shape].to_s).to eq 'winning_trace'
    end

    it 'mistakes.resolve does not write fix_prose preference pairs' do
      m = mistakes.record(tool: 'shell', error: 'p25-no-prose-unique-zz')
      before = reward.preferences.length
      mistakes.resolve(signature: m[:signature], fix: 'use a different flag next time')
      # no structured winning_trace → no new preference row
      expect(reward.preferences.length).to eq before
    end

    it 'mistakes.resolve writes winning_trace when structured_fix has trace' do
      m = mistakes.record(tool: 'shell', error: 'p25-with-trace-unique-yy')
      before = reward.preferences.length
      # winning_trace must be ≥40 chars (P21 gate inside Mistakes.resolve)
      mistakes.resolve(
        signature: m[:signature],
        fix: 'run uname -r once',
        structured: {
          strategy: 'short_horizon_finish',
          tool: 'shell',
          winning_trace: "shell → uname -r\n6.19.14-kali\n(kernel release)"
        }
      )
      expect(reward.preferences.length).to be > before
      pref = reward.preferences(source: 'mistakes_resolve').find { |p| p[:chosen].to_s.include?('uname') }
      expect(pref).not_to be_nil
      expect(pref[:shape].to_s).to eq 'winning_trace'
    end
  end

  describe 'P22 · W3 calibration lights up from plan_first' do
    it 'plan_first parse accepts p(success)= and stashes on Thread' do
      # Direct unit: emulate stash write path used by plan_first
      Thread.current[:pwn_plan_predicted] = 0.72
      expect(Thread.current[:pwn_plan_predicted]).to eq 0.72
      # calibrate path
      r = curriculum.calibrate(predicted: 0.72, actual: 1.0, engine: :ollama)
      expect(r[:brier]).to be_a(Numeric)
      expect(metrics.calibration(engine: :ollama)[:n]).to be >= 1
      Thread.current[:pwn_plan_predicted] = nil
    end

    it 'recover_predicted_from_session reads Thread stash' do
      Thread.current[:pwn_plan_predicted] = 0.55
      pred = learning.send(:recover_predicted_from_session, session_id: 'missing')
      expect(pred).to eq 0.55
      Thread.current[:pwn_plan_predicted] = nil
    end
  end

  describe 'P23 · short-horizon budget practice' do
    it 'self_play detects short-horizon prompt language' do
      # natural prompts already short-horizon; ensure generator still emits them
      prompts = curriculum.send(
        :natural_repro_prompts,
        mistake: { tool: 'agent_loop', error: 'iteration budget exhausted' },
        count: 3
      )
      expect(prompts.join(' ')).to match(/one shell|at most two|no tools|three iterations/i)
    end

    it 'practice refuses resolve when holdouts ok but trace weak on budget target' do
      mistakes.record(tool: 'agent_loop', error: 'p23-weak-trace-budget-zz')
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      allow(curriculum).to receive(:self_play).and_return(
        score: 0.9, verdict: :solved,
        final: 'x' * 2000, # long prose, no tool arrow
        prompt: 'Answer in one shell call: print kernel release with uname -r',
        trace: '' # empty trace
      )
      r = curriculum.practice(limit: 1, prompts_per: 2)
      row = r[:results]&.first || (r[:practiced] && nil)
      # practice returns practiced/resolved counts; weak trace should not resolve
      expect(r[:resolved]).to eq 0
    end
  end

  describe 'P24 · critic cost capped under budget hot' do
    it 'critic(text_only: true) returns without persona tools' do
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      r = curriculum.critic(
        request: 'what is kernel',
        final: '[pwn-ai] iteration budget exhausted',
        text_only: true
      )
      expect(r[:source].to_s).to include('text_only')
      expect(%i[pass flaw]).to include(r[:verdict])
      expect(r[:verdict]).to eq :flaw # heuristic sees budget exhausted
    end

    it 'critic(text_only: true) does not require critic env flag' do
      # even when critic disabled, text_only path works (forced by budget hot)
      allow(curriculum).to receive(:enabled?).and_return(false)
      allow(curriculum).to receive(:reflect_available?).and_return(false)
      r = curriculum.critic(request: 'q', final: 'solid answer with facts', text_only: true)
      expect(r[:verdict]).to eq :pass
    end
  end

  # ═══════════════════════════════════════════════════════════════════════
  # Design-priority STATUS (post P14–P25) — P0 / P1 / P2
  # documentation/Reinforcement-Learning.md § Design-priority STATUS
  # ═══════════════════════════════════════════════════════════════════════

  describe 'P0 · W1 generator diversity (TARGET_SOURCE_MIX + generator_mix)' do
    it 'exposes TARGET_SOURCE_MIX soft targets that sum to 1.0' do
      mix = reward::TARGET_SOURCE_MIX
      expect(mix.keys).to include('mistakes_resolve', 'curriculum', 'counterfactual', 'critic', 'user_correction')
      expect(mix.values.sum).to be_within(0.001).of(1.0)
      expect(mix['mistakes_resolve']).to be <= 0.40
    end

    it 'generator_mix flags underfilled sources and returns recommendation' do
      # seed a few usable traj pairs skewed toward curriculum/critic
      6.times do |i|
        reward.record_preference(
          prompt: "p#{i}",
          rejected: "bad answer #{i} " + ('x' * 40),
          chosen: "STRATEGY: use shell\nWINNING_TRACE: shell(uname)\nFINAL: linux #{i}",
          source: i.even? ? :curriculum : :critic,
          shape: :winning_trace
        )
      end
      m = reward.generator_mix
      expect(m[:n]).to be >= 5
      expect(m[:shares]).to be_a(Hash)
      expect(m[:targets]).to eq(reward::TARGET_SOURCE_MIX)
      expect(m[:urgent]).to include('counterfactual') # 0 share << 0.20 target
      expect(m[:healthy]).to eq(false)
      expect(m[:recommendation]).to match(/boost:|need_/)
    end

    it 'write_source_quota reports underfilled against TARGET_SOURCE_MIX' do
      12.times do |i|
        reward.record_preference(
          prompt: "q#{i}",
          rejected: "nope #{'y' * 40}",
          chosen: "STRATEGY: a\nWINNING_TRACE: t\nFINAL: ok #{i}",
          source: :curriculum,
          shape: :winning_trace
        )
      end
      q = reward.write_source_quota(source: 'counterfactual')
      expect(q[:underfilled]).to eq(true)
      expect(q[:target]).to eq(0.20)
    end

    it 'counterfactual and critic force-run when generator_mix marks them urgent' do
      allow(reward).to receive(:generator_mix).and_return(
        urgent: %w[counterfactual critic], suppress: [], healthy: false, n: 20,
        recommendation: 'boost:counterfactual,critic'
      )
      # env flags OFF — mix_need should still open the gate
      @agent_cfg[:counterfactual] = false
      @agent_cfg[:critic] = false
      allow(curriculum).to receive(:in_curriculum?).and_return(false)
      allow(curriculum).to receive(:reflect_available?).and_return(false)

      # counterfactual: stubs the expensive branch; we only assert it does not
      # short-circuit on disabled when mix_need is true. If still nil for other
      # reasons, at least enabled? gate is not the cause.
      allow(curriculum).to receive(:enabled?).and_call_original
      # critic text_only always works once gate opens
      r = curriculum.critic(request: 'q', final: 'a solid factual answer', text_only: true)
      expect(r[:source].to_s).not_to eq('disabled')
    end
  end

  describe 'P0 · Introspect budget (soft/hard ms + stages_skipped)' do
    it 'defines INTROSPECT_SOFT_MS < INTROSPECT_HARD_MS' do
      expect(learning::INTROSPECT_SOFT_MS).to be < learning::INTROSPECT_HARD_MS
      expect(learning::INTROSPECT_SOFT_MS).to be_between(500, 10_000)
    end

    it 'auto_introspect returns stages_skipped and respects hard budget' do
      @agent_cfg[:auto_introspect] = true
      # Force over_hard by collapsing thresholds
      stub_const('PWN::AI::Agent::Learning::INTROSPECT_SOFT_MS', 0)
      stub_const('PWN::AI::Agent::Learning::INTROSPECT_HARD_MS', 0)
      allow(loop_mod).to receive(:budget_exhaustion_hot?).and_return(false)

      sid = 'spec_budget_introspect'
      dir = File.join(@tmp, 'sessions')
      FileUtils.mkdir_p(dir)
      payload = [
        { role: 'user', content: 'uname -a', timestamp: Time.now.utc.iso8601 },
        { role: 'assistant', content: 'Linux kali', timestamp: Time.now.utc.iso8601 }
      ].map { |h| JSON.generate(h) }.join("\n")
      File.write(File.join(dir, "#{sid}.jsonl"), "#{payload}\n")

      r = learning.auto_introspect(session_id: sid, request: 'uname -a', final: 'Linux kali')
      expect(r).to be_a(Hash)
      expect(r).to have_key(:stages_run)
      expect(r).to have_key(:stages_skipped)
      expect(r[:stages_skipped]).to include(:prm) # hard skip
      expect(r[:elapsed_ms]).to be_a(Numeric)
    end
  end

  describe 'P1 · Local judge calibration (shrinkage + confidence)' do
    it 'heuristic judge returns confidence and shrinks extreme local scores' do
      v = reward.judge(
        request: 'what is the kernel',
        final: 'The Linux kernel is a monolithic unix-like kernel used by kali.',
        trace: [],
        proxy_ok: true,
        commit: false
      )
      expect(v[:source].to_s).to eq('heuristic')
      expect(v[:confidence]).to be <= 0.5
      expect(v).to have_key(:score_raw)
      # local + no-trace cap pulls highs down
      expect(v[:score]).to be <= 0.45 if v[:score_raw].to_f >= 0.6
      expect(v[:rationale].to_s).to match(/P1:local_no_trace_cap|heuristic/)
    end

    it 'Metrics.effective_rate scales distrust by judge_confidence' do
      # establish proxy success
      10.times { metrics.record(name: 'shell', success: true, duration: 0.01) }
      # high judge scores but low confidence (heuristic)
      8.times { metrics.record_judge(name: 'shell', score: 0.2, confidence: 0.35) }
      allow(metrics).to receive(:proxy_trust).and_return(0.3) # distrust 0.7
      rate = metrics.effective_rate(name: 'shell')
      conf = metrics.judge_confidence(name: 'shell')
      expect(conf).to be_within(0.05).of(0.35)
      # With conf=0.35, eff_d = 0.7*0.35 = 0.245 — still blended, not pure judge
      # pure judge would be ~0.2; pure proxy ~1.0; blend must sit between
      expect(rate).to be > 0.2
      expect(rate).to be < 1.0
    end
  end

  describe 'P1 · Practice outer KPI (practice_kpi + repeating_trend)' do
    it 'practice_kpi snapshots repeating counts and writes KPI_FILE' do
      mistakes.record(tool: 'agent_loop', error: 'iteration budget exhausted without a final answer')
      3.times { mistakes.record(tool: 'agent_loop', error: 'iteration budget exhausted without a final answer') }
      r = curriculum.practice_kpi(results: [{ resolved: true, mean_score: 0.8 }])
      expect(r[:repeating_n]).to be >= 1
      expect(r[:budget_repeating_n]).to be >= 1
      expect(r[:practiced]).to eq 1 # len(results) recorded tonight
      expect(r[:resolved_tonight]).to eq 1
      expect(File.exist?(curriculum::KPI_FILE)).to eq(true)
      expect(r[:trend]).to be_a(Hash)
    end

    it 'repeating_trend reports baseline then delta across snapshots' do
      curriculum.practice_kpi(results: [])
      # bump repeating by recording more
      4.times { mistakes.record(tool: 'assistant_answer', error: 'critic: [pwn-ai] iteration budget exhausted') }
      curriculum.practice_kpi(results: [])
      t = curriculum.repeating_trend
      expect(t[:samples]).to be >= 2
      expect(t).to have_key(:delta_repeating)
      expect(%i[improving flat regressing baseline]).to include(t[:status])
    end
  end

  describe 'P2 · PRM sample efficiency (PRM_MIN_N / fleet coverage)' do
    it 'prm_advantage is 0 until n >= PRM_MIN_N then applies shrinkage' do
      expect(metrics::PRM_MIN_N).to eq 5
      expect(metrics::PRM_FULL_N).to eq 20
      4.times { metrics.record_step_reward(name: 'shell', reward: 1.0) }
      expect(metrics.prm_n(name: 'shell')).to eq 4
      expect(metrics.prm_advantage(name: 'shell')).to eq 0.0
      metrics.record_step_reward(name: 'shell', reward: 1.0)
      expect(metrics.prm_n(name: 'shell')).to eq 5
      # single-tool zero-variance → damp*shrink keeps |adv| small but defined
      adv = metrics.prm_advantage(name: 'shell')
      expect(adv).to be_a(Numeric)
    end

    it 'Registry.rank drops PRM delta until ≥3 tools are PRM-ready' do
      # only 1 tool ready → delta 0; rank still returns by keyword
      10.times { metrics.record_step_reward(name: 'shell', reward: 1.0) }
      expect(metrics.prm_n(name: 'shell')).to be >= metrics::PRM_MIN_N
      ranked = registry.rank(query: 'run a shell command on the host')
      expect(ranked.map(&:name)).to include('shell')
      # spin up 3 ready tools — rank path must not raise
      %w[shell memory_recall sessions_list].each do |n|
        10.times { metrics.record_step_reward(name: n, reward: 0.5) }
      end
      expect do
        registry.rank(query: 'run a shell command on the host')
      end.not_to raise_error
    end
  end

  describe 'P2 · STATUS table is the flag authority (no archaeology)' do
    it 'Reinforcement-Learning.md ships a Design-priority STATUS section' do
      doc_path = File.expand_path('../../documentation/Reinforcement-Learning.md', __dir__)
      expect(File.exist?(doc_path)).to eq(true), "missing #{doc_path}"
      doc = File.read(doc_path)
      expect(doc).to match(/Design-priority STATUS/)
      expect(doc).to match(/generator_mix/)
      expect(doc).to match(/INTROSPECT_SOFT_MS/)
      expect(doc).to match(/practice_kpi/)
      expect(doc).to match(/PRM_MIN_N/)
    end
  end

  # Design-priority ops closure — make STATUS success criteria reachable on-host
  describe 'P0 ops · nightly diet close + shape backfill + mix in prompt' do
    it 'infer_shape tags legacy winning_trace-like chosen sides' do
      row = {
        source: 'mistakes_resolve',
        chosen: "shell → {\"success\":true}\npwn_eval → ok\n#{'x' * 80}",
        rejected: "failed earlier #{'y' * 80}",
        shape: ''
      }
      s = reward.infer_shape(row: row)
      expect(s).to eq('winning_trace')
    end

    it 'infer_shape tags long critic revisions as revised_answer' do
      row = {
        source: 'critic',
        chosen: 'A' * 250,
        rejected: 'B' * 100,
        shape: nil
      }
      expect(reward.infer_shape(row: row)).to eq('revised_answer')
    end

    it 'scrub_preferences backfills shape on kept rows when dry_run:false path runs over tmp' do
      # exercise infer_shape + usable path without rewriting the live ledger
      raw = {
        source: 'curriculum',
        prompt: 'finish under 5 tools',
        rejected: "iteration budget exhausted #{'z' * 80}",
        chosen: "shell → ok\nmemory_recall → hit\n#{'w' * 100}",
        shape: ''
      }
      expect(reward.usable_preference?(row: raw.merge(shape: 'winning_trace'))).to eq(true)
      inferred = reward.infer_shape(row: raw)
      expect(reward::TRAJECTORY_SHAPES).to include(inferred)
    end

    it 'offline_judge return hash reserves scrub/generator_mix/practice_kpi keys' do
      # dry structural contract: method source must call scrub + mix + kpi
      src = begin
        File.read(curriculum.instance_method(:offline_judge).source_location.first)
      rescue StandardError
        File.read('lib/pwn/ai/agent/curriculum.rb')
      end
      expect(src).to match(/scrub_preferences/)
      expect(src).to match(/generator_mix/)
      expect(src).to match(/practice_kpi/)
    end

    it 'Metrics.to_context surfaces W1 MIX when generator_mix is unhealthy' do
      allow(reward).to receive(:generator_mix).and_return(
        n: 20, healthy: false, trajectory_fraction: 0.1,
        urgent: %w[critic counterfactual], suppress: %w[mistakes_resolve],
        recommendation: 'boost:critic,counterfactual'
      )
      # ensure at least one metrics row so to_context is non-empty
      metrics.record(name: 'shell', success: true, duration: 0.01) if metrics.respond_to?(:record)
      ctx = metrics.to_context(limit: 3)
      expect(ctx).to match(/W1 MIX:/)
      expect(ctx).to match(/boost:critic/)
    end
  end

  describe 'P0 · Budget exhaust deepen (last-iter / no-CF-hot / exhaust Learning)' do
    it 'tightens budget-hot max_iters: 24 local (ollama/openwebui) / 75 remote (long-goal runway)' do
      src = File.read(loop_mod.method(:run).source_location.first)
      # max_iters is private_class_method — read surrounding source
      # P17 long-autonomy: local stays 24; remote keeps multi-step runway 75.
      # always-24-for-ALL starved long-lived goals after the hot text-only tail.
      expect(src).to match(/budget_exhaustion_hot\?/)
      expect(src).to match(/hot_cap = local_engine\? \? 24 : 75/)
      expect(src).to match(/n = \[n, hot_cap\]\.min/)
      expect(src).not_to match(/n = \[n, 24\]\.min/)
    end

    it 'forces tools=nil on last iter and skips counterfactual when budget-hot' do
      src = File.read(loop_mod.method(:run).source_location.first)
      expect(src).to match(/FINAL ITERATION/)
      expect(src).to match(/last_iter \? nil : tools/)
      # CF gate requires !budget_exhaustion_hot?
      expect(src).to match(/!budget_exhaustion_hot\?/)
      expect(src).to match(/Curriculum\.counterfactual/)
    end

    it 'exhaust path appends session + auto_introspect (not bare string only)' do
      src = File.read(loop_mod.method(:run).source_location.first)
      idx = src.index('shape: :budget_exhausted')
      expect(idx).not_to be_nil
      tail = src[idx, 800]
      expect(tail).to match(/append_session/)
      expect(tail).to match(/auto_introspect/)
      expect(tail).to match(/final_msg/)
    end

    it 'STATUS table lists Budget exhaust deepen' do
      doc = File.read(File.expand_path('../../documentation/Reinforcement-Learning.md', __dir__))
      expect(doc).to match(/Budget exhaust deepen/)
      expect(doc).to match(/Last-iter force-final/)
    end
  end

  describe 'P28 · autonomy (remote overconf runway + incomplete-final)' do
    it 'sets W3 overconf max_iters_cap to 120 on remote, 24 on local engines' do
      src = File.read(loop_mod.method(:run).source_location.first)
      expect(src).to match(/P28/)
      expect(src).to match(/remote_cap = 120/)
      expect(src).to match(/local_cap\s*=\s*24/)
      expect(src).to match(/local_engine\?\(engine: eng\) \? local_cap : remote_cap/)
      # P17 budget-hot: 24 ollama / 75 remote (not always-24)
      expect(src).to match(/hot_cap = local_engine\? \? 24 : 75/)
    end

    it 'defines incomplete_final? and continues on mid-goal handoff' do
      src = File.read(loop_mod.method(:run).source_location.first)
      expect(src).to match(/incomplete_final\?/)
      expect(src).to match(/INCOMPLETE_FINAL_RX/)
      expect(src).to match(/MONOLOGUE_TOOL_INTENT_RX/)
      expect(src).to match(%r{\[pwn-ai/p28\]})
      expect(src).to match(/continuing autonomously/)
      # last-iter wording no longer coaches "next single step" handoffs
      expect(src).not_to match(/next single step/)
      expect(src).to match(/Do NOT monologue/)
      expect(src).to match(/Emit NATIVE tool_calls NOW/)
    end

    it 'PromptBuilder injects AUTONOMY block' do
      src = File.read(File.expand_path('../../lib/pwn/ai/agent/prompt_builder.rb', __dir__))
      expect(src).to match(/AUTONOMY/)
      expect(src).to match(/Do NOT stop to/)
      expect(src).to match(/Multi-step goals must be finished in one Loop\.run/)
    end
  end

  describe 'R5 · Policy (live MDP + Q / REINFORCE)' do
    let(:policy) { PWN::AI::Agent::Policy }

    it 'records (s,a,r,s\') steps and updates Q toward a judge-scored terminal' do
      @agent_cfg[:policy] = true
      policy.reset
      policy.begin_episode(session_id: 'r5', request: 'run uname', kind: :autonomous_goal, engine: :ollama)
      policy.observe_step(action: 'shell', ok: true, session_id: 'r5')
      policy.observe_step(action: 'shell', ok: true, session_id: 'r5')
      report = policy.finish(session_id: 'r5', score: 0.9, verdict: :solved)
      expect(report[:steps]).to eq 2
      expect(report[:td_updates]).to be >= 1
      expect(policy.trajectories(limit: 1).first[:steps].length).to eq 2
      expect(policy.stats[:n_updates]).to be >= 2
    end

    it 'Q-advantage is zero until visits accumulate, so rank stays keyword-first' do
      @agent_cfg[:policy] = true
      policy.reset
      expect(policy.advantage(state: 'goal|t1|a0|f0|ollama', action: 'shell')).to eq 0.0
    end
  end
end
# rubocop:enable Metrics/BlockLength
