# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Policy do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'learns a better Q for a rewarded action than a punished one' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset

    allow(described_class).to receive(:enabled?).and_return(true)
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:agent] ||= {}
    PWN::Env[:ai][:agent][:policy] = true

    described_class.begin_episode(
      session_id: 'spec_win',
      request: 'inventory host tools',
      kind: :autonomous_goal,
      engine: :ollama
    )
    4.times { described_class.observe_step(action: 'shell', ok: true, session_id: 'spec_win') }
    described_class.finish(session_id: 'spec_win', score: 0.95, verdict: :solved)

    described_class.begin_episode(
      session_id: 'spec_lose',
      request: 'inventory host tools',
      kind: :autonomous_goal,
      engine: :ollama
    )
    4.times { described_class.observe_step(action: 'extro_rf_tune', ok: false, session_id: 'spec_lose') }
    described_class.finish(session_id: 'spec_lose', score: 0.05, verdict: :wrong)

    s = described_class.current_state
    # reopen a comparable state
    described_class.begin_episode(
      session_id: 'spec_query',
      request: 'inventory host tools',
      kind: :autonomous_goal,
      engine: :ollama
    )
    s = described_class.current_state
    q_shell = described_class.q(state: s, action: 'shell')
    q_rf    = described_class.q(state: s, action: 'extro_rf_tune')
    expect(q_shell).to be > q_rf

    rec = described_class.recommend(actions: %w[shell extro_rf_tune], epsilon: 0.0)
    expect(rec[:action]).to eq 'shell'

    ev = described_class.evaluate(limit: 10)
    expect(ev[:n]).to eq 2
    expect(ev[:mean_return]).not_to be_nil

    st = described_class.stats
    expect(st[:n_episodes]).to be >= 2
    expect(st[:n_updates]).to be >= 4
    expect(described_class.to_context).to include('POLICY')
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end
  it 'quality bin sees plan and usable result' do
    open_s = described_class.state(
      kind: :autonomous_goal,
      request: 'fix the reward judge',
      engine: :grok,
      ts_state: { plan: %w[inspect tighten verify], plan_idx: 0 }
    )
    done_s = described_class.state(
      kind: :autonomous_goal,
      request: 'fix the reward judge',
      engine: :grok,
      ts_state: { plan: %w[inspect tighten verify], plan_idx: 2 },
      final: 'The cheap ORM now grades the last tools and usable result.',
      score: 0.82
    )
    expect(open_s).to include('|pl')
    expect(open_s).to include('un|')
    expect(done_s).to include('|ph')
    expect(done_s).to include('uy|')
    expect(open_s).not_to eq(done_s)
  end

  it 'warmup! meets the episode budget so greedy suggestions appear' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    described_class::COLD_EPISODES.times do |i|
      sid = "warm_budget_#{i}"
      described_class.begin_episode(session_id: sid, request: 'uname', kind: :question, engine: :grok)
      described_class.observe_step(action: 'shell', ok: true, session_id: sid)
      described_class.finish(session_id: sid, score: 0.8, verdict: :solved)
    end
    tab = described_class.load
    tab[:returns] = tab[:returns].first(2)
    tab[:warmed_at] = nil
    described_class.save(table: tab)
    expect(described_class.cold?).to be true
    described_class.warmup!(limit: 20)
    expect(described_class.episode_budget_met?).to be true
    expect(described_class.to_context).not_to include('omit greedy suggestion')
    expect(described_class.to_context).to include('suggest=')
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'warmup! replays stored trajectories into Q' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    described_class.begin_episode(session_id: 'w1', request: 'uname', kind: :autonomous_goal, engine: :grok)
    described_class.observe_step(action: 'shell', ok: true, session_id: 'w1')
    described_class.finish(session_id: 'w1', score: 0.9, verdict: :solved)
    tab = described_class.load
    tab[:q] = {}
    tab[:visits] = {}
    tab[:warmed_at] = nil
    described_class.save(table: tab)
    r = described_class.warmup!(limit: 10)
    expect(r[:td_updates].to_i).to be >= 1
    expect(described_class.stats[:n_updates].to_i).to be >= 1
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'drops the omit-greedy banner once the episode budget is met' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
    described_class.reset
    allow(described_class).to receive(:enabled?).and_return(true)
    PWN::Env[:ai] ||= {}
    PWN::Env[:ai][:agent] ||= {}
    PWN::Env[:ai][:agent][:policy] = true
    described_class::COLD_EPISODES.times do |i|
      sid = "budget_#{i}"
      described_class.begin_episode(session_id: sid, request: 'uname', kind: :question, engine: :grok)
      described_class.observe_step(action: 'shell', ok: true, session_id: sid)
      described_class.finish(session_id: sid, score: 0.8, verdict: :solved)
    end
    ctx = described_class.to_context
    expect(ctx).to include('POLICY')
    expect(ctx).not_to include('omit greedy suggestion')
    expect(described_class.cold?).to be false
  ensure
    described_class.reset
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  describe 'Hermes episode handoff' do
    it 'detach_episode! snapshots and clears current_episode' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
      stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'policy_traj.jsonl'))
      described_class.reset
      allow(described_class).to receive(:enabled?).and_return(true)
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:policy] = true
      described_class.begin_episode(session_id: 'detach1', request: 'uname', kind: :question, engine: :grok)
      expect(described_class.current_episode).to be_a(Hash)
      ep = described_class.detach_episode!
      expect(ep[:session_id]).to eq('detach1')
      expect(described_class.current_episode).to be_nil
      described_class.attach_episode!(episode: ep)
      expect(described_class.current_episode[:session_id]).to eq('detach1')
    ensure
      described_class.attach_episode!(episode: nil)
    end
  end
end
