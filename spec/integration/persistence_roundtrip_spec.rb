# frozen_string_literal: true

require 'spec_helper'

# ─────────────────────────────────────────────────────────────────────────────
#  #5 — one tmpdir-sandboxed spec that exercises every ~/.pwn/* store
#  end-to-end. reinforced_feedback_loop_spec touches most of these
#  tangentially but never asserts the write→reload→delete round-trip
#  itself. NON-BLOCKING: every path stub_const'd into @tmp; no engine,
#  no crontab, no subprocesses.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN persistence stores — write → reload → delete round-trip', :aggregate_failures do
  include_context 'pwn tmp sandbox'

  describe 'PWN::Sessions' do
    it 'create → append(×3 roles) → load → to_response_history → stats → delete' do
      s = PWN::Sessions.create(title: 'roundtrip')
      %w[user assistant tool].each_with_index do |r, i|
        PWN::Sessions.append(session_id: s[:id], role: r, content: "msg#{i}")
      end
      loaded = PWN::Sessions.load(session_id: s[:id])
      expect(loaded.length).to eq(4) # system + 3
      expect(loaded.map { |e| e[:role] }).to eq(%w[system user assistant tool])
      hist = PWN::Sessions.to_response_history(session_id: s[:id])
      expect(hist).to be_a(Hash).or be_an(Array)
      expect(PWN::Sessions.stats[:total_sessions]).to be >= 1
      expect(PWN::Sessions.delete(session_id: s[:id])).to be_truthy
      expect(PWN::Sessions.load(session_id: s[:id])).to eq([])
    end
  end

  describe 'PWN::Memory' do
    it 'remember → recall(query:) → forget → clear' do
      PWN::Memory.remember(key: 'rt_key', value: 'needle-xyz', category: :fact)
      hits = PWN::Memory.recall(query: 'needle')
      expect(hits).not_to be_empty
      expect(PWN::Memory.forget(key: 'rt_key')).to be_truthy
      expect(PWN::Memory.recall(query: 'needle')).to be_empty
      PWN::Memory.remember(key: 'x', value: 'y')
      PWN::Memory.clear
      expect(PWN::Memory.load).to eq({})
    end
  end

  describe 'PWN::Cron' do
    before { allow(PWN::Cron).to receive(:install_crontab_entry).and_return('stubbed') }

    it 'create(ruby:) → list → run → disable → enable → remove; install_defaults idempotent' do
      job = PWN::Cron.create(name: 'rt', schedule: '0 * * * *', ruby: '1 + 1')
      expect(PWN::Cron.list.keys).to include(job[:id])
      run = PWN::Cron.run(id: job[:id])
      expect(run[:status]).to eq('success')
      expect(run[:result]).to eq(2)
      expect(PWN::Cron.disable(id: job[:id])[:enabled]).to be false
      expect(PWN::Cron.enable(id: job[:id])[:enabled]).to be true
      PWN::Cron.remove(id: job[:id])
      expect(PWN::Cron.list.keys).not_to include(job[:id])

      seeded = PWN::Cron.install_defaults
      expect(seeded.map { |j| j[:name] }).to include('curriculum_practice_nightly', 'curriculum_train_weekly')
      expect(PWN::Cron.install_defaults).to eq([]) # idempotent
    end
  end

  describe 'PWN::AI::Agent::Metrics' do
    it 'record(×N) → summary sorted by calls with correct success_rate' do
      m = PWN::AI::Agent::Metrics
      3.times { m.record(name: 'alpha', success: true, duration: 0.1) }
      m.record(name: 'alpha', success: false, duration: 0.1, error: 'x')
      m.record(name: 'beta', success: true, duration: 0.2)
      rows = m.summary(limit: 10)
      expect(rows.first[:name]).to eq('alpha')
      expect(rows.first[:calls]).to eq(4)
      expect(rows.first[:success_rate]).to eq(0.75)
      expect(rows.map { |r| r[:name] }).to eq(%w[alpha beta])
    end
  end

  describe 'PWN::AI::Agent::Mistakes' do
    it 'record ×3 same → count==3 → resolve → recurrence reopens [REGRESSED]' do
      mm = PWN::AI::Agent::Mistakes
      3.times { mm.record(tool: 'shell', error: 'nmpa: command not found at /var/x:1') }
      row = mm.for_tool(tool: 'shell').first
      expect(row[:count]).to eq(3)
      mm.resolve(signature: row[:signature], fix: 'use nmap not nmpa')
      expect(mm.find(signature: row[:signature])[:resolved]).to be true
      mm.record(tool: 'shell', error: 'nmpa: command not found at /var/y:9')
      re = mm.find(signature: row[:signature])
      expect(re[:resolved]).to be false
      expect(re[:regressed]).to be true
    end
  end

  describe 'PWN::AI::Agent::Swarm' do
    it 'create → bus_append → bus_tail ordering → list; depth cap raises past max_depth' do
      sw = PWN::AI::Agent::Swarm
      s  = sw.create(topic: 'rt')
      sw.bus_append(swarm_id: s[:swarm_id], from: :red, content: 'first')
      sw.bus_append(swarm_id: s[:swarm_id], from: :blue, content: 'second')
      tail = sw.bus_tail(swarm_id: s[:swarm_id], limit: 10)
      expect(tail.map { |m| m[:content] }.last(2)).to eq(%w[first second])
      expect(sw.list.map { |x| x[:swarm_id] }).to include(s[:swarm_id])

      sw.spawn(name: 'rt_persona', role: 'test persona')
      @agent_cfg[:max_depth] = 1
      Thread.current[:pwn_swarm_depth] = 1
      expect { sw.ask(name: 'rt_persona', request: 'x', swarm_id: s[:swarm_id]) }
        .to raise_error(/recursion depth/)
    end
  end
end
