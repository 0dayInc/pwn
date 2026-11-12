# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::Reward, 'immutable PRM binding review' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @agent_cfg[:reward_llm] = true
    @sid = PWN::Sessions.create(title: 'PRM identity fixture')[:id]
    PWN::Sessions.append(session_id: @sid, role: 'user', content: 'original request')
    PWN::Sessions.append(session_id: @sid, role: 'tool', content: 'shell → {"success":true,"result":{"exit":0}}')
  end

  def append_next_turn
    PWN::Sessions.append(session_id: @sid, role: 'assistant', content: 'earlier answer')
    PWN::Sessions.append(session_id: @sid, role: 'user', content: 'next request')
    PWN::Sessions.append(session_id: @sid, role: 'tool', content: 'pwn_eval → {"success":false,"error":"next turn failed"}')
  end

  it 'freezes captured action identity before handing the snapshot to delayed work' do
    snapshot = described_class.prm_snapshot(session_id: @sid, request: 'original request')
    expect { snapshot[:binding][:actions].first[:sha256].replace('0' * 64) }.to raise_error(FrozenError)
    expect { snapshot[:trace].first.replace('different action') }.to raise_error(FrozenError)
  end

  it 'annotates the scored live action and Metrics after a new turn arrives during scoring' do
    allow(PWN::AI::Ollama).to receive(:chat) do |opts|
      expect(opts[:request]).to include('original request')
      append_next_turn
      '1'
    end
    result = described_class.prm(request: 'original request', session_id: @sid)
    expect(result.first[:reward]).to eq(1)
    tools = PWN::Sessions.load(session_id: @sid).select { |row| row[:role] == 'tool' }
    expect(tools.map { |row| row[:step_reward] }).to eq([1, nil])
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'shell')).to eq(1)
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'pwn_eval')).to eq(0)
  end

  it 'rejects changed scored bytes instead of applying rewards to replacement actions' do
    path = File.join(PWN::Sessions.sessions_dir, "#{@sid}.jsonl")
    after = nil
    allow(PWN::AI::Ollama).to receive(:chat) do
      rows = PWN::Sessions.load(session_id: @sid)
      rows.last[:content] = 'pwn_eval → {"success":false,"error":"replacement"}'
      after = rows.map { |row| "#{JSON.generate(row)}\n" }.join
      File.write(path, after)
      '1'
    end
    described_class.prm(request: 'original request', session_id: @sid)
    expect(File.binread(path)).to eq(after.b)
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'shell')).to eq(0)
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'pwn_eval')).to eq(0)
  end

  it 'does not annotate a supplied trace unrelated to the persisted action' do
    allow(PWN::AI::Ollama).to receive(:chat).and_return('1')
    described_class.prm(request: 'original request', session_id: @sid, trace: ['pwn_eval → {"success":true}'])
    expect(PWN::Sessions.load(session_id: @sid).last[:step_reward]).to be_nil
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'shell')).to eq(0)
  end

  it 'captures the action identity before a deferred worker starts even for repeated request text' do
    @agent_cfg[:auto_introspect] = true
    @agent_cfg[:critic] = false
    @agent_cfg[:verify_as_reward] = false
    finalizer = PWN::AI::Agent::TurnFinalizer
    started = Queue.new
    release = Queue.new
    first_worker = true
    allow(Thread).to receive(:new).and_wrap_original do |original, *args, &block|
      if first_worker
        first_worker = false
        original.call(*args) do
          started << true
          release.pop
          block.call
        end
      else
        original.call(*args, &block)
      end
    end
    prompts = Queue.new
    allow(PWN::AI::Ollama).to receive(:chat) do |opts|
      if opts[:system_role_content].to_s.include?('Process Reward')
        prompts << opts[:request]
        '1'
      else
        '{"score":0.8,"verdict":"solved","rationale":"offline scoring fixture","key_step":1}'
      end
    end
    finalizer.defer(session_id: @sid, request: 'original request', final: 'The requested observation is reported.')
    Timeout.timeout(3) { started.pop }
    PWN::Sessions.append(session_id: @sid, role: 'user', content: 'original request')
    PWN::Sessions.append(session_id: @sid, role: 'tool', content: 'pwn_eval → {"success":false,"error":"different action"}')
    release << true
    finalizer.join_all!(timeout: 5)
    tools = PWN::Sessions.load(session_id: @sid).select { |row| row[:role] == 'tool' }
    expect(tools.map { |row| row[:step_reward] }).to eq([1, nil])
    expect(prompts.size).to eq(1)
    expect(prompts.pop).to include('shell')
  ensure
    release << true if release
    finalizer&.join_all!(timeout: 5)
  end

  it 'binds copy-on-write retained annotations to the scored original action', :retained_binding_boundary do
    learning = PWN::AI::Agent::Learning
    old_body = old_path = nil
    allow(PWN::AI::Ollama).to receive(:chat) do
      append_next_turn
      learning.note_outcome(task: 'original request', success: true, session_id: @sid)
      learning.migrate_evidence(dry_run: false)
      reference = learning.outcomes.first.fetch(:evidence_ref).fetch(:sha256)
      old_path = File.join(File.dirname(learning::LEARNING_FILE), 'learning', 'evidence', "#{reference}.json")
      old_body = File.binread(old_path)
      File.rename(File.join(PWN::Sessions.sessions_dir, "#{@sid}.jsonl"), File.join(@tmp, 'retired-transcript-fixture'))
      '1'
    end
    described_class.prm(request: 'original request', session_id: @sid)
    tools = learning.session_evidence(session_id: @sid).select { |row| row[:role] == 'tool' }
    expect(tools.map { |row| row[:step_reward] }).to eq([1, nil])
    expect(File.binread(old_path)).to eq(old_body)
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'shell')).to eq(1)
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'pwn_eval')).to eq(0)
  end
end
