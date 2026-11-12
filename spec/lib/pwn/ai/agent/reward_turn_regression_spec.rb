# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Reward, 'turn-scoped process rewards' do
  include_context 'pwn tmp sandbox'

  before do
    allow(described_class).to receive(:llm_prm).and_return(nil)
    @sid = PWN::Sessions.create(title: 'offline process reward fixture')[:id]
    [
      ['user', 'earlier request'],
      ['tool', 'shell → {"success":true,"result":{"exit":0}}'],
      ['assistant', 'earlier answer'],
      ['user', 'current request'],
      ['tool', 'pwn_eval → {"success":true,"result":{"exit":0}}'],
      ['assistant', 'current answer']
    ].each { |role, content| PWN::Sessions.append(session_id: @sid, role: role, content: content) }
  end

  it 'annotates the same latest-turn tools that were scored in the live session' do
    described_class.prm(request: 'current request', session_id: @sid)
    tools = PWN::Sessions.load(session_id: @sid).select { |row| row[:role] == 'tool' }
    expect(tools.map { |row| row[:step_reward] }).to eq([nil, 1])
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'shell')).to eq(0)
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'pwn_eval')).to eq(1)
  end

  it 'annotates the same latest-turn tools in retained immutable evidence' do
    learning = PWN::AI::Agent::Learning
    learning.note_outcome(task: 'current request', success: true, session_id: @sid)
    learning.migrate_evidence(dry_run: false)
    File.unlink(File.join(PWN::Sessions::SESSIONS_DIR, "#{@sid}.jsonl"))
    described_class.prm(request: 'current request', session_id: @sid)
    tools = learning.session_evidence(session_id: @sid).select { |row| row[:role] == 'tool' }
    expect(tools.map { |row| row[:step_reward] }).to eq([nil, 1])
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'shell')).to eq(0)
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'pwn_eval')).to eq(1)
  end
end
