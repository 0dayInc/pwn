# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Learning do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Learning
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Learning
    expect(help_response).to respond_to :help
  end

  it 'notes outcomes, surfaces context, and consolidates memory' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'learning.jsonl'))
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))

    PWN::AI::Agent::Learning.reset
    e = PWN::AI::Agent::Learning.note_outcome(task: 'nmap sweep', success: true, details: '3 hosts up', tags: %w[recon])
    expect(e[:success]).to be true

    rows = PWN::AI::Agent::Learning.outcomes(limit: 10)
    expect(rows.first[:task]).to eq 'nmap sweep'

    ctx = PWN::AI::Agent::Learning.to_context
    expect(ctx).to include('nmap sweep')

    stats = PWN::AI::Agent::Learning.stats
    expect(stats[:total_outcomes]).to be >= 1

    # duplicate lesson in memory then consolidate
    PWN::Memory.remember(key: :dup_a, value: 'same lesson', category: :lesson)
    PWN::Memory.remember(key: :dup_b, value: 'same lesson', category: :lesson)
    res = PWN::AI::Agent::Learning.consolidate(max_entries: 100)
    expect(res[:removed]).to be >= 1
  end

  it 'reflects on a session using the heuristic extractor' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'learning.jsonl'))
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    stub_const('PWN::Sessions::SESSIONS_DIR', File.join(tmp, 'sessions'))

    s = PWN::Sessions.create(title: 'learning spec')
    PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'scan target')
    PWN::Sessions.append(session_id: s[:id], role: 'tool', content: 'shell → {"success":false,"error":"timeout after 120s"}')
    PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: 'Retry with -T2')

    report = PWN::AI::Agent::Learning.reflect(session_id: s[:id])
    expect(report[:count]).to be >= 1
    expect(PWN::Memory.recall(query: 'failure').keys).not_to be_empty
  end

  it 'distills a skill from an explicit body' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'learning.jsonl'))
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    allow(PWN::AI::Agent::Learning).to receive(:skills_dir).and_return(File.join(tmp, 'skills'))

    out = PWN::AI::Agent::Learning.distill_skill(name: 'spec_skill', content: "# Spec Skill\nDo the thing.")
    expect(out[:saved]).to be true
    expect(File.exist?(out[:path])).to be true
  end
end
