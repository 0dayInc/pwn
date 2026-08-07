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
    expect(PWN::Memory.recall(query: 'fails').keys).not_to be_empty
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

  it 'promotes rubocop/rake process SOPs into PWN::Memory on note_outcome' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'learning.jsonl'))
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))

    PWN::AI::Agent::Learning.reset
    PWN::AI::Agent::Learning.note_outcome(
      task: 'Ensure rake and rubocop violations are fixed after patch',
      success: true,
      score: 0.9,
      details: 'bundle exec rubocop clean; rake green',
      tags: %w[hygiene]
    )
    mem = PWN::Memory.load
    expect(mem.keys).to include(:process_sop_code_hygiene)
    expect(mem[:process_sop_code_hygiene][:value].to_s).to match(/rubocop/i)
    expect(mem[:process_sop_code_hygiene][:category].to_s).to eq('lesson')
  ensure
    FileUtils.rm_rf(tmp) if defined?(tmp) && tmp
  end

  it 'P29 resyncs verdict after critic floor and strips request envelopes in to_context' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'learning.jsonl'))
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))

    PWN::AI::Agent::Learning.reset

    # Critic-capped solved-at-0.3 pattern (pre-P29 poison)
    PWN::AI::Agent::Learning.note_outcome(
      task: "REQUEST:\nwhats the bottom line?\n\nANSWER:\nfake bottom line",
      success: false,
      score: 0.3,
      details: 'solved(0.3) heuristic overlap=0.75 ratio=1.0 | fake bottom line',
      tags: %w[auto loop solved plan_cover_high]
    )
    PWN::AI::Agent::Learning.note_outcome(
      task: 'real bare goal that failed',
      success: false,
      score: 0.22,
      details: 'wrong(0.22) heuristic overlap=0.06 | blew up',
      tags: %w[auto loop wrong]
    )
    PWN::AI::Agent::Learning.note_outcome(
      task: 'successful scan',
      success: true,
      score: 0.9,
      details: 'solved(0.9) ok',
      tags: %w[auto loop solved]
    )

    # reconcile should flip solved→partial on the 0.3 row
    rep = PWN::AI::Agent::Learning.reconcile_verdict_tags!
    expect(rep[:repaired]).to be >= 1

    rows = PWN::AI::Agent::Learning.outcomes(limit: 20)
    fixed = rows.find { |r| (r[:score].to_f - 0.3).abs < 0.001 }
    expect(Array(fixed[:tags])).to include('partial')
    expect(Array(fixed[:tags])).not_to include('solved')
    expect(fixed[:details]).to match(/\Apartial\(0\.30?\)/)

    ctx = PWN::AI::Agent::Learning.to_context(limit: 5)
    # envelope stripped
    expect(ctx).to include('whats the bottom line?')
    expect(ctx).not_to match(/REQUEST:\nwhats/)
    # score visible
    expect(ctx).to match(/\[0\.30\]/)
    # RECENT OUTCOMES and RECENT FAILURES must not be identical dumps
    # (dedupe by id) — with 1 success + 2 fails, outcomes shows mix
    expect(ctx).to include('successful scan')
    expect(ctx).to include('cause:')
  ensure
    FileUtils.rm_rf(tmp) if defined?(tmp) && tmp
  end

  it 'P29 verdict_for_score thresholds match Reward.judge' do
    expect(PWN::AI::Agent::Learning.send(:verdict_for_score, score: 0.6)).to eq(:solved)
    expect(PWN::AI::Agent::Learning.send(:verdict_for_score, score: 0.59)).to eq(:partial)
    expect(PWN::AI::Agent::Learning.send(:verdict_for_score, score: 0.3)).to eq(:partial)
    expect(PWN::AI::Agent::Learning.send(:verdict_for_score, score: 0.29)).to eq(:wrong)
  end
end
