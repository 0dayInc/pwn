# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

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

    # Critic-capped solved-at-0.3 pattern must not persist as solved.
    poisoned = PWN::AI::Agent::Learning.note_outcome(
      task: "REQUEST:\nwhats the bottom line?\n\nANSWER:\nfake bottom line",
      success: false,
      score: 0.3,
      details: 'solved(0.3) heuristic overlap=0.75 ratio=1.0 | fake bottom line',
      tags: %w[auto loop solved plan_cover_high]
    )
    expect(Array(poisoned[:tags])).to include('partial')
    expect(Array(poisoned[:tags])).not_to include('solved')
    expect(poisoned[:details]).to match(/\Apartial\(0\.30?\)/)
    expect(poisoned[:success]).to be false
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

    # Legacy disk poison (bypass note_outcome) still gets repaired.
    File.open(PWN::AI::Agent::Learning::LEARNING_FILE, 'a') do |f|
      f.puts(JSON.generate(
               id: 'legacy029',
               task: 'legacy critic poison',
               success: false,
               score: 0.3,
               details: 'solved(0.3) leftover from pre-write-align',
               tags: %w[auto loop solved],
               timestamp: Time.now.utc.iso8601
             ))
    end
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

  it 'note_outcome rewrites solved-at-fail so inconsistent LEARNING rows cannot be stored' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 'learning.jsonl')
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', path)
    PWN::AI::Agent::Learning.reset
    e = PWN::AI::Agent::Learning.note_outcome(
      task: 'goal done?',
      success: true,
      score: 0.3,
      details: 'solved(0.3) critic floor left stale verdict',
      tags: %w[auto loop solved]
    )
    expect(e[:success]).to be false
    expect(Array(e[:tags])).to include('partial')
    expect(Array(e[:tags])).not_to include('solved')
    expect(e[:details]).to match(/\Apartial\(0\.30?\)/)
    disk = JSON.parse(File.read(path).lines.last, symbolize_names: true)
    expect(disk[:success]).to be false
    expect(Array(disk[:tags])).to include('partial')
    expect(Array(disk[:tags])).not_to include('solved')
    soft = PWN::AI::Agent::Learning.note_outcome(
      task: 'her relabel',
      success: 'soft',
      score: 0.7,
      details: 'HER',
      tags: %w[hindsight her]
    )
    expect(soft[:success]).to eq('soft')
    expect(Array(soft[:tags])).to include('solved')
  ensure
    FileUtils.rm_rf(tmp) if defined?(tmp) && tmp
  end

  it 'discounts raw success_rate when proxy_distrust is high' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'learning.jsonl'))
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    PWN::AI::Agent::Learning.reset
    8.times do |i|
      PWN::AI::Agent::Learning.note_outcome(
        task: "proxy win #{i}",
        success: true,
        score: 0.8,
        details: 'solved(0.80) handler-ok proxy',
        tags: %w[auto loop]
      )
    end
    2.times do |i|
      PWN::AI::Agent::Learning.note_outcome(
        task: "real fail #{i}",
        success: false,
        score: 0.2,
        details: 'wrong(0.20) missed',
        tags: %w[auto loop]
      )
    end
    allow(PWN::AI::Agent::Reward).to receive(:proxy_distrust).and_return(1.0)
    allow(PWN::AI::Agent::Reward).to receive(:sentinel).and_return(nil)
    # Simulate a lying proxy vs weaker judge mean by stubbing discount inputs
    # through a second corpus whose judge_mean sits below the boolean rate.
    stats = PWN::AI::Agent::Learning.stats
    expect(stats[:success_rate]).to eq(0.8)
    expect(stats[:judge_mean]).to be_within(0.02).of(0.68)
    expect(stats[:adjusted_success_rate]).to be < stats[:success_rate]
    expect(stats[:adjusted_success_rate]).to be_within(0.05).of(stats[:judge_mean])
    ctx = PWN::AI::Agent::Learning.to_context(limit: 5)
    expect(ctx).to match(/success_rate=\d+\.\d+% adj/)
    expect(ctx).not_to match(/success_rate=80\.0% over/)
  ensure
    FileUtils.rm_rf(tmp) if defined?(tmp) && tmp
  end

  it 'note_outcome enforces OUTCOME_DETAILS_MAX' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 'learning.jsonl')
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', path)
    long = 'D' * (PWN::AI::Agent::Learning::OUTCOME_DETAILS_MAX + 100)
    e = PWN::AI::Agent::Learning.note_outcome(task: 'policy details cap', success: true, details: long, tags: %w[spec])
    expect(e[:details].bytesize).to be <= PWN::AI::Agent::Learning::OUTCOME_DETAILS_MAX
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'prune_outcomes! keeps gold/high-value and enforces MAX_OUTCOME_ROWS' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 'learning.jsonl')
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', path)
    stub_const('PWN::AI::Agent::Learning::MAX_OUTCOME_ROWS', 30)
    stub_const('PWN::AI::Agent::Learning::EXEMPLARS_POOL_MIN', 5)
    stub_const('PWN::AI::Agent::Learning::FAILURE_WINDOW_MIN', 5)
    stub_const('PWN::AI::Agent::Learning::OUTCOME_RECENT_DAYS', 1)
    stub_const('PWN::AI::Agent::Learning::OUTCOME_RETAIN_DAYS', 2)

    now = Time.now.utc
    rows = []
    # gold protected
    5.times do |i|
      rows << {
        id: "g#{i}", task: "gold task #{i}", success: true, score: 0.9,
        session_id: "sid_g#{i}", details: 'ok', tags: %w[auto],
        timestamp: (now - (10 * 86_400)).iso8601
      }
    end
    # high-value tag protected
    rows << {
      id: 'hv1', task: 'needs human row', success: false, score: 0.2,
      session_id: 'sid_hv', details: 'x', tags: %w[needs_human],
      timestamp: (now - (20 * 86_400)).iso8601
    }
    # old low-value noise (should be droppable)
    40.times do |i|
      rows << {
        id: "n#{i}", task: "noise #{i}", success: false, score: 0.1,
        session_id: "sid_n#{i}", details: 'noise', tags: %w[auto loop partial],
        timestamp: (now - (30 * 86_400)).iso8601
      }
    end
    File.open(path, 'w') { |f| rows.each { |r| f.puts(JSON.generate(r)) } }

    res = PWN::AI::Agent::Learning.prune_outcomes!
    kept = File.readlines(path).map { |l| JSON.parse(l, symbolize_names: true) }
    ids = kept.map { |r| r[:id] }
    expect(ids).to include('g0', 'hv1')
    expect(kept.size).to be <= 30
    expect(res[:kept]).to eq(kept.size)
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'consolidate respects MAX_MEMORY_ENTRIES and PROTECT prefixes' do
    tmp = Dir.mktmpdir
    mem_path = File.join(tmp, 'memory.json')
    stub_const('PWN::Memory::MEMORY_FILE', mem_path)
    PWN::Memory.clear(force: true)
    PWN::Memory.remember(key: :operator_pref_keep, value: 'must survive', category: :preference)
    25.times do |i|
      PWN::Memory.remember(key: :"bulk_#{i}", value: "lesson body #{i} unique #{i}", category: :lesson, importance: 0.1, confidence: 0.1)
    end
    res = PWN::AI::Agent::Learning.consolidate(max_entries: 10)
    mem = PWN::Memory.load
    expect(mem.keys).to include(:operator_pref_keep)
    expect(mem.size).to be <= 10
    expect(res[:remaining]).to eq(mem.size)
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end
  it 'weighted_judge_mean prefers llm_orm rows over heuristic overlap' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'learning.jsonl'))
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    PWN::AI::Agent::Learning.reset
    8.times do |i|
      PWN::AI::Agent::Learning.note_outcome(
        task: "overlap #{i}", success: true, score: 0.9,
        details: 'solved(0.90) heuristic overlap', tags: %w[auto],
        judge_source: :heuristic
      )
    end
    8.times do |i|
      PWN::AI::Agent::Learning.note_outcome(
        task: "orm #{i}", success: false, score: 0.2,
        details: 'wrong(0.20) missed the ask', tags: %w[auto],
        judge_source: :llm_orm
      )
    end
    allow(PWN::AI::Agent::Reward).to receive(:proxy_distrust).and_return(1.0)
    allow(PWN::AI::Agent::Reward).to receive(:sentinel).and_return(nil)
    stats = PWN::AI::Agent::Learning.stats
    # unweighted mean = 0.55; ORM-weighted mean closer to 0.2
    expect(stats[:judge_mean]).to be < 0.45
    expect(stats[:judge_mean]).to be > 0.2
    expect(stats[:adjusted_success_rate]).to be_within(0.05).of(stats[:judge_mean])
  ensure
    FileUtils.rm_rf(tmp) if defined?(tmp) && tmp
  end

  it 'tags candidate lessons UNVERIFIED until two successes, then demotes after two contradictions' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::AI::Agent::Learning::LESSONS_FILE', File.join(dir, 'lessons.json'))
      row = described_class.lesson_record(text: 'always ls parent first')
      expect(described_class.lesson_prompt).to include('[UNVERIFIED]')
      described_class.lesson_observe(id: row[:id], success: true)
      described_class.lesson_observe(id: row[:id], success: true)
      expect(described_class.lesson_prompt).not_to include('[UNVERIFIED]')
      expect(described_class.lesson_prompt).to include('always ls parent first')
      described_class.lesson_observe(id: row[:id], success: false)
      described_class.lesson_observe(id: row[:id], success: false)
      expect(described_class.lesson_prompt).not_to include('always ls parent first')
    end
  end
end
