# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::AI::Agent::Learning do
  describe 'worker lock ownership' do
    include_context 'pwn tmp sandbox'

    it 'does not inherit learning write ownership through copied request locals' do
      lock = described_class.send(:learning_lock)
      inherited = Thread.current[:pwn_learning_write_lock]
      entered = Queue.new
      acquired = Queue.new
      worker = Thread.new do
        Thread.current[:pwn_learning_write_lock] = inherited
        entered << true
        child_lock = described_class.send(:learning_lock)
        acquired << child_lock
      ensure
        described_class.send(:learning_unlock, lock: child_lock) if child_lock
      end
      Timeout.timeout(2) { entered.pop }
      expect(worker.join(0.05)).to be_nil
      described_class.send(:learning_unlock, lock: lock)
      lock = nil
      expect(worker.join(2)).to eq(worker)
      expect(acquired.pop).not_to be_nil
    ensure
      described_class.send(:learning_unlock, lock: lock) if lock
      worker&.join(2)
    end
  end

  describe 'failure regression tasks' do
    include_context 'pwn tmp sandbox'

    it 'exports a reviewed replay recipe only for a persisted independently verified failure' do
      request = 'Write result.txt'
      checks = [{ requirement: request, kind: :file, path: 'result.txt', expected: 'correct' }]
      verification = PWN::AI::Agent::Verification.run(request: request, requirements: [request], checks: checks, root: @tmp)
      row = described_class.note_outcome(task: request, outcome: { score: 0.9, source: :llm_orm, claimed_completion: true, verification: verification })
      recipe = described_class.regression_task(outcome_id: row[:id], request: request, checks: checks)
      expect(recipe).to include(schema: 'pwn-failure-regression-v1', split: 'regression', source_outcome_id: row[:id])
      expect(recipe[:source_verification_sha256]).to eq(Digest::SHA256.hexdigest(JSON.generate(row[:verification])))
      replay = PWN::AI::Agent::Verification.run(recipe[:contract].merge(root: @tmp))
      expect(replay[:status]).to eq(:fail)
      File.write(File.join(@tmp, 'result.txt'), 'correct')
      expect(PWN::AI::Agent::Verification.run(recipe[:contract].merge(root: @tmp))[:status]).to eq(:pass)
      expect { described_class.regression_task(outcome_id: row[:id], request: 'other', checks: checks) }.to raise_error(ArgumentError, /request/)
      expect { described_class.regression_task(outcome_id: row[:id], request: request, checks: []) }.to raise_error(ArgumentError, /coverage/)
      expect { described_class.regression_task(outcome_id: row[:id], request: request, checks: checks.map { |c| c.merge(path: '../escape') }) }.to raise_error(ArgumentError, /relative/)
      expect { described_class.regression_task(outcome_id: 'missing', request: request, checks: checks) }.to raise_error(ArgumentError, /verified failure/)
    end
  end

  describe 'evidence failure safety' do
    before do
      home = Dir.mktmpdir
      @home = home
      allow(Dir).to receive(:home).and_return(home)
      @root = File.join(home, '.pwn')
      FileUtils.mkdir_p(File.join(@root, 'sessions'))
      stub_const('PWN::Sessions::SESSIONS_DIR', File.join(@root, 'sessions'))
      stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(@root, 'learning.jsonl'))
      @sid = '20261012_120000_87654321'
      @source = File.join(@root, 'sessions', "#{@sid}.jsonl")
      @trace = %w[user tool observation assistant].map { |role| { role: role, content: "support #{role}" } }
      File.write(@source, "#{@trace.map(&:to_json).join("\n")}\n")
      @learning = described_class::LEARNING_FILE
      @original = "#{JSON.generate(id: 'lesson', session_id: @sid, task: 'support', success: true, timestamp: Time.now.utc.iso8601)}\n"
      File.write(@learning, @original)
    end

    after { FileUtils.rm_rf(@home) }

    it 'migrates Unicode evidence byte-exactly and rolls back the original index' do
      @trace.last[:content] = "café 日本語 🔒 e\u0301"
      File.binwrite(@source, "#{@trace.map(&:to_json).join("\n")}\r\n")
      original_source = File.binread(@source)
      @original = "#{JSON.generate(session_id: @sid, task: 'résumé 日本語')}\r\n"
      File.binwrite(@learning, @original)
      expect(PWN::Sessions.dependency_index[:dependencies][@sid]).to include(@learning)
      result = described_class.migrate_evidence(dry_run: false)
      expect(result[:migrated_rows]).to eq(1)
      row = JSON.parse(File.binread(@learning), symbolize_names: true)
      expect(described_class.evidence_transcript(row: row)).to eq(@trace)
      expect(described_class.evidence_complete?(row: row)).to be(true)
      expect(File.binread(@source)).to eq(original_source)
      migration = Digest::SHA256.hexdigest(@original)
      backup = File.join(@root, 'learning', 'migrations', "#{migration}.backup.jsonl")
      expect(File.binread(backup)).to eq(@original.b)
      expect(described_class.rollback_evidence(migration: migration)[:restored]).to be(true)
      expect(File.binread(@learning)).to eq(@original.b)
    end

    it 'verifies exact bytes without changing input encoding or accepting altered readback' do
      target = File.join(@root, 'learning', 'probe.bin')
      ['ASCII', 'café 日本語 🔒', "e\u0301", "\xFF\x00".b].each do |body|
        encoding = body.encoding
        original = body.dup
        described_class.send(:evidence_write, path: target, body: body)
        expect(File.binread(target)).to eq(original.b)
        expect(body).to eq(original)
        expect(body.encoding).to eq(encoding)
      end
      allow(described_class).to receive(:evidence_read).with(path: target).and_return('altered'.b)
      expect { described_class.send(:evidence_write, path: target, body: 'café') }
        .to raise_error(IOError, 'Evidence write verification failed')
    end

    it 'keeps original references when artifact creation is interrupted and retries safely' do
      allow(described_class).to receive(:evidence_write).and_wrap_original do |method, opts|
        raise IOError, 'injected interruption' if opts[:path].include?('/evidence/')

        method.call(opts)
      end
      expect { described_class.migrate_evidence(dry_run: false) }.to raise_error(IOError, 'injected interruption')
      expect(File.read(@learning)).to eq(@original)
      expect(PWN::Sessions.dependency_index[:dependencies]).to have_key(@sid)
      allow(described_class).to receive(:evidence_write).and_call_original
      expect(described_class.migrate_evidence(dry_run: false)[:migrated_rows]).to eq(1)
    end

    it 'refuses a concurrent index edit without overwriting it' do
      changed = "#{@original}#{JSON.generate(task: 'concurrent outcome')}\n"
      allow(described_class).to receive(:evidence_write).and_wrap_original do |method, opts|
        result = method.call(opts)
        File.write(@learning, changed) if opts[:path].include?('/evidence/')
        result
      end
      expect { described_class.migrate_evidence(dry_run: false) }.to raise_error(IOError, /changed during/)
      expect(File.read(@learning)).to eq(changed)
    end

    it 'pins missing, forged, and source-changed evidence and retains other stores' do
      described_class.migrate_evidence(dry_run: false)
      row = JSON.parse(File.read(@learning), symbolize_names: true)
      artifact = File.join(@root, 'learning', 'evidence', "#{row[:evidence_ref][:sha256]}.json")
      expect(File.stat(artifact).mode & 0o777).to eq(0o600)
      expect(File.stat(File.dirname(artifact)).mode & 0o777).to eq(0o700)
      File.write(File.join(@root, 'mistakes.json'), JSON.generate(error: { sessions: [@sid] }))
      expect(PWN::Sessions.dependency_index[:dependencies][@sid]).to eq([File.join(@root, 'mistakes.json')])
      File.open(@source, 'a') { |file| file.puts(JSON.generate(role: 'user', content: 'new turn')) }
      expect(described_class.evidence_complete?(row: row)).to be(false)
      File.delete(artifact)
      expect(PWN::Sessions.dependency_index[:session_errors][@sid]).to include(@learning)
      expect(PWN::Sessions.protected_session_ids(hot_days: -1)).to include(@sid)
      expect(PWN::Sessions.load(session_id: @sid)).not_to be_empty
    end

    it 'does not release a source pin for a hash-valid but incomplete snapshot' do
      described_class.migrate_evidence(dry_run: false)
      row = JSON.parse(File.read(@learning), symbolize_names: true)
      dir = File.join(@root, 'learning', 'evidence')
      data = JSON.parse(File.read(File.join(dir, "#{row[:evidence_ref][:sha256]}.json")))
      data['transcript'].pop
      data['row_count'] -= 1
      body = JSON.generate(data)
      hash = Digest::SHA256.hexdigest(body)
      File.write(File.join(dir, "#{hash}.json"), body)
      row[:evidence_ref] = { version: 1, id: hash, sha256: hash }
      File.write(@learning, "#{JSON.generate(row)}\n")
      expect(described_class.evidence_complete?(row: row)).to be(false)
      expect(PWN::Sessions.dependency_index[:dependencies][@sid]).to include(@learning)
    end

    it 'does not follow source symlinks or path-shaped session IDs' do
      File.delete(@source)
      File.symlink(@learning, @source)
      plan = described_class.migrate_evidence
      expect(plan[:malformed_sessions]).to eq(1)
      File.write(@learning, "#{JSON.generate(session_id: '../../private')}\n")
      expect(described_class.migrate_evidence[:malformed_refs]).to eq(1)
      expect(File.exist?(File.join(@root, 'learning'))).to be(false)
    end

    it 'rejects a symlinked evidence parent before creating directories through it' do
      target = File.join(@home, 'outside')
      FileUtils.mkdir_p(target)
      File.symlink(target, File.join(@root, 'learning'))
      expect { described_class.migrate_evidence(dry_run: false) }.to raise_error(IOError)
      expect(Dir.children(target)).to eq([])
      expect(File.read(@learning)).to eq(@original)
    end

    it 'exports the same uncompressed training context after source removal' do
      stub_const('PWN::AI::Agent::Learning::FINETUNE_DIR', File.join(@root, 'finetune'))
      before = described_class.export_finetune(compress: false)
      body = File.read(before[:path])
      described_class.migrate_evidence(dry_run: false)
      File.delete(@source)
      after = described_class.export_finetune(compress: false)
      expect(after[:samples]).to eq(1)
      expect(File.read(after[:path])).to eq(body)
      expect(PWN::AI::Agent::Reward.send(:load_trace, session_id: @sid)).to eq(['support tool'])
    end

    it 'persists PRM annotations by copy-on-write without losing the original supporting trace' do
      described_class.migrate_evidence(dry_run: false)
      before = File.read(@learning)
      old_row = JSON.parse(before, symbolize_names: true)
      File.delete(@source)
      expect(PWN::AI::Agent::Reward).to receive(:fold_step_reward_to_metrics).with(content: 'support tool', reward: 1)
      PWN::AI::Agent::Reward.send(:annotate_session, session_id: @sid, rewards: [1])
      trace = PWN::Sessions.load(session_id: @sid)
      expect(trace.find { |row| row[:role] == 'tool' }[:step_reward]).to eq(1)
      expect(trace.map { |row| row[:content] }).to eq(@trace.map { |row| row[:content] })
      expect(described_class.evidence_transcript(row: old_row)).to eq(@trace)
      expect(File.exist?(@source)).to be(false)
      expect(described_class.rollback_evidence(migration: Digest::SHA256.hexdigest(before))[:restored]).to be(true)
      expect(File.read(@learning)).to eq(before)
    end

    it 'reports malformed JSON without creating migration files' do
      File.open(@learning, 'a') { |file| file.puts('{invalid') }
      expect(described_class.migrate_evidence[:malformed_rows]).to eq(1)
      expect(described_class.migrate_evidence(dry_run: false)[:aborted]).to be(true)
      expect(File.exist?(File.join(@root, 'learning'))).to be(false)
    end

    it 'keeps migrated sessions discoverable to offline evaluation' do
      described_class.migrate_evidence(dry_run: false)
      File.delete(@source)
      allow(PWN::AI::Agent::Curriculum).to receive(:log)
      allow(PWN::AI::Agent::Reward).to receive(:judge).and_return(score: 1.0, training_score: 1.0, success: true)
      expect(PWN::AI::Agent::Curriculum.offline_judge(commit: false)[:scored]).to eq(1)
    end

    it 'recovers a prepared ledger after interruption following the atomic index replacement' do
      allow(described_class).to receive(:evidence_write).and_wrap_original do |method, opts|
        raise IOError, 'interrupted commit marker' if opts[:body].include?('"state":"committed"')

        method.call(opts)
      end
      expect { described_class.migrate_evidence(dry_run: false) }.to raise_error(IOError, 'interrupted commit marker')
      row = JSON.parse(File.read(@learning), symbolize_names: true)
      expect(described_class.evidence_transcript(row: row)).to eq(@trace)
      allow(described_class).to receive(:evidence_write).and_call_original
      id = Digest::SHA256.hexdigest(@original)
      expect(described_class.rollback_evidence(migration: id)[:restored]).to be(true)
      expect(File.read(@learning)).to eq(@original)
    end

    it 'serializes outcome writers with the migration lock and rejects rollback over later writes' do
      migration = described_class.migrate_evidence(dry_run: false)
      lock = described_class.send(:learning_lock)
      started = Queue.new
      writer = Thread.new do
        started << true
        described_class.note_outcome(task: 'concurrent', success: true)
      end
      started.pop
      expect(writer.join(0.05)).to be_nil
      described_class.send(:learning_unlock, lock: lock)
      lock = nil
      expect(writer.join(5)).to eq(writer)
      writer.value
      expect(described_class.outcomes(limit: 10).length).to eq(2)
      expect { described_class.rollback_evidence(migration: File.basename(migration[:ledger], '.json')) }.to raise_error(IOError, /changed since/)
    ensure
      described_class.send(:learning_unlock, lock: lock) if lock
      writer&.join(5)
    end

    it 'redacts copied evidence without opening a vault and keeps session export usable' do
      File.open(@source, 'a') { |file| file.puts(JSON.generate(role: 'observation', content: 'password=fixture-only-secret')) }
      expect(PWN::Redaction).not_to receive(:capture)
      described_class.migrate_evidence(dry_run: false)
      row = JSON.parse(File.read(@learning), symbolize_names: true)
      trace = described_class.evidence_transcript(row: row)
      expect(trace.last[:content]).to include('[REDACTED:password:')
      expect(JSON.generate(trace)).not_to include('fixture-only-secret')
      File.delete(@source)
      export = PWN::Sessions.export(session_id: @sid)
      expect(File.file?(export[:path])).to be(true)
      expect(export[:manifest]).to have_key("#{@sid}.jsonl")
    end
  end

  it 'migrates complete evidence only after verification and resolves it without the source' do
    Dir.mktmpdir do |home|
      allow(Dir).to receive(:home).and_return(home)
      root = File.join(home, '.pwn')
      FileUtils.mkdir_p(File.join(root, 'sessions'))
      stub_const('PWN::Sessions::SESSIONS_DIR', File.join(root, 'sessions'))
      stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(root, 'learning.jsonl'))
      sid = '20261012_120000_12345678'
      transcript = %w[user tool observation assistant].map { |role| { role: role, content: "support #{role}" } }
      source = File.join(root, 'sessions', "#{sid}.jsonl")
      File.write(source, "#{transcript.map(&:to_json).join("\n")}\n")
      learning = described_class::LEARNING_FILE
      original = "#{JSON.generate(id: 'lesson1', session_id: sid, task: 'support', success: true)}\n"
      File.write(learning, original)
      plan = described_class.migrate_evidence
      expect(plan[:migratable_sessions]).to eq(1)
      expect(File.read(learning)).to eq(original)
      expect(File.exist?(File.join(root, 'learning'))).to be(false)
      migration = described_class.migrate_evidence(dry_run: false)
      expect(migration[:migrated_rows]).to eq(1)
      migrated = File.read(learning)
      expect(described_class.rollback_evidence(migration: File.basename(migration[:ledger], '.json'))[:restored]).to be(true)
      expect(File.read(learning)).to eq(original)
      expect(described_class.migrate_evidence(dry_run: false)[:migrated_rows]).to eq(1)
      expect(File.read(learning)).to eq(migrated)
      row = JSON.parse(File.read(learning), symbolize_names: true)
      expect(row[:evidence_ref][:version]).to eq(1)
      expect(PWN::Sessions.dependency_index[:dependencies]).not_to have_key(sid)
      File.delete(source)
      expect(PWN::Sessions.load(session_id: sid)).to eq(transcript)
      expect(described_class.migrate_evidence(dry_run: false)[:migrated_rows]).to eq(0)
      artifact = File.join(root, 'learning', 'evidence', "#{row[:evidence_ref][:sha256]}.json")
      File.write(artifact, '{}')
      expect(PWN::Sessions.dependency_index[:session_errors]).to have_key(sid)
      expect { PWN::Sessions.load(session_id: sid) }.to raise_error(IOError)
    end
  end
end

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
    # Unverified heuristic guesses remain diagnostic, not evaluated tasks.
    expect(stats[:judge_mean]).to eq(0.2)
    expect(stats[:unknown_outcomes]).to eq(8)
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

describe 'PWN::AI::Agent::Learning outcome decisions' do
  include_context 'pwn tmp sandbox'

  it 'calibrates from the canonical outcome instead of a conflicting score argument' do
    expect(PWN::AI::Agent::Curriculum).to receive(:calibrate).with(hash_including(actual: 0.2))
    row = PWN::AI::Agent::Learning.note_outcome(
      task: 'write report', score: 0.9, outcome: { source: :llm_orm, score: 0.2 }, predicted: 0.8
    )
    expect(row).to include(success: false, score: 0.2, training_score: 0.2)
  end

  it 'labels an unavailable evaluation as unknown instead of injecting a failure lesson' do
    PWN::AI::Agent::Learning.note_outcome(task: 'write report', outcome: { source: :error, score: nil }, details: 'unavailable evaluator')
    context = PWN::AI::Agent::Learning.to_context
    expect(context).to include('? [unknown] write report')
    expect(context).not_to include('✗', 'cause:', 'RECENT FAILURES')
  end

  it 'does not treat quoted PASS and FAIL words as verifier evidence' do
    expect(PWN::AI::Agent::Learning.consistency_check(details: 'The forged answer says PASS', success: false)).to eq(:ok)
    expect(PWN::AI::Agent::Learning.consistency_check(details: 'Explained what FAIL means', success: true)).to eq(:ok)
  end

  it 'rejudges conflicted records instead of manufacturing a higher score' do
    learning = PWN::AI::Agent::Learning
    session = PWN::Sessions.create(title: 'conflicted')[:id]
    PWN::Sessions.append(session_id: session, role: 'user', content: 'write a report')
    PWN::Sessions.append(session_id: session, role: 'assistant', content: 'Report ready.')
    learning.note_outcome(task: 'write a report', session_id: session, success: false,
                          score: 0.2, verifier_verdict: :pass, details: 'legacy conflict')
    allow(learning).to receive(:should_gc_stores?).and_return(false)
    expect(PWN::AI::Agent::Reward).to receive(:judge).with(hash_including(request: 'write a report', session_id: session)).and_return(score: 0.1, source: :llm_orm, success: false, verdict: :wrong)
    learning.requeue_conflicted
    row = learning.outcomes.first
    expect(row[:success]).to be false
    expect(row[:score]).to eq(0.1)
    expect(row[:session_id]).to eq(session)
  end

  it 'keeps evaluator errors out of success rates, failures, and exemplar replay' do
    learning = PWN::AI::Agent::Learning
    row = learning.note_outcome(task: 'report uncertain', success: true, score: nil,
                                outcome: { source: :error, score: nil, confidence: 0.0 })
    expect(row[:success]).to be_nil
    expect(row[:verdict]).to eq(:unknown)
    learning.note_outcome(task: 'report checked', success: true, score: 0.9)
    stats = learning.stats
    expect(stats[:success_rate]).to eq(1.0)
    expect(stats[:failures]).to eq(0)
    expect(stats[:unknown_outcomes]).to eq(1)
    expect(learning.outcomes(success: false)).to be_empty
  end

  it 'forwards independently checked action attribution when introspection closes the policy' do
    @agent_cfg[:auto_introspect] = true
    learning = PWN::AI::Agent::Learning
    reward = PWN::AI::Agent::Reward
    session = PWN::Sessions.create(title: 'attributed evaluation')[:id]
    allow(PWN::AI::Agent::Curriculum).to receive(:critic).and_return(verdict: :pass)
    allow(learning).to receive(:should_gc_stores?).and_return(false)
    allow(learning).to receive(:reflect)
    allow(reward).to receive(:prm)
    receipt = { source: 'independent_verifier', verified_action_ids: ['writer'] }
    allow(reward).to receive(:judge).and_return(
      score: 0.9, source: :llm_orm,
      verification: { runner_version: 1, requirements: ['write a report'],
                      checks: [{ criterion: 'write a report', passed: true, evidence: 'fixture-digest' }], attribution: receipt }
    )
    expect(PWN::AI::Agent::Policy).to receive(:finish).with(hash_including(attribution: receipt))
    learning.auto_introspect(session_id: session, request: 'write a report', final: 'Report ready.', inline: true)
  end

  it 'preserves a cautious judge decision through persistence and policy training' do
    @agent_cfg[:auto_introspect] = true
    learning = PWN::AI::Agent::Learning
    reward = PWN::AI::Agent::Reward
    session = PWN::Sessions.create(title: 'uncertain evaluation')[:id]
    allow(PWN::AI::Agent::Curriculum).to receive(:critic).and_return(verdict: :pass)
    allow(learning).to receive(:should_gc_stores?).and_return(false)
    allow(learning).to receive(:reflect)
    allow(reward).to receive(:judge).and_return(
      score: 0.9, source: :heuristic, confidence: 0.35, verdict: :unknown,
      success: false, training_score: nil, rationale: 'unverified overlap'
    )
    expect(PWN::AI::Agent::Policy).to receive(:finish).with(hash_including(score: nil, verdict: :unknown))
    expect(learning).not_to receive(:fold_judge_into_metrics)
    expect(reward).not_to receive(:prm)
    learning.auto_introspect(session_id: session, request: 'write a report', final: 'Report ready.', inline: true)
    row = learning.outcomes.first
    expect(row[:success]).not_to be true
    expect(row[:verdict].to_s).to eq('unknown')
    expect(row[:training_score]).to be_nil
    expect(row[:confidence]).to eq(0.35)
    expect(row[:judge_source].to_s).to eq('heuristic')
  end
end

describe 'PWN::AI::Agent::Learning conflicted outcomes' do
  it 'tags verifier/judge conflicts and keeps them out of RECENT FAILURES' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(dir, 'learning.jsonl'))
      PWN::AI::Agent::Learning.note_outcome(task: 'pass-low-judge', success: false, score: 0.36, verifier_verdict: :pass, details: 'overlap=0.01 ratio=1.0')
      expect(PWN::AI::Agent::Learning.list_conflicted.first[:status]).to eq('conflicted')
      ctx = PWN::AI::Agent::Learning.to_context(limit: 10)
      expect(ctx).not_to include('overlap=')
    end
  end

  it 'prunes bak files down to max_baks' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(dir, 'learning.jsonl'))
      File.write(File.join(dir, 'learning.jsonl'), "{}\n")
      7.times { |i| File.write(File.join(dir, "learning.jsonl.bak-#{i}"), 'x') }
      out = PWN::AI::Agent::Learning.compact!(max_baks: 5)
      expect(Dir[File.join(dir, '*.bak*')].length).to eq(5)
      expect(out[:pruned]).to eq(2)
    end
  end
end
