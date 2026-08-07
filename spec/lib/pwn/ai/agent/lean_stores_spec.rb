# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'fileutils'
require 'tmpdir'
require 'time'

RSpec.describe 'lean RL stores' do
  let(:tmpdir) { Dir.mktmpdir('pwn-lean-') }
  after { FileUtils.rm_rf(tmpdir) }

  def with_store_paths
    mem = File.join(tmpdir, 'memory.json')
    learn = File.join(tmpdir, 'learning.jsonl')
    mist = File.join(tmpdir, 'mistakes.json')
    sess = File.join(tmpdir, 'sessions')
    FileUtils.mkdir_p(sess)

    stub_const('PWN::Memory::MEMORY_FILE', mem)
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', learn)
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', mist)
    stub_const('PWN::Sessions::SESSIONS_DIR', sess)
    yield(mem: mem, learn: learn, mist: mist, sess: sess)
  end

  it 'Memory.lean! drops expired session_* but keeps prefs and SOPs' do
    with_store_paths do
      PWN::Memory.remember(key: :operator_pref_x, value: 'keep me', category: :preference, importance: 1.0)
      PWN::Memory.remember(key: :process_sop_y, value: 'always rake', category: :lesson, importance: 1.0)
      PWN::Memory.remember(
        key: :session_old_context,
        value: 'ephemeral',
        category: :fact,
        ttl: 1
      )
      # backdate
      m = PWN::Memory.load
      m[:session_old_context][:timestamp] = (Time.now.utc - 86_400).iso8601
      PWN::Memory.save(mem: m)

      r = PWN::Memory.lean!
      expect(r[:removed]).to be >= 1
      left = PWN::Memory.load
      expect(left.keys.map(&:to_s)).to include('operator_pref_x', 'process_sop_y')
      expect(left.keys.map(&:to_s)).not_to include('session_old_context')
    end
  end

  it 'Learning.prune_outcomes! keeps gold success+score and never empties failure window' do
    with_store_paths do |paths|
      now = Time.now.utc
      rows = []
      # gold
      5.times do |i|
        rows << {
          id: "g#{i}", task: "gold task #{i}", success: true, score: 0.9,
          session_id: "sid_gold_#{i}", tags: %w[auto loop], details: 'x' * 50,
          timestamp: (now - i).iso8601
        }
      end
      # bulk old low-score auto noise
      40.times do |i|
        rows << {
          id: "n#{i}", task: "noise #{i % 3}", success: false, score: 0.1,
          session_id: "sid_n_#{i}", tags: %w[auto loop wrong], details: 'y' * 1200,
          timestamp: (now - ((50 + i) * 86_400)).iso8601
        }
      end
      File.write(paths[:learn], "#{rows.map { |r| JSON.generate(r) }.join("\n")}\n")

      r = PWN::AI::Agent::Learning.prune_outcomes!(max_rows: 30, retain_days: 45, recent_days: 14)
      kept = File.readlines(paths[:learn]).map { |l| JSON.parse(l, symbolize_names: true) }
      gold_left = kept.select { |r| r[:id].to_s.start_with?('g') }
      expect(gold_left.size).to eq(5)
      expect(kept.size).to be <= 30
      expect(r[:kept]).to eq(kept.size)
      # details truncated
      expect(kept.any? { |r| r[:details].to_s.include?('[compacted]') || r[:details].to_s.bytesize <= 800 }).to be true
    end
  end

  it 'Mistakes.lean! never drops unresolved signatures' do
    with_store_paths do |paths|
      store = {
        open1: {
          signature: 'open1', tool: 'shell', error: 'boom', snippet: 'x' * 300,
          sample_args: 'a' * 400, count: 2, first_seen: Time.now.utc.iso8601,
          last_seen: Time.now.utc.iso8601, sessions: %w[s1 s2 s3 s4],
          resolved: false, fix: nil
        },
        oldres: {
          signature: 'oldres', tool: 'shell', error: 'old', snippet: 's',
          sample_args: 'a', count: 1, first_seen: (Time.now.utc - (40 * 86_400)).iso8601,
          last_seen: (Time.now.utc - (40 * 86_400)).iso8601,
          resolved_at: (Time.now.utc - (40 * 86_400)).iso8601,
          sessions: %w[s9], resolved: true, fix: 'do the thing'
        }
      }
      File.write(paths[:mist], JSON.pretty_generate(store))
      # memory already has fix lesson
      PWN::Memory.remember(key: :mistake_fix_oldres, value: 'AVOID: shell → old — FIX: do the thing', category: :lesson)

      r = PWN::AI::Agent::Mistakes.lean!
      after = PWN::AI::Agent::Mistakes.load
      expect(after.keys.map(&:to_s)).to include('open1')
      expect(after[:open1][:sample_args].to_s.bytesize).to be <= PWN::AI::Agent::Mistakes::SAMPLE_ARGS_MAX
      expect(Array(after[:open1][:sessions]).size).to be <= PWN::AI::Agent::Mistakes::SESSIONS_KEEP
      expect(r[:unresolved]).to eq(1)
    end
  end

  it 'Sessions.lean! pins gold session ids and deletes unreferenced stubs' do
    with_store_paths do |paths|
      gold_id = '20260101_000000_gold0001'
      stub_id = '20260101_000000_stub0001'
      old_id = '20260101_000000_old00001'

      File.write(File.join(paths[:sess], "#{gold_id}.jsonl"), "#{JSON.generate(role: 'user', content: 'do gold work here', timestamp: Time.now.utc.iso8601)}\n")
      File.write(File.join(paths[:sess], "#{stub_id}.jsonl"), "#{JSON.generate(role: 'system', content: 'Session started', timestamp: Time.now.utc.iso8601)}\n")
      File.write(File.join(paths[:sess], "#{old_id}.jsonl"), "#{JSON.generate(role: 'user', content: 'old stuff session', timestamp: (Time.now.utc - (60 * 86_400)).iso8601)}\n")
      # age the old/stub mtimes
      old_t = Time.now - (60 * 86_400)
      File.utime(old_t, old_t, File.join(paths[:sess], "#{old_id}.jsonl"))
      File.utime(old_t, old_t, File.join(paths[:sess], "#{stub_id}.jsonl"))

      gold_row = {
        id: '1', task: 't', success: true, score: 0.95, session_id: gold_id,
        tags: [], details: 'ok', timestamp: Time.now.utc.iso8601
      }
      File.write(paths[:learn], "#{JSON.generate(gold_row)}\n")
      File.write(paths[:mist], '{}')

      r = PWN::Sessions.lean!(retain_days: 30, hot_days: 14, max_files: 400)
      expect(File.exist?(File.join(paths[:sess], "#{gold_id}.jsonl"))).to be true
      expect(File.exist?(File.join(paths[:sess], "#{stub_id}.jsonl"))).to be false
      expect(File.exist?(File.join(paths[:sess], "#{old_id}.jsonl"))).to be false
      expect(r[:deleted]).to be >= 2
    end
  end

  it 'Learning.consolidate does not evict protected operator_pref keys' do
    with_store_paths do
      5.times do |i|
        PWN::Memory.remember(key: :"noise_#{i}", value: "noise lesson #{i} " * 5, category: :lesson, importance: 0.1, confidence: 0.2)
      end
      PWN::Memory.remember(key: :operator_pref_keep, value: 'must survive', category: :preference, importance: 1.0, confidence: 1.0)
      r = PWN::AI::Agent::Learning.consolidate(max_entries: 3)
      left = PWN::Memory.load
      expect(left.keys.map(&:to_s)).to include('operator_pref_keep')
      expect(left.size).to be <= 3
      expect(r[:remaining]).to eq(left.size)
    end
  end

  it 'Learning.should_gc_stores? gates on PRUNE_EVERY_N_APPENDS and MAX_OUTCOME_ROWS' do
    with_store_paths do |paths|
      # empty / missing → true (force initial lean opportunity)
      FileUtils.rm_f(paths[:learn])
      expect(PWN::AI::Agent::Learning.send(:should_gc_stores?)).to be true

      n = PWN::AI::Agent::Learning::PRUNE_EVERY_N_APPENDS
      rows = n.times.map do |i|
        {
          id: "r#{i}", task: "t#{i}", success: false, score: 0.2,
          session_id: "s#{i}", tags: %w[auto loop], details: 'd',
          timestamp: Time.now.utc.iso8601
        }
      end
      File.write(paths[:learn], "#{rows.map { |r| JSON.generate(r) }.join("\n")}\n")
      expect(PWN::AI::Agent::Learning.send(:should_gc_stores?)).to be true

      # one under the modulo boundary
      short = rows.first(n - 1)
      File.write(paths[:learn], "#{short.map { |r| JSON.generate(r) }.join("\n")}\n")
      expect(PWN::AI::Agent::Learning.send(:should_gc_stores?)).to be false
    end
  end

  it 'Learning.gc_stores! leans memory+learning+mistakes+sessions and pins current_session_id' do
    with_store_paths do |paths|
      now = Time.now.utc
      cur = '20260101_000000_current1'
      stub_id = '20260101_000000_stub9999'
      File.write(File.join(paths[:sess], "#{cur}.jsonl"), "#{JSON.generate(role: 'user', content: 'active turn', timestamp: now.iso8601)}\n")
      File.write(File.join(paths[:sess], "#{stub_id}.jsonl"), "#{JSON.generate(role: 'system', content: 'Session started', timestamp: now.iso8601)}\n")
      old_t = Time.now - (60 * 86_400)
      File.utime(old_t, old_t, File.join(paths[:sess], "#{stub_id}.jsonl"))

      PWN::Memory.remember(key: :session_tmp_gc, value: 'ephemeral', category: :fact, ttl: 1)
      m = PWN::Memory.load
      m[:session_tmp_gc][:timestamp] = (now - 86_400).iso8601
      PWN::Memory.save(mem: m)

      # modulo-aligned noise outcomes
      n = PWN::AI::Agent::Learning::PRUNE_EVERY_N_APPENDS
      rows = n.times.map do |i|
        {
          id: "n#{i}", task: "noise #{i % 2}", success: false, score: 0.1,
          session_id: "sid_#{i}", tags: %w[auto loop wrong], details: 'z' * 50,
          timestamp: (now - ((50 + i) * 86_400)).iso8601
        }
      end
      File.write(paths[:learn], "#{rows.map { |r| JSON.generate(r) }.join("\n")}\n")
      File.write(paths[:mist], JSON.pretty_generate({}))

      res = PWN::AI::Agent::Learning.gc_stores!(current_session_id: cur)
      expect(res).to include(:memory, :learning, :mistakes, :sessions)
      expect(File.exist?(File.join(paths[:sess], "#{cur}.jsonl"))).to be true
      expect(File.exist?(File.join(paths[:sess], "#{stub_id}.jsonl"))).to be false
      left_mem = PWN::Memory.load
      expect(left_mem.keys.map(&:to_s)).not_to include('session_tmp_gc')
    end
  end

  it 'auto_introspect runs :lean_gc via gc_stores! when should_gc_stores?' do
    with_store_paths do |paths|
      # Enable auto_introspect for this process
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      prev = PWN::Env[:ai][:agent][:auto_introspect]
      PWN::Env[:ai][:agent][:auto_introspect] = true

      n = PWN::AI::Agent::Learning::PRUNE_EVERY_N_APPENDS
      now = Time.now.utc
      # Leave learning at n-1 so note_outcome append hits modulo n and should_gc fires
      rows = (n - 1).times.map do |i|
        {
          id: "pre#{i}", task: "pre #{i}", success: true, score: 0.9,
          session_id: "sid_pre_#{i}", tags: %w[auto loop solved], details: 'ok',
          timestamp: now.iso8601
        }
      end
      File.write(paths[:learn], "#{rows.map { |r| JSON.generate(r) }.join("\n")}\n")
      File.write(paths[:mist], '{}')
      FileUtils.mkdir_p(paths[:sess])

      called = []
      allow(PWN::AI::Agent::Learning).to receive(:gc_stores!).and_wrap_original do |m, **opts|
        called << opts
        m.call(**opts)
      end
      # Avoid LLM/slow stages
      allow(PWN::AI::Agent::Reward).to receive(:judge).and_return(
        { score: 0.8, success: true, verdict: :solved, rationale: 'ok', confidence: 0.7 }
      )
      allow(PWN::AI::Agent::Reward).to receive(:prm)
      allow(PWN::AI::Agent::Reward).to receive(:sentinel)
      allow(PWN::AI::Agent::Curriculum).to receive(:critic).and_return(verdict: :pass, source: :test)
      allow(PWN::AI::Agent::Learning).to receive(:reflect)
      allow(PWN::AI::Agent::Extrospection).to receive(:auto_extrospect) if defined?(PWN::AI::Agent::Extrospection)

      sid = '20260101_000000_introspect'
      File.write(File.join(paths[:sess], "#{sid}.jsonl"), "#{JSON.generate(role: 'user', content: 'hi', timestamp: now.iso8601)}\n")

      out = PWN::AI::Agent::Learning.auto_introspect(
        session_id: sid,
        request: 'keep stores lean please',
        final: 'done lean'
      )
      expect(out).to be_a(Hash)
      expect(Array(out[:stages_run])).to include(:lean_gc)
      expect(called).not_to be_empty
      expect(called.last[:current_session_id]).to eq(sid)
    ensure
      PWN::Env[:ai][:agent][:auto_introspect] = prev if defined?(prev)
    end
  end
end
