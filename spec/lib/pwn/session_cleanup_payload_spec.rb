# frozen_string_literal: true

require 'spec_helper'
require File.expand_path('../../../etc/default_cron/session_cleanup', __dir__)

RSpec.describe PWN::SessionCleanup do
  include_context 'pwn tmp sandbox'

  let(:id) { '20200101_010203_abcdef12' }
  let(:title) { "pwn-ai session #{id}" }
  let(:path) { File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl") }
  let(:meta_path) { path.sub('.jsonl', '.meta.json') }

  before do
    allow(Dir).to receive(:home).and_return(File.join(@tmp, 'home'))
    FileUtils.mkdir_p(File.join(Dir.home, '.pwn'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(Dir.home, '.pwn', 'learning.jsonl'))
    PWN::Sessions.create(id: id)
  end

  def metadata(value)
    File.write(meta_path, JSON.generate({ id: id, title: title, source: 'pwn-ai' }.merge(value)))
  end

  describe 'reader-based historical retention' do
    it 'keeps incomplete provenance records and reusable swarm associations, including retired registry names' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      root = File.join(Dir.home, '.pwn')
      swarm = PWN::AI::Agent::Swarm
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(root, 'swarm'))
      swarm_id = swarm.create[:swarm_id]
      swarm.spawn(name: 'fixture', role: 'fixture', swarm_id: swarm_id)
      mapping = File.join(root, 'swarm', swarm_id, 'personas.json')
      File.write(mapping, JSON.generate(fixture: id))
      swarm.retire(name: 'fixture', swarm_id: swarm_id, local: true)
      # Retire edits only agents.yml: persona_session still intentionally reuses
      # this mapping for an explicit persona or a later respawn. Age is not exit.
      stores = {
        'mistakes.json' => { incomplete: { sessions: [id] } },
        'memory.json' => { "reflect_#{id}_abcdef12" => { category: 'lesson' } },
        'extrospection.json' => { observations: [{ source: 'auto_extrospect', tags: ['drift', id] }] },
        'curriculum/log.jsonl' => { event: 'practice', data: [{ runs: [{ session_id: id }] }] }
      }
      stores.each do |name, row|
        FileUtils.mkdir_p(File.dirname(File.join(root, name)))
        File.write(File.join(root, name), JSON.generate(row))
      end
      expected = stores.keys.map { |name| File.join(root, name) } + [mapping]
      expect(PWN::Sessions.dependency_index[:dependencies][id]).to match_array(expected)
      expect(described_class.run(dry_run: false)[:deleted_ids]).to be_empty
      expect(File.exist?(path)).to be(true)
      expect(swarm.send(:persona_session, swarm_id: swarm_id, name: 'fixture')).to eq(id)
    end

    it 'preserves reflection values, drift observations and practice results without retaining their provenance transcripts' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      root = File.join(Dir.home, '.pwn')
      stub_const('PWN::Memory::MEMORY_FILE', File.join(root, 'memory.json'))
      stub_const('PWN::AI::Agent::Extrospection::EXTRO_FILE', File.join(root, 'extrospection.json'))
      stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', File.join(root, 'curriculum'))
      PWN::Memory.remember(key: "reflect_#{id}_abcdef12", value: 'Use verified results café', category: :lesson, source: :reflect)
      PWN::AI::Agent::Extrospection.observe(source: 'auto_extrospect', category: :env, data: 'Host changed café', tags: ['drift', id])
      run = { session_id: id, prompt: 'fixture', final: nil, trace: nil, score: nil, verdict: 'unknown', training_score: nil }
      PWN::AI::Agent::Curriculum.send(:log, event: :practice, data: [{ signature: 'fixture', tool: 'shell', prompts: ['fixture'], resolved: false, runs: [run] }])
      stores = %w[memory.json extrospection.json curriculum/log.jsonl].to_h { |name| [File.join(root, name), File.binread(File.join(root, name))] }
      expect(PWN::Sessions.dependency_index[:dependencies].fetch(id, [])).to be_empty
      expect(described_class.run(dry_run: false)[:deleted_ids]).to include(id)
      stores.each { |file, bytes| expect(File.binread(file)).to eq(bytes) }
      expect(PWN::Memory.recall(query: "reflect_#{id}_abcdef12", include_session: false).values.first[:value]).to eq('Use verified results café')
      expect(PWN::AI::Agent::Extrospection.observations.first[:data]).to eq('Host changed café')
    end

    it 'removes transcripts without altering self-contained mistake history or its readers' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      store = File.join(Dir.home, '.pwn', 'mistakes.json')
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', store)
      mistake = PWN::AI::Agent::Mistakes.record(tool: 'fixture', error: 'Unicode failure café', session_id: id)
      PWN::AI::Agent::Mistakes.record(tool: 'unrelated', error: 'unrelated retained failure', session_id: '20200101_010203_abcdef99')
      bytes = File.binread(store)
      expect(PWN::Sessions.dependency_index[:dependencies].fetch(id, [])).not_to include(store)
      expect(PWN::Sessions.protected_session_ids(hot_days: 0)).not_to include(id)
      expect(described_class.run(dry_run: false, current_session_id: id)[:deleted_ids]).to be_empty
      lease = PWN::Sessions.activate(session_id: id)
      begin
        expect(described_class.run(dry_run: false)[:deleted_ids]).to be_empty
        expect(File.exist?(path)).to be(true)
      ensure
        PWN::Sessions.deactivate(lease: lease)
      end
      result = described_class.run(dry_run: false)
      expect(result[:deleted_ids]).to include(id)
      expect(File.exist?(path)).to be(false)
      expect(File.binread(store)).to eq(bytes)
      expect(PWN::AI::Agent::Mistakes.for_tool(tool: 'fixture').first).to eq(mistake)
    end
  end

  describe 'offline storage layout' do
    it 'preserves externally anchored metadata and legacy trace paths rather than breaking evidence' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      PWN::SessionTrace.append(session_id: id, event: 'request', data: 'fixture')
      trace = File.join(PWN::Sessions.sessions_dir, id, 'trace.jsonl')
      File.write(File.join(Dir.home, '.pwn', 'findings.jsonl'), JSON.generate(session_id: id, evidence_paths: [meta_path, trace]))
      result = described_class.reorganize(dry_run: false, writers_stopped: true)
      expect(File.file?(meta_path)).to be(true)
      expect(File.file?(trace)).to be(true)
      expect(result[:retained_support]).to include(meta_path, trace)
      expect(PWN::SessionTrace.read(session_id: id).length).to eq(1)
    end

    it 'requires stopped writers and preserves transcripts, metadata and lock inode through migration' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      lock_path = PWN::Sessions.support_path(kind: :lease, session_id: id)
      inode = File.stat(lock_path).ino
      bytes = File.binread(path)
      lease = PWN::Sessions.activate(session_id: id)
      expect { described_class.reorganize(dry_run: false, writers_stopped: true) }.to raise_error(IOError, /active/)
      PWN::Sessions.deactivate(lease: lease)
      expect { described_class.reorganize(dry_run: false) }.to raise_error(ArgumentError, /stopped/)
      result = described_class.reorganize(dry_run: false, writers_stopped: true)
      expect(result[:state]).to eq('committed')
      expect(File.binread(path)).to eq(bytes)
      expect(File.stat(PWN::Sessions.support_path(kind: :lease, session_id: id)).ino).to eq(inode)
      expect(File.exist?(meta_path)).to be(false)
      expect(PWN::Sessions.metadata(session_id: id)[:title]).to eq(title)
      expect(PWN::Sessions.dependency_index[:errors]).to be_empty
      lease = PWN::Sessions.activate(session_id: id)
      expect { described_class.reorganize(dry_run: false, writers_stopped: true) }.to raise_error(IOError, /active/)
      PWN::Sessions.deactivate(lease: lease)
      expect(described_class.run(dry_run: false)[:deleted_ids]).to eq([id])
    ensure
      PWN::Sessions.deactivate(lease: lease)
    end
  end

  describe 'maintenance writer ownership' do
    it 'admits only one maintenance writer across default and approved entry points' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      entered = Queue.new
      release = Queue.new
      allow(PWN::AI::Agent::Learning).to receive(:migrate_evidence).and_wrap_original do |method, **options|
        unless options[:dry_run]
          entered << true
          release.pop
        end
        method.call(**options)
      end
      worker = Thread.new { described_class.maintain }
      Timeout.timeout(2) { entered.pop }
      expect { described_class.run(dry_run: false, approved_candidates: {}) }.to raise_error(IOError, /maintenance already running/)
      read, write = IO.pipe
      child = fork do
        read.close
        begin
          described_class.run(dry_run: false, approved_candidates: {})
          write.write('unexpected writer')
        rescue IOError => e
          write.write(e.message)
        ensure
          write.close
          exit! 0
        end
      end
      write.close
      expect(Timeout.timeout(2) { read.read }).to include('maintenance already running')
      Process.wait(child)
      read.close
      expect(described_class.maintain(dry_run: true)[:dry_run]).to be(true)
      release << true
      expect(worker.join(5)).to eq(worker)
      expect(worker.value[:deleted_ids]).to eq([id])
    ensure
      release << true if release
      worker&.join(5)
    end

    it 'does not wait on a title provider and retains its active session lease' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      PWN::Sessions.append(session_id: id, role: 'user', content: 'Fixture title topic')
      other = PWN::Sessions.create[:id]
      entered = Queue.new
      release = Queue.new
      allow(PWN::AI::Router).to receive(:summarize) do
        entered << true
        release.pop
        JSON.generate(title: 'Fixture topic summary', summary: 'Offline fixture summary')
      end
      worker = Thread.new { PWN::Sessions.refresh_title(session_id: id) }
      Timeout.timeout(2) { entered.pop }
      result = Timeout.timeout(3) { described_class.maintain }
      expect(result[:deleted_ids]).to eq([other])
      expect(result[:records].find { |row| row[:id] == id }[:skip]).to eq(:active)
      release << true
      expect(worker.join(2)).to eq(worker)
      expect(PWN::Sessions.title_status(session_id: id)[:is_summarized]).to be(true)
    ensure
      release << true if release
      worker&.join(2)
    end
  end
end

RSpec.describe PWN::SessionCleanup do
  include_context 'pwn tmp sandbox'

  let(:id) { '20200101_010203_abcdef12' }
  let(:title) { "pwn-ai session #{id}" }
  let(:path) { File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl") }
  let(:meta_path) { path.sub('.jsonl', '.meta.json') }

  before do
    allow(Dir).to receive(:home).and_return(File.join(@tmp, 'home'))
    FileUtils.mkdir_p(File.join(Dir.home, '.pwn'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(Dir.home, '.pwn', 'learning.jsonl'))
    PWN::Sessions.create(id: id)
  end

  def metadata(value)
    File.write(meta_path, JSON.generate({ id: id, title: title, source: 'pwn-ai' }.merge(value)))
  end

  it 'runs evidence preservation and deletion through the default maintenance path idempotently' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    PWN::Sessions.append(session_id: id, role: 'user', content: 'offline evidence fixture café')
    PWN::Sessions.append(session_id: id, role: 'tool', content: 'verified tool observation 日本語')
    PWN::Sessions.append(session_id: id, role: 'assistant', content: 'fixture final')
    mistakes = File.join(Dir.home, '.pwn', 'mistakes.json')
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', mistakes)
    PWN::AI::Agent::Mistakes.record(tool: 'fixture', error: 'fixture failure', session_id: id)
    mistake_bytes = File.binread(mistakes)
    File.write(PWN::AI::Agent::Learning::LEARNING_FILE, "#{JSON.generate(session_id: id, outcome: 'fixture')}\n")
    original = PWN::Sessions.load(session_id: id)
    plan = described_class.maintain(dry_run: true)
    expect(plan[:evidence_migration][:migratable_sessions]).to eq(1)
    expect(File).to exist(path)
    result = described_class.maintain
    expect(result[:deleted_ids]).to eq([id])
    expect(PWN::Sessions.load(session_id: id)).to eq(original)
    expect(File.binread(mistakes)).to eq(mistake_bytes)
    row = JSON.parse(File.read(PWN::AI::Agent::Learning::LEARNING_FILE), symbolize_names: true)
    expect(PWN::AI::Agent::Learning.evidence_complete?(row: row)).to be(true)
    evidence = File.join(Dir.home, '.pwn', 'learning', 'evidence', "#{row[:evidence_ref][:sha256]}.json")
    expect(Digest::SHA256.file(evidence).hexdigest).to eq(row[:evidence_ref][:sha256])
    PWN::AI::Agent::Reward.send(:annotate_session, session_id: id, rewards: [1])
    expect(PWN::Sessions.load(session_id: id).find { |entry| entry[:role] == 'tool' }[:step_reward]).to eq(1)
    expect(Digest::SHA256.file(evidence).hexdigest).to eq(row[:evidence_ref][:sha256])
    expect(PWN::Sessions.catalog[:sessions]).to eq([])
    expect(described_class.maintain[:deleted_ids]).to eq([])
    expect(result[:maintenance_ledger]).to be_a(String)
    expect(JSON.parse(File.read(result[:maintenance_ledger]))['state']).to eq('committed')
  end

  it 'validates versioned request checkpoints as provenance rather than transcript dependencies' do
    runtime = PWN::AI::Agent::RequestRuntime.new(request: 'offline fixture', session_id: id, request_id: 'fixture-request')
    index = PWN::Sessions.dependency_index
    expect(index[:errors]).to eq([])
    expect(index[:dependencies].fetch(id, [])).not_to include(runtime.checkpoint_path)
    expect(index[:provenance][id]).to eq([runtime.checkpoint_path])
    data = JSON.parse(File.read(runtime.checkpoint_path))
    data['version'] = 99
    File.write(runtime.checkpoint_path, JSON.generate(data))
    index = PWN::Sessions.dependency_index
    expect(index[:errors]).to include(runtime.checkpoint_path)
    expect(index[:diagnostics].map { |row| row[:code] }).to include('Unsupported request checkpoint version')
  end

  it 'paginates visible retained sessions and reports global diagnostics only once' do
    ids = [id, '20200101_010203_abcdef13', '20200101_010203_abcdef14']
    ids.drop(1).each { |sid| PWN::Sessions.create(id: sid) }
    File.write(File.join(Dir.home, '.pwn', 'learning.jsonl'), ids.map { |sid| JSON.generate(session_id: sid) }.join("\n"))
    File.write(File.join(Dir.home, '.pwn', 'memory.json'), '{')
    page = PWN::Sessions.catalog(offset: 0, limit: 2)
    expect(page).to include(total: 3, has_more: true)
    expect(page[:sessions].length).to eq(2)
    expect(page[:sessions].flat_map(&:keys)).not_to include(:unresolved_dependency_stores, :dependency_errors)
    expect(page[:unresolved_dependency_stores].length).to eq(1)
    last = PWN::Sessions.catalog(offset: 2, limit: 2)
    expect(last).to include(total: 3, has_more: false)
    expect((page[:sessions] + last[:sessions]).map { |row| row[:id] }).to match_array(ids)
  end

  it 'shares default command, seeded cron and legacy cron maintenance behavior' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    PWN::Sessions.append(session_id: id, role: 'user', content: 'retained café 日本語 🔒 fixture')
    File.write(PWN::AI::Agent::Learning::LEARNING_FILE, JSON.generate(session_id: id, task: 'résumé'))
    expect { PWN::Plugins::REPL.pwn_ai_run_sessions(args: ['cleanup']) }.to output(/deleted: 1/).to_stdout
    expect(File).not_to exist(path)
    expect(PWN::Sessions.load(session_id: id)).not_to be_empty
    cron_id = PWN::Sessions.create[:id]
    payload = PWN::Cron::DEFAULT_JOBS.find { |job| job[:name] == 'session_cleanup' }[:ruby]
    allow(PWN::Cron).to receive(:cron_dir).and_return(File.expand_path('../../../etc/default_cron', __dir__))
    expect(eval(payload)[:deleted_ids]).to eq([cron_id]) # rubocop:disable Security/Eval -- execute the exact bundled local job
    legacy_id = PWN::Sessions.create[:id]
    expect(described_class.run(dry_run: false)[:deleted_ids]).to eq([legacy_id])
  end

  it 'does not migrate evidence or delete while legacy ownership is unresolved' do
    allow(described_class).to receive(:legacy_owners).and_return([{ pid: 123, reason: 'legacy_session_ownership_unknown' }])
    expect(PWN::AI::Agent::Learning).to receive(:migrate_evidence).with(dry_run: true).and_call_original
    expect(described_class.maintain[:apply_blocked]).to be(true)
    expect(File).to exist(path)
  end

  %w[memory.json memory.archive.json mistakes.json].each do |store|
    it "remediates only the attributable invalid map entry in #{store}" do
      allow(described_class).to receive(:legacy_owners).and_return([])
      target = File.join(Dir.home, '.pwn', store)
      key = store == 'mistakes.json' ? 'bad' : "reflect_#{id}_abcdef12"
      invalid = store == 'mistakes.json' ? { sessions: [id, 123] } : 123
      valid = store == 'mistakes.json' ? { sessions: [], description: 'résumé 日本語 🔒' } : { value: 'keep résumé 日本語 🔒', category: 'fact' }
      File.write(target, JSON.generate(key => invalid, 'unrelated' => valid))
      expect(PWN::Sessions.dependency_index[:session_errors].keys).to eq([id])
      expect(PWN::Sessions.list.map { |row| row[:id] }).not_to include(id)
      lease = PWN::Sessions.activate(session_id: id)
      expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
      PWN::Sessions.deactivate(lease: lease)
      result = described_class.sweep(dry_run: false)
      expect(result[:deleted_ids]).to eq([id])
      expect(JSON.parse(File.read(target))).to eq('unrelated' => JSON.parse(JSON.generate(valid)))
      removal = result[:dependency_removals].first
      expect(removal[:state]).to eq('committed')
      expect(JSON.parse(File.read(removal[:backup]))).to have_key(key)
    ensure
      PWN::Sessions.deactivate(lease: lease)
    end
  end

  it 'rejects stale map approvals and never removes a refreshed entry' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    target = File.join(Dir.home, '.pwn', 'memory.json')
    key = "reflect_#{id}_abcdef12"
    File.write(target, JSON.generate(key => 123))
    plan = described_class.sweep
    approvals = plan[:records].to_h { |row| [row[:id], row.slice(:files, :dependency_records)] }
    File.write(target, JSON.generate(key => { value: 'refreshed' }))
    expect(described_class.sweep(dry_run: false, approved_candidates: approvals)[:deleted_ids]).to eq([])
    expect(JSON.parse(File.read(target))[key]['value']).to eq('refreshed')
  end

  it 'protects a session while a cooperative writer can introduce a new dependency' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    target = File.join(Dir.home, '.pwn', 'memory.json')
    PWN::Memory.transaction(path: target) do
      expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
      expect(File).to exist(path)
    end
  end

  it 'does not race a cooperating map writer' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    target = File.join(Dir.home, '.pwn', 'memory.json')
    File.write(target, JSON.generate("reflect_#{id}_abcdef12" => 123))
    PWN::Memory.transaction(path: target) do
      expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
    end
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([id])
  end

  it 'protects only a held session lease and releases it while the owner remains alive' do
    proc_root = File.join(@tmp, 'processes')
    FileUtils.mkdir_p(proc_root)
    other = PWN::Sessions.create(id: '20200101_010203_abcdef13')[:id]
    ready_r, ready_w = IO.pipe
    stop_r, stop_w = IO.pipe
    pid = fork do
      $0 = 'pwn-ai'
      ready_r.close
      stop_w.close
      lease = PWN::Sessions.activate(session_id: id)
      ready_w.puts('ready')
      stop_r.gets
      PWN::Sessions.deactivate(lease: lease)
      ready_w.puts('released')
      stop_r.gets
      exit! 0
    end
    ready_w.close
    stop_r.close
    File.symlink("/proc/#{pid}", File.join(proc_root, pid.to_s))
    expect(ready_r.wait_readable(5)).not_to be_nil
    expect(ready_r.gets).to eq("ready\n")
    expect(described_class.legacy_owners(proc_root)).to eq([])
    result = described_class.sweep(dry_run: false, proc_root: proc_root)
    expect(result[:deleted_ids]).to eq([other])
    expect(result[:records].find { |row| row[:id] == id }[:skip]).to eq(:active)
    stop_w.puts('release')
    expect(ready_r.gets).to eq("released\n")
    expect(described_class.sweep(dry_run: false, proc_root: proc_root)[:deleted_ids]).to eq([id])
  ensure
    stop_w&.close
    ready_r&.close
    Process.wait(pid) if pid
  end

  it 'recognizes inherited upgraded-worker descriptors without pinning unrelated sessions' do
    proc_root = File.join(@tmp, 'processes')
    FileUtils.mkdir_p(proc_root)
    ready_r, ready_w = IO.pipe
    stop_r, stop_w = IO.pipe
    lease = PWN::Sessions.activate(session_id: id)
    pid = fork do
      $0 = 'pwn-ai'
      ready_r.close
      stop_w.close
      ready_w.puts('ready')
      stop_r.gets
      exit! 0
    end
    ready_w.close
    stop_r.close
    File.symlink("/proc/#{pid}", File.join(proc_root, pid.to_s))
    expect(ready_r.wait_readable(5)).not_to be_nil
    expect(ready_r.gets).to eq("ready\n")
    PWN::Sessions.deactivate(lease: lease)
    expect(described_class.legacy_owners(proc_root)).to eq([])
    expect(PWN::Sessions.active?(session_id: id)).to be(true)
    other = PWN::Sessions.create(id: '20200101_010203_abcdef13')[:id]
    expect(described_class.sweep(dry_run: false, proc_root: proc_root)[:deleted_ids]).to eq([other])
  ensure
    PWN::Sessions.deactivate(lease: lease)
    stop_w&.close
    ready_r&.close
    Process.wait(pid) if pid
  end

  it 'releases a crashed owner without trusting stale contents or a reused PID' do
    ready_r, ready_w = IO.pipe
    stop_r, stop_w = IO.pipe
    pid = fork do
      ready_r.close
      stop_w.close
      lease = PWN::Sessions.activate(session_id: id)
      ready_w.puts(lease.fileno)
      stop_r.gets
      exit! 19
    end
    ready_w.close
    stop_r.close
    expect(ready_r.wait_readable(5)).not_to be_nil
    expect(ready_r.gets).not_to be_nil
    expect(PWN::Sessions.active?(session_id: id)).to be(true)
    stop_w.puts('crash without ensure')
    expect(Process.wait2(pid).last.exitstatus).to eq(19)
    pid = nil
    File.write(File.join(PWN::Sessions.sessions_dir, ".#{id}.cleanup.lock"), JSON.generate(pid: Process.pid, start: 'wrong-start'))
    expect(PWN::Sessions.active?(session_id: id)).to be(false)
    lease = PWN::Sessions.activate(session_id: id)
    expect(PWN::Sessions.active?(session_id: id)).to be(true)
  ensure
    PWN::Sessions.deactivate(lease: lease)
    stop_w&.close
    ready_r&.close
    Process.wait(pid) if pid
  end

  it 'rejects activation during deletion and does not recreate a deleted session' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    allow(described_class).to receive(:backup).and_wrap_original do |original, *args|
      expect { PWN::Sessions.activate(session_id: id) }.to raise_error(IOError, /being removed/)
      child = fork do
        PWN::Sessions.activate(session_id: id)
        exit! 1
      rescue IOError
        exit! 23
      end
      expect(Process.wait2(child).last.exitstatus).to eq(23)
      original.call(*args)
    end
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([id])
    expect { PWN::Sessions.activate(session_id: id) }.to raise_error(IOError, /not found/)
    expect { PWN::Sessions.append(session_id: id, content: 'late writer') }.to raise_error(/not found/)
    expect(File).not_to exist(path)
  end

  it 'protects nested independent owners even from force deletion' do
    first = PWN::Sessions.activate(session_id: id)
    second = PWN::Sessions.activate(session_id: id)
    PWN::Sessions.deactivate(lease: first)
    expect(PWN::Sessions.active?(session_id: id)).to be(true)
    expect { PWN::Sessions.delete(session_id: id, force: true) }.to raise_error(/active/)
    PWN::Sessions.deactivate(lease: second)
    expect(PWN::Sessions.active?(session_id: id)).to be(false)
  ensure
    PWN::Sessions.deactivate(lease: first)
    PWN::Sessions.deactivate(lease: second)
  end

  it 'holds an independent lease through nested Loop workers and exception unwinding' do
    worker = PWN::AI::Agent::Loop
    other = PWN::Sessions.create(id: '20200101_010203_abcdef13')[:id]
    allow(worker).to receive(:run_turn) do |options|
      expect(PWN::Sessions.active?(session_id: id)).to be(true)
      if options[:nested]
        expect(PWN::Sessions.active?(session_id: other)).to be(true)
        raise IOError, 'worker fixture failure'
      end
      worker.run(session_id: other, request: 'child', nested: true)
    end
    expect { worker.run(session_id: id, request: 'parent') }.to raise_error(IOError, 'worker fixture failure')
    expect(PWN::Sessions.active?(session_id: id)).to be(false)
    expect(PWN::Sessions.active?(session_id: other)).to be(false)
  end

  it 'keeps self-play sessions leased through grading and releases after the trial' do
    seen = nil
    allow(PWN::AI::Agent::Loop).to receive(:run) do |options|
      seen = options[:session_id]
      expect(PWN::Sessions.active?(session_id: seen)).to be(true)
      'fixture response'
    end
    allow(PWN::AI::Agent::Reward).to receive(:judge) do
      expect(PWN::Sessions.active?(session_id: seen)).to be(true)
      { score: 0.5 }
    end
    PWN::AI::Agent::Curriculum.send(:self_play, prompt: 'fixture', tag: 'test')
    expect(seen).not_to be_nil
    expect(PWN::Sessions.active?(session_id: seen)).to be(false)
  end
end

RSpec.describe PWN::SessionCleanup do
  include_context 'pwn tmp sandbox'

  let(:id) { '20200101_010203_abcdef12' }
  let(:title) { "pwn-ai session #{id}" }
  let(:path) { File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl") }
  let(:meta_path) { path.sub('.jsonl', '.meta.json') }

  before do
    allow(Dir).to receive(:home).and_return(File.join(@tmp, 'home'))
    FileUtils.mkdir_p(File.join(Dir.home, '.pwn'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(Dir.home, '.pwn', 'learning.jsonl'))
    PWN::Sessions.create(id: id)
  end

  def metadata(value)
    File.write(meta_path, JSON.generate({ id: id, title: title, source: 'pwn-ai' }.merge(value)))
  end

  it 'hides unretained sessions without attributing global store errors to them' do
    File.write(File.join(Dir.home, '.pwn', 'memory.json'), '{')
    expect(PWN::Sessions.list).to eq([])
    row = PWN::Sessions.list(include_hidden: true).find { |session| session[:id] == id }
    expect(row[:dependency_errors]).to eq([])
    expect(row).not_to have_key(:unresolved_dependency_stores)
    expect(PWN::Sessions.catalog[:unresolved_dependency_stores]).to eq([File.join(Dir.home, '.pwn', 'memory.json')])
  end

  it 'attributes broken learning evidence to its owner and preserves mixed valid rows' do
    other = PWN::Sessions.create(id: '20200101_010203_abcdef13')[:id]
    store = File.join(Dir.home, '.pwn', 'learning.jsonl')
    good = "#{JSON.generate(session_id: other, score: 1)}\n"
    File.write(store, "#{JSON.generate(session_id: id, evidence_ref: {})}\n#{good}")
    index = PWN::Sessions.dependency_index
    expect(index[:errors]).to eq([])
    expect(index[:session_errors]).to eq(id => [store])
    expect(index[:dependencies]).to eq(other => [store])
    expect(PWN::Sessions.list.map { |row| row[:id] }).to eq([other])
    allow(described_class).to receive(:legacy_owners).and_return([])
    result = described_class.sweep(dry_run: false)
    expect(result[:deleted_ids]).to eq([id])
    expect(File.binread(store)).to eq(good)
    expect(File).not_to exist(path)
    expect(result[:dependency_removals].map { |row| row[:path] }).to eq([store])
    expect(File.binread(result[:dependency_removals].first[:backup])).to include(id, other)
  end

  it 'uses a shared dependency snapshot for a dry-run inventory' do
    4.times { |index| PWN::Sessions.create(id: "20200101_010203_abcdef2#{index}") }
    allow(described_class).to receive(:legacy_owners).and_return([])
    expect(PWN::Sessions).to receive(:dependency_index).at_most(3).times.and_call_original
    expect(described_class.sweep[:candidate_ids].length).to eq(5)
  end

  it 'keeps active erroneous sessions physically intact but hidden' do
    store = File.join(Dir.home, '.pwn', 'learning.jsonl')
    bytes = JSON.generate(session_id: id, evidence_ref: {})
    File.write(store, bytes)
    lease = PWN::Sessions.activate(session_id: id)
    allow(described_class).to receive(:legacy_owners).and_return([])
    expect(PWN::Sessions.list).to eq([])
    result = described_class.sweep(dry_run: false)
    expect(result[:deleted_ids]).to eq([])
    expect(result[:skipped][:active]).to eq(1)
    expect(File.binread(store)).to eq(bytes)
    expect(File).to exist(path)
  ensure
    PWN::Sessions.deactivate(lease: lease)
  end

  it 'preserves valid map entries while reporting attributable and unresolved remediation separately' do
    other = PWN::Sessions.create(id: '20200101_010203_abcdef13')[:id]
    store = File.join(Dir.home, '.pwn', 'mistakes.json')
    bytes = JSON.generate(bad: { sessions: [id], verified_sessions: {} }, good: { sessions: [other] })
    File.write(store, bytes)
    index = PWN::Sessions.dependency_index
    expect(index[:session_errors]).to eq(id => [store])
    expect(index[:dependencies]).to eq(other => [store])
    expect(PWN::Sessions.list.map { |row| row[:id] }).to eq([other])
    allow(described_class).to receive(:legacy_owners).and_return([])
    result = described_class.sweep(dry_run: false)
    expect(result[:deleted_ids]).to eq([id])
    expect(JSON.parse(File.binread(store))).to eq('good' => { 'sessions' => [other] })
    expect(File.binread(result[:dependency_removals].first[:backup])).to eq(bytes)
  end

  it 'never guesses ownership for corrupt global bytes and keeps valid summaries visible' do
    metadata(title: 'Valid summary title', title_source: 'summary', summary: 'Conversation summary', summary_turns: 2)
    store = File.join(Dir.home, '.pwn', 'memory.json')
    File.write(store, '{')
    expect(PWN::Sessions.list.map { |row| row[:id] }).to eq([id])
    expect(PWN::Sessions.list.first[:dependency_errors]).to eq([])
    allow(described_class).to receive(:legacy_owners).and_return([])
    result = described_class.sweep(dry_run: false)
    expect(result[:unresolved_store_remediation]).to eq([store])
    expect(result[:deleted_ids]).to eq([])
    expect(File.read(store)).to eq('{')
  end

  it 'rechecks invalid evidence after backup and does not remove repaired records' do
    store = File.join(Dir.home, '.pwn', 'learning.jsonl')
    File.write(store, JSON.generate(session_id: id, evidence_ref: {}))
    repaired = JSON.generate(session_id: id, score: 1)
    allow(described_class).to receive(:legacy_owners).and_return([])
    allow(described_class).to receive(:backup).and_wrap_original do |original, *args|
      original.call(*args)
      File.write(store, repaired)
    end
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
    expect(File.read(store)).to eq(repaired)
    expect(File).to exist(path)
  end

  it 'keeps referenced placeholders visible with the exact dependency paths' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    dependency = File.join(Dir.home, '.pwn', 'jobs', '123456abcdef.json')
    FileUtils.mkdir_p(File.dirname(dependency))
    File.write(dependency, JSON.generate(session_id: id))
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
    row = PWN::Sessions.list.find { |session| session[:id] == id }
    expect(row[:dependencies]).to eq([dependency])
    expect(PWN::Sessions.resolve(identifier: id)).to eq(id)
  end

  it 'pins engagement memory and embeddings by their real session-scoped paths' do
    memory = File.join(Dir.home, '.pwn', 'artifacts', id, 'engagement-memory.json')
    database = File.join(Dir.home, '.pwn', 'embeddings', "#{id}.db")
    [memory, database].each { |file| FileUtils.mkdir_p(File.dirname(file)) }
    File.write(memory, '{}')
    File.write(database, 'opaque database bytes')
    expect(PWN::Sessions.list.find { |session| session[:id] == id }[:dependencies]).to match_array([memory, database])
  end

  it 'lists an explicit empty dependency array for unreferenced sessions' do
    expect(PWN::Sessions.list(include_hidden: true).find { |session| session[:id] == id }[:dependencies]).to eq([])
  end

  it 'fails closed without reading through a symlinked artifact parent' do
    target = File.join(@tmp, 'private-fixture')
    FileUtils.mkdir_p(target)
    source = File.join(target, 'engagement-memory.json')
    File.write(source, '{}')
    root = File.join(Dir.home, '.pwn', 'artifacts')
    FileUtils.mkdir_p(root)
    File.symlink(target, File.join(root, id))
    expect(PWN::Sessions.dependency_index[:errors]).not_to be_empty
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
  end

  it 'fails closed for malformed run dependency stores' do
    dependency = File.join(Dir.home, '.pwn', 'runs', 'fixture', 'state.json')
    FileUtils.mkdir_p(File.dirname(dependency))
    File.write(dependency, '{')
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
    expect(described_class.sweep[:skipped][:unknown_pins]).to eq(1)
  end

  it 'never treats a placeholder as a generated title despite summary markers' do
    metadata(title_source: 'summary', summary: 'A valid conversation summary', summary_turns: 2)
    expect(PWN::Sessions.title_status(session_id: id)).to include(classification: :unnamed, is_summarized: false, title_reason: 'placeholder_not_summary')
    expect(PWN::Sessions.list(include_hidden: true).find { |row| row[:id] == id }[:is_summarized]).to be(false)
  end

  it 'accepts an exact current placeholder with provisional non-summary metadata' do
    metadata(title_source: 'provisional')
    expect(described_class.classify(path, id)).to eq(:unnamed)
    ['pwn-ai', 'pwn-ai 2020-01-01 01:02'].each do |name|
      metadata(title: name, title_source: 'provisional')
      expect(described_class.classify(path, id)).to eq(:unnamed)
    end
  end

  it 'accepts default, empty and legacy timestamp titles without metadata' do
    File.unlink(meta_path)
    ['', 'pwn-ai', title, 'pwn-ai 2020-01-01 01:02'].each do |name|
      File.write(path, "#{JSON.generate(role: 'system', content: "Session started: #{name}")}\n")
      expect(described_class.classify(path, id)).to eq(:unnamed)
    end
  end

  it 'does not infer LLM provenance from arbitrary display titles' do
    ["#{title} notes", "notes #{title}", 'pwn-ai session 20200101_010203_abcdef13', 'pwn-ai work'].each do |name|
      metadata(title: name)
      expect(described_class.classify(path, id)).to eq(:unnamed)
    end
  end

  it 'requires complete summary provenance and rejects unknown metadata without calling it named' do
    [
      { title_source: 'summary' }, { title_source: 'custom' },
      { title_history: [{ title: title, title_source: 'summary' }] }
    ].each do |value|
      metadata(value)
      expect(described_class.classify(path, id)).to eq(:unknown)
    end
  end

  it 'does not treat provisional, manual, historical, persona or alias titles as summarized' do
    [
      { title: 'First request topic', title_source: 'provisional' },
      { title: 'pwn-ai', title_source: 'manual' },
      { title: 'One two three four five six seven', title_source: 'manual' },
      { title: 'Security analyst' }, { summary: 'Old summary without provenance', summary_turns: 2 },
      { title_aliases: ['Human name'] }, { title_history: ['Prior topic'] }
    ].each do |value|
      metadata(value)
      row = PWN::Sessions.list(include_hidden: true).find { |session| session[:id] == id }
      expect(row).to include(is_summarized: false, classification: :unnamed)
      expect(described_class.classify(path, id)).to eq(row[:classification])
    end
    metadata(title_aliases: ['Human name'])
    expect(PWN::Sessions.resolve(identifier: 'Human name')).to eq(id)
  end

  it 'recognizes provenance written by the real title worker without altering history' do
    PWN::Sessions.append(session_id: id, role: 'user', content: 'Repair the console')
    history = File.binread(path)
    summary = 'Overall goals and outcomes. ' * 100
    allow(PWN::AI::Router).to receive(:summarize).with(hash_including(llm: true, session: true)).and_return(JSON.generate(title: 'One two three four five six seven eight', summary: summary))
    PWN::Sessions.refresh_title(session_id: id)
    expect(described_class.classify(path, id)).to eq(:named)
    expect(PWN::Sessions.list.first).to include(title: 'One two three four five six seven', title_source: 'summary', is_summarized: true)
    expect(PWN::Sessions.metadata(session_id: id)[:summary]).to eq(summary)
    expect(File.binread(path)).to eq(history)
  end

  it 'names only a title carrying complete persisted LLM summary evidence' do
    metadata(title: 'One two three four five six seven', title_source: 'summary', summary: 'Overall conversation', summary_turns: 2)
    expect(described_class.classify(path, id)).to eq(:named)
    expect(PWN::Sessions.list.first).to include(title_source: 'summary', is_summarized: true, title_reason: 'llm_summary')
    [nil, '', "\u2003", false].each do |summary|
      metadata(title_source: 'summary', summary: summary, summary_turns: 2)
      expect(described_class.classify(path, id)).to eq(:unknown)
    end
    [nil, 0, -1, '2', false].each do |cursor|
      metadata(title_source: 'summary', summary: 'Overall conversation', summary_turns: cursor)
      expect(described_class.classify(path, id)).to eq(:unknown)
    end
  end

  it 'retains malformed and ambiguous sidecars' do
    [[], { title: '' }, { id: 'other' }, { summary_turns: '0' }, { summary_turns: false }, { summary: false }, { future_field: true }, { title_aliases: nil }].each do |value|
      value.is_a?(Hash) ? metadata(value) : File.write(meta_path, JSON.generate(value))
      expect(described_class.classify(path, id)).to eq(:unknown)
    end
    File.write(meta_path, '{')
    expect(described_class.classify(path, id)).to eq(:unknown)
  end

  it 'retains malformed transcripts but never infers summary from embedded prior names' do
    File.write(path, "{\n")
    expect(described_class.classify(path, id)).to eq(:unknown)
    File.write(path, "#{JSON.generate(role: 'system', content: 'Session started: Named previously')}\n")
    expect(described_class.classify(path, id)).to eq(:unnamed)
  end

  it 'classifies known swarm producer metadata without inventing summary provenance' do
    metadata(source: 'pwn-ai-swarm', title: 'swarm:fixture persona:critic')
    expect(PWN::Sessions.title_status(session_id: id)).to include(classification: :unnamed, title_reason: 'missing_summary_provenance')
    allow(described_class).to receive(:legacy_owners).and_return([])
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([id])
  end

  it 'recognizes native scalar step rewards without accepting unknown reward shapes' do
    original = File.read(path)
    [-1, 0, 1].each do |reward|
      File.write(path, original + "#{JSON.generate(role: 'tool', content: '', step_reward: reward)}\n")
      expect(described_class.classify(path, id)).to eq(:unnamed)
    end
    ['1', { title: 'Named history' }, nil].each do |reward|
      File.write(path, original + "#{JSON.generate(role: 'tool', content: '', step_reward: reward)}\n")
      expect(described_class.classify(path, id)).to eq(:unknown)
    end
  end

  it 'retains transcript summary markers even with an automatic current title' do
    File.open(path, 'a') { |file| file.puts(JSON.generate(role: 'system', content: '', summary: 'previous summary')) }
    expect(described_class.classify(path, id)).to eq(:unknown)
  end

  it 'retains symlinks and noncanonical ids' do
    File.unlink(meta_path)
    File.symlink(path, meta_path)
    expect(described_class.classify(path, id)).to eq(:unknown)
    expect(described_class.classify(path, '../unsafe')).to eq(:unknown)
  end

  it 'dry-runs and applies only to temporary old unpinned fixtures through Sessions.delete' do
    old = Time.utc(2020)
    File.utime(old, old, path)
    allow(described_class).to receive(:legacy_owners).and_return([])
    dry = described_class.sweep
    expect(dry[:candidate_ids]).to include(id)
    expect(dry[:deleted_ids]).to eq([])
    expect(File).to exist(path)
    expect(PWN::Sessions).to receive(:delete).with(session_id: id, current_session_id: nil, force: true, cleanup_lock: an_instance_of(File)).and_call_original
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([id])
    expect(File).not_to exist(path)
    expect(File).not_to exist(meta_path)
  end

  it 'archives and removes hot placeholders without deleting current sessions' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    original = File.binread(path)
    expect(described_class.sweep(dry_run: false, current_session_id: id)[:deleted_ids]).to eq([])
    dry = described_class.sweep
    expect(dry[:candidate_ids]).to eq([id])
    expect(Dir.glob(File.join(Dir.home, '.pwn', 'session_cleanup_archive', '**', '*.jsonl'))).to eq([])
    result = described_class.sweep(dry_run: false)
    expect(result[:deleted_ids]).to eq([id])
    archived = File.join(result[:archive_dir], "#{id}.jsonl")
    expect(File.binread(archived)).to eq(original)
    expect(File.stat(archived).mode & 0o777).to eq(0o600)
    expect(File.stat(result[:archive_dir]).mode & 0o777).to eq(0o700)
    expect(PWN::Sessions.list.map { |row| row[:id] }).not_to include(id)
  end
end

RSpec.describe PWN::SessionCleanup do
  include_context 'pwn tmp sandbox'

  let(:id) { '20200101_010203_abcdef12' }
  let(:path) { File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl") }
  let(:meta_path) { path.sub('.jsonl', '.meta.json') }

  before do
    allow(Dir).to receive(:home).and_return(File.join(@tmp, 'home'))
    FileUtils.mkdir_p(File.join(Dir.home, '.pwn'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(Dir.home, '.pwn', 'learning.jsonl'))
    PWN::Sessions.create(id: id)
  end

  it 'retains current/referenced sessions and defers active processes' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    old = Time.utc(2020)
    File.utime(old, old, path)
    expect(described_class.sweep(dry_run: false, current_session_id: id)[:deleted_ids]).to eq([])
    allow(described_class).to receive(:legacy_owners).and_return([{ pid: 123, reason: 'legacy_session_ownership_unknown' }])
    result = described_class.sweep(dry_run: false)
    expect(result[:skipped][:unknown_legacy_ownership]).to eq(1)
    expect(File).to exist(path)
    allow(described_class).to receive(:legacy_owners).and_return([])
    File.write(File.join(Dir.home, '.pwn', 'learning.jsonl'), JSON.generate(session_id: id))
    expect(described_class.sweep(dry_run: false)[:skipped][:referenced]).to eq(1)
  end

  it 'ignores shell payload mentions while retaining actual PWN executable processes' do
    proc_root = File.join(@tmp, 'proc')
    process_dir = File.join(proc_root, (Process.pid + 1).to_s)
    FileUtils.mkdir_p(process_dir)
    exe = File.join(process_dir, 'exe')
    cmdline = File.join(process_dir, 'cmdline')
    File.symlink('/bin/bash', exe)
    File.binwrite(cmdline, ['/bin/bash', '-c', 'cd /opt/pwn && ruby helper.rb'].join("\0"))
    expect(described_class.legacy_owners(proc_root)).to eq([])
    File.unlink(exe)
    File.symlink('/usr/bin/ruby', exe)
    File.binwrite(cmdline, ['ruby', '-I', '/opt/pwn', 'helper.rb'].join("\0"))
    expect(described_class.legacy_owners(proc_root)).to eq([])
    File.binwrite(cmdline, ['ruby', '-e', 'puts "pwn"'].join("\0"))
    expect(described_class.legacy_owners(proc_root)).to eq([])
    [
      ['ruby', '/usr/local/bin/pwn'],
      ['ruby', '-I', '/opt/pwn/lib', '/usr/local/bin/pwn-ai'],
      ['ruby /usr/local/rvm/gems/ruby-4.0.6@pwn/bin/pwn'],
      ['/usr/local/bin/pwn-ai']
    ].each do |argv|
      File.binwrite(cmdline, argv.join("\0"))
      expect(described_class.legacy_owners(proc_root)).not_to be_empty
    end
  end

  it 'does not require exe access for unrelated non-Ruby processes' do
    proc_root = File.join(@tmp, 'proc')
    process_dir = File.join(proc_root, (Process.pid + 1).to_s)
    FileUtils.mkdir_p(process_dir)
    File.binwrite(File.join(process_dir, 'cmdline'), "chromium\0--type=renderer\0")
    allow(File).to receive(:readlink).with(File.join(process_dir, 'exe')).and_raise(Errno::EACCES)
    expect(described_class.legacy_owners(proc_root)).to eq([])
  end

  it 'fails closed on unknown pin stores and unavailable process inventories' do
    File.write(File.join(Dir.home, '.pwn', 'memory.json'), '{')
    expect(described_class.sweep(dry_run: false)[:skipped][:unknown_pins]).to eq(1)
    expect(described_class.legacy_owners(File.join(@tmp, 'absent'))).not_to be_empty
    expect(File).to exist(path)
  end

  it 'honors real learning gold and mistake references, and rejects corrupt stores' do
    old = Time.utc(2020)
    File.utime(old, old, path)
    allow(described_class).to receive(:legacy_owners).and_return([])
    learning = File.join(Dir.home, '.pwn', 'learning.jsonl')
    mistakes = File.join(Dir.home, '.pwn', 'mistakes.json')
    File.write(learning, "#{JSON.generate(session_id: id, success: true, score: 1)}\n")
    expect(described_class.sweep(dry_run: false)[:skipped][:referenced]).to eq(1)
    File.unlink(learning)
    File.write(mistakes, JSON.generate(issue: { sessions: [id], resolved: false }))
    expect(described_class.sweep(dry_run: false)[:skipped][:referenced]).to eq(1)
    File.write(mistakes, '{')
    expect(described_class.sweep(dry_run: false)[:skipped][:unknown_pins]).to eq(1)
    expect(File).to exist(path)
  end

  it 'retains non-gold learning, old resolved mistakes and durable memory references' do
    old = Time.utc(2020)
    File.utime(old, old, path)
    allow(described_class).to receive(:legacy_owners).and_return([])
    root = File.join(Dir.home, '.pwn')
    {
      'learning.jsonl' => "#{JSON.generate(session_id: id, success: false, score: 0)}\n",
      'mistakes.json' => JSON.generate(issue: { sessions: [id], resolved: true, last_seen: old.iso8601 }),
      'memory.json' => JSON.generate("reflect_#{id}_1234abcd" => { value: 'lesson', source: 'reflect' })
    }.each do |name, data|
      file = File.join(root, name)
      File.write(file, data)
      expect(described_class.sweep(dry_run: false)[:skipped][:referenced]).to eq(1)
      expect(File).to exist(path)
      File.unlink(file)
    end
    File.write(File.join(root, 'memory.json'), '{')
    expect(described_class.sweep(dry_run: false)[:skipped][:unknown_pins]).to eq(1)
    expect(File).to exist(path)
  end

  it 'reclassifies under locks and keeps concurrent titles' do
    old = Time.utc(2020)
    File.utime(old, old, path)
    allow(described_class).to receive(:legacy_owners).and_return([])
    calls = 0
    allow(described_class).to receive(:classify).and_wrap_original do |original, *args|
      calls += 1
      File.write(meta_path, JSON.generate(title: 'Concurrent human title')) if calls == 2
      original.call(*args)
    end
    expect(described_class.sweep(dry_run: false)[:skipped][:changed]).to eq(1)
    expect(File).to exist(path)
  end

  it 'refuses deletion when content changes after the verified backup' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    allow(described_class).to receive(:backup).and_wrap_original do |original, *args|
      original.call(*args)
      File.open(path, 'a') { |file| file.puts(JSON.generate(role: 'user', content: 'concurrent append')) }
    end
    result = described_class.sweep(dry_run: false)
    expect(result[:deleted_ids]).to eq([])
    expect(result[:skipped][:changed]).to eq(1)
    expect(File).to exist(path)
  end

  it 'refuses deletion on an archive failure or newly created evidence reference' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    allow(described_class).to receive(:backup).and_raise(IOError)
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([])
    expect(File).to exist(path)
    allow(described_class).to receive(:backup).and_wrap_original do |original, *args|
      original.call(*args)
      File.write(File.join(Dir.home, '.pwn', 'learning.jsonl'), JSON.generate(session_id: id))
    end
    expect(described_class.sweep(dry_run: false)[:skipped][:changed]).to eq(1)
    expect(File).to exist(path)
  end

  it 'deletes an unreferenced unnamed fixture despite listing mentions, keeping actual evidence visible' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    kept = '20200101_010203_abcdef13'
    PWN::Sessions.create(id: kept)
    observer = PWN::Sessions.create(id: '20200101_010203_abcdef14', title: 'Named observer')
    File.write(observer[:path].sub('.jsonl', '.meta.json'), JSON.generate(title: 'Named observer', title_source: 'summary', summary: 'Observed conversation', summary_turns: 2))
    File.open(observer[:path], 'a') do |file|
      25.times { file.puts(JSON.generate(role: 'tool', content: JSON.generate(PWN::Sessions.list))) }
    end
    dependency = File.join(Dir.home, '.pwn', 'learning.jsonl')
    File.write(dependency, JSON.generate(session_id: kept, details: "A prose mention of #{id}"))
    dry = described_class.sweep
    expect(dry[:candidate_ids]).to eq([id])
    expect(dry[:deleted_ids]).to eq([])
    expect(described_class.sweep(dry_run: false)[:deleted_ids]).to eq([id])
    rows = PWN::Sessions.list
    expect(rows.map { |row| row[:id] }).to contain_exactly(kept, '20200101_010203_abcdef14')
    expect(rows.find { |row| row[:id] == kept }[:dependencies]).to eq([dependency])
    expect(Dir.glob(File.join(Dir.home, '.pwn', 'session_cleanup_archive', '**', "#{kept}.jsonl"))).to eq([])
  end

  it 'never puts transcript bodies into its dry run ledger' do
    allow(described_class).to receive(:legacy_owners).and_return([])
    File.open(path, 'a') { |file| file.puts(JSON.generate(role: 'user', content: 'private body sentinel')) }
    result = described_class.sweep
    expect(JSON.generate(result)).not_to include('private body sentinel')
    expect(result[:records].first[:files]["#{id}.jsonl"][:sha256]).to eq(Digest::SHA256.file(path).hexdigest)
  end

  it 'retains a transcript whose advisory lock is already held' do
    old = Time.utc(2020)
    File.utime(old, old, path)
    allow(described_class).to receive(:legacy_owners).and_return([])
    File.open(path) do |file|
      file.flock(File::LOCK_EX)
      expect(described_class.sweep(dry_run: false)[:skipped][:locked]).to eq(1)
    end
    expect(File).to exist(path)
  end
end
