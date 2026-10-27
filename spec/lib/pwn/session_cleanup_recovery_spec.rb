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

  describe 'bounded housekeeping recovery' do
    it 'restores legacy session bytes explicitly without overwriting newer sessions' do
      allow(described_class).to receive(:legacy_owners).and_return([])
      original = File.binread(path)
      result = described_class.sweep(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
      expect(result[:deleted_ids]).to include(id)
      ledger = File.join(result[:archive_dir], 'ledger.json')
      expect(described_class.recovery_status(ledger: ledger)[:actions]).to include('restore')
      expect(described_class.recover(ledger: ledger, dry_run: false)[:restored]).to include(path)
      expect(File.binread(path)).to eq(original)
      File.write(path, 'newer bytes')
      expect { described_class.recover(ledger: ledger, dry_run: false) }.to raise_error(IOError, /existing/)
      expect(File.read(path)).to eq('newer bytes')
    end

    it 'rolls back a continuation retirement only while the post-retirement map is unchanged' do
      root = File.join(Dir.home, '.pwn', 'swarm')
      swarm = '20200101_010203_abcdef'
      map = File.join(root, swarm, 'personas.json')
      FileUtils.mkdir_p(File.dirname(map))
      File.write(map, JSON.generate('analyst' => id))
      result = described_class.retire_continuation(root: root, swarm_id: swarm, name: 'analyst')
      ledger = File.join(File.dirname(result[:backup]), 'ledger.json')
      expect(described_class.recover(ledger: ledger, action: 'rollback', dry_run: false)[:restored]).to eq([map])
      expect(JSON.parse(File.read(map))).to eq('analyst' => id)
      File.write(map, JSON.generate('changed' => id))
      expect { described_class.recover(ledger: ledger, action: 'rollback', dry_run: false) }.to raise_error(IOError, /changed/)
    end

    it 'rolls back targeted dependency removal only after restoring source sessions and validating current bytes' do
      store = File.join(Dir.home, '.pwn', 'mistakes.json')
      original = JSON.generate(bad: { sessions: [id], verified_sessions: {} })
      File.write(store, original)
      allow(described_class).to receive(:legacy_owners).and_return([])
      result = described_class.sweep(dry_run: false)
      ledger = File.join(result[:archive_dir], 'ledger.json')
      expect { described_class.recover(ledger: ledger, action: 'rollback_dependencies', dry_run: false) }.to raise_error(IOError, /source/)
      described_class.recover(ledger: ledger, dry_run: false)
      expect(described_class.recover(ledger: ledger, action: 'rollback_dependencies', dry_run: false)[:restored]).to eq([store])
      expect(File.binread(store)).to eq(original.b)
    end

    it 'refuses a dependency store exceeding the read admission budget' do
      described_class.install
      config = described_class.policy.merge('work_bytes' => 1)
      File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
      File.write(PWN::AI::Agent::Learning::LEARNING_FILE, JSON.generate(session_id: id, outcome: 'fixture'))
      report = described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
      expect(report).to include(state: 'interrupted', incomplete: true)
      expect(report[:dependency_errors]).to include('incomplete_dependency_index')
      expect(File.file?(path)).to be(true)
    end

    it 'stops between phases on the time budget without interrupting an admitted write' do
      described_class.install
      now = 100.0
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(now)
      allow(described_class).to receive(:maintenance_transaction).and_wrap_original do |method, **options|
        result = method.call(**options)
        allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(now + 60)
        result
      end
      allow(described_class).to receive(:legacy_owners).and_return([])
      report = described_class.maintain(dry_run: false)
      expect(report).to include(state: 'interrupted', incomplete: true)
      expect(JSON.parse(File.read(report[:transaction_ledger]))['state']).to eq('interrupted')
    end

    it 'indexes only committed legacy backup rows and compacts duplicates without unlinking the last copy' do
      described_class.install
      allow(described_class).to receive(:legacy_owners).and_return([])
      original = File.binread(path)
      results = 2.times.map do
        File.binwrite(path, original)
        described_class.sweep(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
      end
      backups = results.map { |row| File.join(row[:archive_dir], "#{id}.jsonl") }
      PWN::Sessions.create(id: id)
      PWN::Sessions.append(session_id: id, role: 'user', content: 'evidence')
      File.write(PWN::AI::Agent::Learning::LEARNING_FILE, JSON.generate(session_id: id, outcome: 'fixture'))
      migration = PWN::AI::Agent::Learning.migrate_evidence(dry_run: false)
      learning_backup = migration[:ledger].sub('.json', '.backup.jsonl')
      inventory = described_class.legacy_backups.map { |row| row[:path] }
      expect(inventory).to include(*backups, learning_backup)
      config = described_class.policy
      config['retention_days']['maintenance'] = 0
      File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
      result = described_class.prune_legacy_backups(dry_run: false)
      expect(result[:compacted] & backups).not_to be_empty
      expect(File.identical?(*backups)).to be(true)
      expect(File.file?(learning_backup)).to be(true)
      record = JSON.parse(File.read(migration[:ledger])).merge('state' => 'prepared')
      File.write(migration[:ledger], JSON.generate(record))
      expect(described_class.legacy_backups.map { |row| row[:path] }).not_to include(learning_backup)
    end

    it 'upgrades the inventory v1 without changing operator policy or unknown layouts' do
      described_class.install
      directory = File.join(Dir.home, '.pwn', 'maintenance')
      config = File.binread(File.join(directory, 'policy.json'))
      layout = File.join(directory, 'layout.json')
      File.write(layout, JSON.generate(version: 1, categories: { learning: ['learning_evidence'] }))
      described_class.install
      expect(JSON.parse(File.read(layout))).to include('version' => 2, 'categories' => described_class::STORAGE)
      expect(File.binread(File.join(directory, 'policy.json'))).to eq(config)
      File.write(layout, JSON.generate(version: 99, categories: {}))
      expect { described_class.install }.to raise_error(IOError, /inventory/)
    end

    it 'halts admission on a partial dependency index without deleting unique or active evidence' do
      described_class.install
      config = described_class.policy.merge('work_items' => 1, 'work_seconds' => 60)
      File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
      bytes = File.binread(path)
      lease = PWN::Sessions.activate(session_id: id)
      report = described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
      expect(report[:state]).to eq('interrupted')
      expect(report[:incomplete]).to be(true)
      expect(File.binread(path)).to eq(bytes)
      expect(Thread.current[:pwn_maintenance_admission]).to be_nil
    ensure
      lease&.close
    end

    it 'prunes redundant physical continuation backups while preserving rollback paths and unique evidence' do
      described_class.install
      root = File.join(Dir.home, '.pwn', 'swarm')
      swarm = '20200101_010203_abcdef'
      map = File.join(root, swarm, 'personas.json')
      FileUtils.mkdir_p(File.dirname(map))
      backups = 2.times.map do
        File.write(map, JSON.generate('analyst' => id))
        described_class.retire_continuation(root: root, swarm_id: swarm, name: 'analyst').fetch(:backup)
      end
      config = described_class.policy
      config['retention_days']['maintenance'] = 0
      File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
      original = File.binread(backups.first)
      config['retention_days']['maintenance'] = 90
      config['budget_bytes']['maintenance'] = 0
      File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
      expect(File.identical?(*backups)).to be(false)
      report = described_class.prune_legacy_backups(dry_run: false)
      expect(report[:compacted].length).to eq(1)
      expect(File.identical?(*backups)).to be(true)
      expect(backups.map { |file| File.binread(file) }).to eq([original, original])
      expect(described_class.prune_legacy_backups(dry_run: false)[:compacted]).to be_empty
      expect(described_class.recovery_status(ledger: report[:ledger])[:state]).to eq('committed')
      # Model interruption after the atomic replacement but before commit readback.
      interrupted = JSON.parse(File.read(report[:ledger]))
      interrupted['state'] = 'prepared'
      interrupted['records'].each { |row| row['state'] = 'prepared' }
      File.write(report[:ledger], JSON.generate(interrupted))
      expect(described_class.recover(ledger: report[:ledger], action: 'resume', dry_run: false)[:state]).to eq('committed')
      expect(backups.map { |file| File.binread(file) }).to eq([original, original])
    end

    it 'owns actual festival input through use and removes it without a global tmp sweep' do
      observed = nil
      allow(PWN::Plugins::Voice).to receive(:text_to_speech) do |opts|
        observed = opts[:text_path]
        expect(observed).to start_with("#{File.join(Dir.home, '.pwn', 'tmp')}/")
        expect(File.read(observed)).to eq('fixture speech')
        expect(described_class.clean_disposables(dry_run: false)[:deleted]).to be_empty
      end
      result = PWN::AI::Agent::Extrospection.send(:voice_tts, text: 'fixture speech', engine: :festival, out: File.join(@tmp, 'speech.wav'))
      expect(result.first).to be(true)
      expect(File.exist?(observed)).to be(false)
    end

    it 'recovers a killed atomic cache producer using its ownership journal, never its filename' do
      described_class.install
      cache = File.join(Dir.home, '.pwn', 'cache', 'killed')
      described_class.cache(path: cache, bytes: 'old')
      child = fork do
        allow(File).to receive(:rename).and_call_original
        allow(File).to receive(:rename).with(anything, cache) { exit! 0 }
        described_class.cache(path: cache, bytes: 'new')
        exit! 1
      end
      _, child_status = Process.wait2(child)
      expect(child_status.exitstatus).to eq(0)
      unknown = "#{cache}.unknown.tmp"
      File.write(unknown, 'unknown')
      atomic = Dir.glob(File.join(Dir.home, '.pwn', 'maintenance', 'atomic', '*.json')).fetch(0)
      owned = JSON.parse(File.read(atomic)).fetch('path')
      File.write(owned, 'changed')
      expect(described_class.recover_atomic_temps(dry_run: false)[:deleted]).to be_empty
      File.write(owned, 'new')
      report = described_class.recover_atomic_temps(dry_run: false)
      expect(report[:deleted].length).to eq(1)
      expect(File.read(cache)).to eq('old')
      expect(File.read(unknown)).to eq('unknown')
      expect(described_class.recover_atomic_temps(dry_run: false)[:deleted]).to be_empty
    end

    it 'resumes expiry_prepared after an interruption between backup unlinks' do
      described_class.install
      config = described_class.policy
      config['retention_days']['maintenance'] = 0
      File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
      2.times do |index|
        file = File.join(Dir.home, '.pwn', 'tmp', "expiry-#{index}")
        File.write(file, "bytes-#{index}")
        described_class.register_disposable(path: file, category: 'tmp', expires_at: 0)
      end
      result = described_class.clean_disposables(dry_run: false)
      backups = result[:records].map { |row| row['backup'] }
      allow(File).to receive(:unlink).and_call_original
      allow(File).to receive(:unlink).with(backups.last).and_raise(Interrupt)
      expect { described_class.prune_quarantine(dry_run: false) }.to raise_error(Interrupt)
      expect(JSON.parse(File.read(result[:ledger]))['state']).to eq('expiry_prepared')
      expect(File.exist?(backups.first)).to be(false)
      allow(File).to receive(:unlink).with(backups.last).and_call_original
      expect(described_class.prune_quarantine(dry_run: false)[:deleted]).to eq([backups.last])
      expect(JSON.parse(File.read(result[:ledger]))['state']).to eq('expired')
    end

    it 'explicitly delegates learning recovery to validated store rollback without pretending broad rollback' do
      PWN::Sessions.append(session_id: id, role: 'user', content: '証拠')
      file = PWN::AI::Agent::Learning::LEARNING_FILE
      original = JSON.generate(session_id: id, outcome: 'fixture')
      File.write(file, original)
      migration = PWN::AI::Agent::Learning.migrate_evidence(dry_run: false)
      expect(described_class.recovery_status(ledger: migration[:ledger])[:actions]).to include('rollback')
      expect(described_class.recover(ledger: migration[:ledger], action: 'rollback', dry_run: true)[:dry_run]).to be(true)
      expect(File.read(file)).not_to eq(original)
      expect(described_class.recover(ledger: migration[:ledger], action: 'rollback', dry_run: false)[:restored]).to be(true)
      expect(File.binread(file)).to eq(original.b)
    end
  end
end

RSpec.describe PWN::SessionCleanup, 'disposable admission and scan progress' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(File.join(@tmp, 'home'))
    FileUtils.mkdir_p(File.join(Dir.home, '.pwn'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(Dir.home, '.pwn', 'learning.jsonl'))
  end

  it 'admits disposable payload IO before hashing or backing up through maintain' do
    described_class.install
    allow(described_class).to receive(:legacy_owners).and_return([])
    cache = File.join(Dir.home, '.pwn', 'cache', 'large')
    described_class.cache(path: cache, bytes: 'x' * 1_048_576)
    described_class.register_disposable(path: cache, category: 'cache', expires_at: 0)
    allow(Digest::SHA256).to receive(:file).and_call_original
    allow(File).to receive(:binread).and_call_original
    expect(Digest::SHA256).not_to receive(:file).with(cache)
    expect(File).not_to receive(:binread).with(cache, any_args)
    config = described_class.policy.merge('work_bytes' => 1024)
    File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
    report = described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
    expect(report).to include(state: 'interrupted', incomplete: true)
    expect(File.size(cache)).to eq(1_048_576)
    expect(report[:storage][:deleted]).to be_empty
    expect(Dir.glob(File.join(Dir.home, '.pwn', 'maintenance', 'quarantine', '*', '*.bin'))).to be_empty
  end

  it 'advances bounded scans past completed and normally removed temporary manifests' do
    described_class.install
    allow(described_class).to receive(:legacy_owners).and_return([])
    described_class.temporary(bytes: 'normal producer') { |_file| nil }
    files = 2.times.map do |index|
      file = File.join(Dir.home, '.pwn', 'cache', "expire-#{index}")
      described_class.cache(path: file, bytes: "cache-#{index}")
      described_class.register_disposable(path: file, category: 'cache', expires_at: 0)
      file
    end
    config = described_class.policy.merge('scan_limit' => 1)
    File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
    reports = 6.times.map { described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc')) }
    expect(reports.flat_map { |report| report[:storage][:deleted] }).to contain_exactly(*files)
    expect(files.none? { |file| File.exist?(file) }).to be(true)
    expect(Dir.glob(File.join(Dir.home, '.pwn', 'maintenance', 'disposable', '*.json')).length).to eq(3)
    expect(reports.all? { |report| report[:storage][:deleted].length <= 1 }).to be(true)
  end

  it 'does not hash or expire oversized quarantine backups through maintain' do
    described_class.install
    allow(described_class).to receive(:legacy_owners).and_return([])
    cache = File.join(Dir.home, '.pwn', 'cache', 'quarantined')
    described_class.cache(path: cache, bytes: 'q' * 1_048_576)
    described_class.register_disposable(path: cache, category: 'cache', expires_at: 0)
    removed = described_class.clean_disposables(dry_run: false)
    backup = removed[:records].first.fetch('backup')
    config = described_class.policy.merge('work_bytes' => 8192)
    config['retention_days']['maintenance'] = 0
    File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
    report = described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
    expect(report).to include(state: 'interrupted', incomplete: true)
    expect(File.size(backup)).to eq(1_048_576)
    expect(JSON.parse(File.read(removed[:ledger]))['state']).to eq('committed')
  end

  it 'revisits active and mutated entries without losing a later re-registration' do
    described_class.install
    allow(described_class).to receive(:legacy_owners).and_return([])
    files = %w[active mutated ready].map do |name|
      file = File.join(Dir.home, '.pwn', 'cache', name)
      described_class.cache(path: file, bytes: name)
      described_class.register_disposable(path: file, category: 'cache', expires_at: 0)
      file
    end
    File.write(files[1], 'mutated payload')
    lease = File.open("#{files[0]}.lease", File::RDWR) # rubocop:disable Style/FileOpen -- lifetime spans repeated maintenance calls
    lease.flock(File::LOCK_SH)
    config = described_class.policy.merge('scan_limit' => 1)
    File.write(File.join(Dir.home, '.pwn', 'maintenance', 'policy.json'), JSON.generate(config))
    reports = 3.times.map { described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc')) }
    expect(reports.flat_map { |report| report[:storage][:deleted] }).to eq([files[2]])
    expect(File.read(files[0])).to eq('active')
    expect(File.read(files[1])).to eq('mutated payload')
    lease.close
    described_class.cache(path: files[2], bytes: 'new registration')
    3.times { described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc')) }
    expect(File.exist?(files[0])).to be(false)
    expect(File.read(files[1])).to eq('mutated payload')
    expect(File.read(files[2])).to eq('new registration')
  ensure
    lease&.close unless lease&.closed?
  end

  it 'finishes an admitted disposable commit when the deadline expires during backup' do
    described_class.install
    allow(described_class).to receive(:legacy_owners).and_return([])
    cache = File.join(Dir.home, '.pwn', 'cache', 'admitted')
    described_class.cache(path: cache, bytes: 'exact recoverable payload')
    described_class.register_disposable(path: cache, category: 'cache', expires_at: 0)
    allow(described_class).to receive(:publish).and_wrap_original do |method, target, bytes|
      result = method.call(target, bytes)
      Thread.current[:pwn_maintenance_budget][:deadline] = 0 if target.end_with?('.bin')
      result
    end
    report = described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
    expect(report).to include(state: 'interrupted', incomplete: true)
    expect(report[:storage][:deleted]).to eq([cache])
    record = report[:storage][:records].first
    expect(record['state']).to eq('committed')
    expect(File.binread(record['backup'])).to eq('exact recoverable payload')
    expect(JSON.parse(File.read(report[:storage][:ledger]))['records'].first['state']).to eq('committed')
  end

  it 'retains a manifest re-registered after discovery but before its lease' do
    described_class.install
    allow(described_class).to receive(:legacy_owners).and_return([])
    cache = File.join(Dir.home, '.pwn', 'cache', 'renewed')
    described_class.cache(path: cache, bytes: 'same payload')
    described_class.register_disposable(path: cache, category: 'cache', expires_at: 0)
    renewed = false
    allow(described_class).to receive(:disposable_reason).and_wrap_original do |method, row, **options|
      reason = method.call(row, **options)
      if !options[:verify] && !renewed
        renewed = true
        described_class.register_disposable(path: cache, category: 'cache', expires_at: Time.now.to_i + 3600)
      end
      reason
    end
    report = described_class.maintain(dry_run: false, proc_root: File.join(@tmp, 'no-proc'))
    expect(report[:storage][:deleted]).to be_empty
    expect(File.read(cache)).to eq('same payload')
  end
end
