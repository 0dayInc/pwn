# frozen_string_literal: true

require 'spec_helper'
require 'timeout'
require File.expand_path('../../../etc/default_cron/session_cleanup', __dir__)

RSpec.shared_context 'lifecycle closure fixtures' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @root = File.join(@tmp, '.pwn')
    FileUtils.mkdir_p(@root, mode: 0o700)
    {
      'PWN::Sessions::SESSIONS_DIR' => 'sessions',
      'PWN::AI::Agent::Learning::LEARNING_FILE' => 'learning.jsonl',
      'PWN::AI::Agent::Learning::DISPUTED_FILE' => 'learning/disputed.jsonl',
      'PWN::AI::Agent::Learning::LESSONS_FILE' => 'lessons.json',
      'PWN::Memory::MEMORY_FILE' => 'memory.json',
      'PWN::AI::Agent::Mistakes::MISTAKES_FILE' => 'mistakes.json',
      'PWN::Plugins::Findings::FILE' => 'findings.jsonl',
      'PWN::Migrate::PWN_ROOT' => '.',
      'PWN::Migrate::SCHEMA_FILE' => '.schema',
      'PWN::Migrate::BACKUP_ROOT' => 'backup',
      'PWN::Migrate::QUARANTINE_DIR' => 'quarantine'
    }.each { |name, path| stub_const(name, File.join(@root, path)) }
    @proc = File.join(@tmp, 'fixture-proc')
    Dir.mkdir(@proc)
  end

  def cold(id = nil, tool: false)
    session = PWN::Sessions.create(id: id)
    File.open(session[:path], 'a') { |file| file.puts(JSON.generate(role: 'tool', content: 'synthetic observation ' * 8000)) } if tool
    File.utime(Time.at(1), Time.at(1), session[:path])
    session
  end

  def inventory
    Dir.glob(File.join(@root, '**', '*'), File::FNM_DOTMATCH).sort.to_h do |path|
      stat = File.lstat(path)
      [path, [stat.ino, stat.mode, stat.size, stat.mtime, stat.ctime, File.file?(path) ? Digest::SHA256.file(path).hexdigest : nil]]
    end
  end

  def mutate(operation, session)
    case operation
    when :delete then PWN::Sessions.delete(session_id: session[:id], hot_days: 0)
    when :retain then PWN::Sessions.retain(days: 1)
    else PWN::Sessions.lean!(hot_days: 0, retain_days: 100_000, tool_content_max: 10)
    end
  end
end

RSpec.describe 'session lifecycle closure' do
  include_context 'lifecycle closure fixtures'

  %i[delete retain compact].each do |operation|
    it "R01 #{operation} fences a real Learning publisher after the final pin scan" do
      session = cold(nil, tool: true)
      reached = Queue.new
      publisher = nil
      allow(PWN::AI::Agent::Learning).to receive(:learning_lock).and_wrap_original do |method, *args|
        reached << true if Thread.current == publisher
        method.call(*args)
      end
      allow(PWN::Sessions).to receive(:protected_session_ids).and_wrap_original do |method, options|
        pins = method.call(options)
        if options[:include_activity] == false && publisher.nil?
          go = Queue.new
          publisher = Thread.new do
            go.pop
            PWN::AI::Agent::Learning.note_outcome(task: 'synthetic evidence', success: false, session_id: session[:id])
          rescue IOError => e
            e
          end
          go << true
          Timeout.timeout(3) { reached.pop }
        end
        pins
      end
      mutate(operation, session)
      expect(publisher).not_to be_nil
      published = Timeout.timeout(3) { publisher.value }
      if operation == :compact
        expect(published).to be_a(Hash)
        expect(PWN::Sessions.load(session_id: session[:id])).not_to be_empty
        expect(PWN::Sessions.dependency_index[:dependencies][session[:id]]).to include(PWN::AI::Agent::Learning::LEARNING_FILE)
      else
        expect(published).to be_a(IOError)
        expect(PWN::AI::Agent::Learning.outcomes).to eq([])
      end
    ensure
      publisher&.kill if publisher&.alive?
      publisher&.join
    end

    it "R01 #{operation} preserves source while the actual Learning publisher owns its lifetime" do
      session = cold(nil, tool: true)
      original = File.binread(session[:path])
      ready = Queue.new
      release = Queue.new
      publisher = nil
      allow(File).to receive(:open).and_wrap_original do |method, *args, &block|
        if Thread.current == publisher && args.first == PWN::AI::Agent::Learning::LEARNING_FILE && args[1] == 'a'
          ready << true
          release.pop
        end
        method.call(*args, &block)
      end
      publisher = Thread.new do
        PWN::AI::Agent::Learning.note_outcome(task: 'synthetic evidence', success: false, session_id: session[:id])
      end
      Timeout.timeout(3) { ready.pop }
      begin
        Timeout.timeout(3) { mutate(operation, session) }
      rescue IOError
        # Nonblocking contention is an explicit refusal, not permission to mutate.
      end
      expect(File.binread(session[:path])).to eq(original)
      release << true
      Timeout.timeout(3) { publisher.value }
      expect(PWN::Sessions.dependency_index[:dependencies][session[:id]]).to include(PWN::AI::Agent::Learning::LEARNING_FILE)
      expect(PWN::Sessions.load(session_id: session[:id])).not_to be_empty
    ensure
      release << true if release
      publisher&.kill if publisher&.alive?
      publisher&.join
    end
  end

  def publish_finding(session)
    PWN::Plugins::Findings.record(title: 'Synthetic evidence', session_id: session[:id], engagement_id: 'fixture',
                                  evidence: 'synthetic fixture evidence long enough to cite its source file', poc_artifacts: [session[:path]])
  end

  it 'R02 scheduled sweep fences an actual Findings publisher after its final check' do
    session = cold
    entered = Queue.new
    publisher = nil
    allow(PWN::Plugins::Findings).to receive(:record).and_wrap_original do |method, options|
      entered << true
      method.call(options)
    end
    allow(PWN::Sessions).to receive(:delete).and_wrap_original do |method, options|
      publisher = Thread.new do
        publish_finding(session)
      rescue IOError => e
        e
      end
      Timeout.timeout(3) { entered.pop }
      method.call(options)
    end
    result = PWN::SessionCleanup.sweep(dry_run: false, proc_root: @proc)
    expect(result[:deleted_ids]).to include(session[:id])
    expect(Timeout.timeout(3) { publisher.value }).to be_a(IOError)
    expect(PWN::Plugins::Findings.report).to eq([])
    expect(PWN::Plugins::Findings.evidence_verify(engagement_id: 'fixture')).to include(ok: true, rows: 0)
  ensure
    publisher&.kill if publisher&.alive?
    publisher&.join
  end

  it 'R02 coordinator retains the literal source while the actual Findings publisher owns it' do
    session = cold
    original = File.binread(session[:path])
    ready = Queue.new
    release = Queue.new
    allow(PWN::Plugins::Findings).to receive(:evidence_anchor).and_wrap_original do |method, options|
      ready << true
      release.pop
      method.call(options)
    end
    publisher = Thread.new { publish_finding(session) }
    Timeout.timeout(3) { ready.pop }
    begin
      result = Timeout.timeout(3) { PWN::SessionCleanup.coordinate(dry_run: false, proc_root: @proc) }
      expect(result[:phases][:maintenance][:deleted_ids]).to eq([])
    rescue IOError => e
      expect(e.message).to include('Dependency writer active')
      ledger = Dir[File.join(@root, 'maintenance', 'runs', 'coordinator-*.json')].fetch(0)
      expect(JSON.parse(File.read(ledger))['state']).to eq('interrupted')
    end
    expect(File.binread(session[:path])).to eq(original)
    release << true
    Timeout.timeout(3) { publisher.value }
    expect(PWN::Plugins::Findings.evidence_verify(engagement_id: 'fixture')).to include(ok: true, rows: 1)
    expect(PWN::Sessions.dependency_index[:dependencies][session[:id]]).to include(PWN::Plugins::Findings::FILE)
  ensure
    release << true if release
    publisher&.kill if publisher&.alive?
    publisher&.join
  end

  %i[learning findings].each do |producer|
    it "R01/R02 excludes mutation while an actual #{producer} process publishes its first store row" do
      session = cold
      bytes = File.binread(session[:path])
      store = producer == :learning ? PWN::AI::Agent::Learning::LEARNING_FILE : PWN::Plugins::Findings::FILE
      ready_read, ready_write = IO.pipe
      release_read, release_write = IO.pipe
      parent = Process.pid
      allow(File).to receive(:open).and_wrap_original do |method, *args, &block|
        if Process.pid != parent && args.first == store && args[1] == 'a'
          ready_write.write('r')
          release_read.read(1)
        end
        method.call(*args, &block)
      end
      pid = fork do
        ready_read.close
        release_write.close
        if producer == :learning
          PWN::AI::Agent::Learning.note_outcome(task: 'process fixture', success: false, session_id: session[:id])
        else
          publish_finding(session)
        end
        exit! 0
      rescue StandardError
        exit! 1
      end
      ready_write.close
      release_read.close
      Timeout.timeout(3) { expect(ready_read.read(1)).to eq('r') }
      expect(File).not_to exist(store)
      expect { Timeout.timeout(3) { PWN::Sessions.delete(session_id: session[:id], force: true) } }.to raise_error(IOError)
      expect(File.binread(session[:path])).to eq(bytes)
      release_write.write('g')
      status = Timeout.timeout(3) { Process.wait2(pid).last }
      pid = nil
      expect(status.success?).to be(true)
      expect(PWN::Sessions.dependency_index[:dependencies][session[:id]]).to include(store)
      expect(PWN::Sessions.load(session_id: session[:id])).not_to be_empty
      expect(PWN::Plugins::Findings.evidence_verify(engagement_id: 'fixture')[:ok]).to be(true) if producer == :findings
    ensure
      if pid
        Process.kill('KILL', pid)
        Process.wait(pid)
      end
      [ready_read, ready_write, release_read, release_write].compact.each { |io| io.close unless io.closed? }
    end
  end

  it 'R04 lean reports recoverable partial deletion and counts the physically removed transcript' do
    session = cold
    bytes = File.binread(session[:path])
    meta = PWN::Sessions.support_path(kind: :metadata, session_id: session[:id])
    allow(File).to receive(:unlink).and_call_original
    allow(File).to receive(:unlink).with(meta).and_raise(Errno::EACCES, 'synthetic metadata fault')
    result = PWN::Sessions.lean!(hot_days: 0, retain_days: 1)
    expect(result).to include(state: 'interrupted', deleted: 1, remaining: 0)
    partial = result.fetch(:partial_deletions).fetch(0)
    ledger = JSON.parse(File.read(partial.fetch(:ledger)))
    expect(ledger['state']).to eq('interrupted')
    expect(ledger['records'].first['deletion']['deleted_paths']).to include(session[:path])
    expect(File.binread(File.join(File.dirname(partial[:ledger]), File.basename(session[:path])))).to eq(bytes)
    allow(File).to receive(:unlink).with(meta).and_call_original
    PWN::SessionCleanup.recover(ledger: partial[:ledger], dry_run: false)
    expect(File.binread(session[:path])).to eq(bytes)
  ensure
    allow(File).to receive(:unlink).with(meta).and_call_original if meta
  end

  it 'R04 coordinator interrupts after partial deletion and persists the exact outcome' do
    session = cold
    bytes = File.binread(session[:path])
    meta = PWN::Sessions.support_path(kind: :metadata, session_id: session[:id])
    allow(File).to receive(:unlink).and_call_original
    allow(File).to receive(:unlink).with(meta).and_raise(Errno::EACCES, 'synthetic metadata fault')
    expect(PWN::AI::Agent::Learning).not_to receive(:consolidate)
    result = PWN::SessionCleanup.coordinate(dry_run: false, proc_root: @proc)
    expect(result[:state]).to eq('interrupted')
    maintenance = result[:phases][:maintenance]
    expect(maintenance[:state]).to eq('interrupted')
    expect(maintenance[:deleted_ids]).to include(session[:id])
    expect(maintenance[:records].first[:deletion]).to include(state: 'interrupted', deleted_paths: [session[:path]], remaining_paths: [meta])
    expect(JSON.parse(File.read(result[:transaction_ledger]))['state']).to eq('interrupted')
    expect(JSON.parse(File.read(maintenance[:transaction_ledger]))['state']).to eq('interrupted')
    ledger = File.join(maintenance[:archive_dir], 'ledger.json')
    expect(JSON.parse(File.read(ledger))['records'].first['deletion']['state']).to eq('interrupted')
    expect(File.binread(File.join(maintenance[:archive_dir], File.basename(session[:path])))).to eq(bytes)
    allow(File).to receive(:unlink).with(meta).and_call_original
    PWN::SessionCleanup.recover(ledger: ledger, dry_run: false)
    expect(File.binread(session[:path])).to eq(bytes)
  ensure
    allow(File).to receive(:unlink).with(meta).and_call_original if meta
  end

  it 'R04 records interruption after transcript unlink before propagating cancellation to both parents' do
    session = cold
    bytes = File.binread(session[:path])
    meta = PWN::Sessions.support_path(kind: :metadata, session_id: session[:id])
    allow(File).to receive(:unlink).and_call_original
    allow(File).to receive(:unlink).with(meta).and_raise(Interrupt, 'synthetic cancellation')
    expect(PWN::AI::Agent::Learning).not_to receive(:consolidate)
    expect { PWN::SessionCleanup.coordinate(dry_run: false, proc_root: @proc) }.to raise_error(Interrupt)
    parents = Dir[File.join(@root, 'maintenance', 'runs', '*.json')].map { |path| JSON.parse(File.read(path)) }
    expect(parents.length).to eq(2)
    expect(parents.map { |row| row['state'] }).to eq(%w[interrupted interrupted])
    ledger = Dir[File.join(@root, 'backup', '**', 'ledger.json')].find { |path| JSON.parse(File.read(path))['records']&.any? { |row| row['deletion'] } }
    child = JSON.parse(File.read(ledger))['records'].find { |row| row['id'] == session[:id] }
    expect(child['deletion']).to include('state' => 'interrupted', 'deleted_paths' => [session[:path]], 'remaining_paths' => [meta])
    expect(File.binread(File.join(File.dirname(ledger), File.basename(session[:path])))).to eq(bytes)
  ensure
    allow(File).to receive(:unlink).with(meta).and_call_original if meta
  end

  it 'R10 commits ordinary coordinator work without confusing status inventory with admitted children' do
    result = PWN::SessionCleanup.coordinate(dry_run: false, proc_root: @proc)
    expect(result[:state]).to eq('committed')
    expect(result[:phases].keys).to eq(%i[maintenance memory_consolidation learning_retention mistakes_retention policy_retention])
  end

  it 'R10 propagates the actual prepared backup-compaction failure through both parent ledgers' do
    id = '20000101_000000_aabbccdd'
    payload = "#{JSON.generate(role: 'system', content: 'Session started: synthetic')}\n"
    digest = Digest::SHA256.hexdigest(payload)
    %w[first second].each do |name|
      dir = File.join(@root, 'session_cleanup_archive', name)
      FileUtils.mkdir_p(dir)
      File.write(File.join(dir, "#{id}.jsonl"), payload)
      ledger = File.join(dir, 'ledger.json')
      File.write(ledger, JSON.generate(dry_run: false, deleted_ids: [id], records: [{ id: id, deleted: true, files: { "#{id}.jsonl" => { sha256: digest } } }]))
      File.utime(Time.at(1), Time.at(1), ledger)
    end
    allow(File).to receive(:link).and_wrap_original do |method, source, dest|
      raise Errno::EACCES, 'synthetic compaction failure' if dest.include?('.compact-')

      method.call(source, dest)
    end
    expect(PWN::AI::Agent::Learning).not_to receive(:consolidate)
    result = PWN::SessionCleanup.coordinate(dry_run: false, proc_root: @proc)
    expect(result[:state]).to eq('interrupted')
    maintenance = result[:phases][:maintenance]
    child = maintenance[:legacy_backups]
    expect(child[:state]).to eq('interrupted')
    expect(JSON.parse(File.read(child[:ledger]))['records']).to include(hash_including('state' => 'prepared'))
    expect(JSON.parse(File.read(maintenance[:transaction_ledger]))['state']).to eq('interrupted')
    expect(JSON.parse(File.read(result[:transaction_ledger]))['state']).to eq('interrupted')
    expect(result[:phases]).not_to have_key(:learning_retention)
  end

  it 'R03 recovery preview resolves absent destinations without creating session or metadata directories' do
    id = '20000101_000000_aabbccdd'
    directory = File.join(@root, 'session_cleanup_archive', 'fixture')
    FileUtils.mkdir_p(directory)
    files = { "#{id}.jsonl" => "#{JSON.generate(role: 'system', content: 'Session started: fixture')}\n", "#{id}.meta.json" => JSON.generate(id: id, title: 'fixture') }
    files.each { |name, bytes| File.write(File.join(directory, name), bytes) }
    ledger = File.join(directory, 'ledger.json')
    File.write(ledger, JSON.generate(dry_run: false, deleted_ids: [id], records: [{ id: id, files: files.transform_values { |bytes| { sha256: Digest::SHA256.hexdigest(bytes) } } }]))
    before = inventory
    PWN::SessionCleanup.recover(ledger: ledger, dry_run: true)
    expect(inventory).to eq(before)
  end

  %i[lean! sweep maintain run coordinate reorganize].each do |operation|
    [false, true].each do |compact|
      it "R03 #{operation} dry-run is noncreating with #{compact ? 'incomplete compact layout' : 'absent store'}" do
        if compact
          root = PWN::Sessions.sessions_dir
          File.write(File.join(root, '20000101_000000_aabbccdd.jsonl'), "#{JSON.generate(role: 'system', content: 'Session started: fixture')}\n")
          File.write(File.join(root, '.layout-v2'), 'fixture')
        end
        before = inventory
        if operation == :lean!
          PWN::Sessions.lean!(dry_run: true)
        else
          PWN::SessionCleanup.public_send(operation, dry_run: true, proc_root: @proc)
        end
        expect(inventory).to eq(before)
      end
    end
  end
end
