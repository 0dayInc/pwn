# frozen_string_literal: true

require 'spec_helper'

describe PWN::Backups do
  before do
    @home = Dir.mktmpdir('pwn-backups-')
    Thread.current[:pwn_backup_root] = nil
    allow(Dir).to receive(:home).and_return(@home)
    @source = File.join(@home, 'source')
    File.write(@source, 'original')
  end

  after { FileUtils.remove_entry(@home) }

  it 'retains no more than seven generations across producers' do
    10.times { described_class.capture(path: @source, label: 'fixture') }
    root = File.join(@home, '.pwn', 'backup')
    expect(Dir.children(root).count { |name| File.directory?(File.join(root, name)) }).to eq(7)
  end

  it 'expires an unreferenced capture pin when capacity is full and keeps a referenced pin' do
    root = File.join(@home, '.pwn', 'backup')
    pinned = 7.times.map { described_class.capture(path: @source, label: 'policy-evaluation', pin: true) }
    generations = pinned.map { |path| File.dirname(path, 2) }.uniq
    generations.each_with_index { |dir, index| File.utime(Time.at(1_700_000_000 + index), Time.at(1_700_000_000 + index), dir) }
    oldest_dir = generations.min_by { |dir| File.mtime(dir) }
    referenced_dir = generations.max_by { |dir| File.mtime(dir) }
    referenced = pinned.find { |path| path.start_with?("#{referenced_dir}/") }
    File.write(File.join(@home, '.pwn', 'policy.json'), JSON.generate(rollback_path: referenced))
    described_class.capture(path: @source, label: 'migration')
    expect(File).not_to exist(oldest_dir)
    expect(File).to exist(referenced)
    expect(Dir.children(root).count { |name| File.directory?(File.join(root, name)) }).to eq(7)
  end

  it 'keeps interrupted transactions prepared and refuses an eighth pinned generation' do
    7.times do
      expect do
        described_class.transaction do
          described_class.capture(path: @source, label: 'fixture')
          raise IOError, 'interrupted'
        end
      end.to raise_error(IOError, 'interrupted')
    end
    expect { described_class.capture(path: @source) }.to raise_error(IOError, /capacity/)
    expect(File.read(@source)).to eq('original')
  end

  it 'pins actual evidence paths but not quoted inventory prose' do
    copies = 7.times.map { described_class.capture(path: @source) }
    generations = copies.map { |path| File.dirname(path, 2) }
    generations.each_with_index { |dir, index| File.utime(Time.at(1_700_000_100 + index), Time.at(1_700_000_100 + index), dir) }
    File.utime(Time.at(1_700_000_000), Time.at(1_700_000_000), generations[1])
    File.write(File.join(@home, '.pwn', 'learning.jsonl'), JSON.generate(evidence_path: copies.first, prose: "old path #{copies[1]}"))
    described_class.capture(path: @source)
    expect(File).to exist(copies.first)
    expect(File).not_to exist(copies[1])
  end

  it 'fails admission on malformed reference data without losing any recovery copy' do
    copies = 7.times.map { described_class.capture(path: @source) }
    File.write(File.join(@home, '.pwn', 'learning.jsonl'), '{broken')
    expect { described_class.capture(path: @source) }.to raise_error(IOError, /references/)
    expect(copies.all? { |path| File.file?(path) }).to be(true)
  end

  it 'uses one generation for nested producers and preserves failed result recovery' do
    copies = []
    described_class.transaction do
      copies << described_class.capture(path: @source, label: 'learning')
      copies << described_class.capture(path: @source, label: 'preferences')
      { ok: false, error: 'fixture' }
    end
    generations = copies.map { |path| File.dirname(path, 2) }.uniq
    expect(generations.length).to eq(1)
    expect(JSON.parse(File.read(File.join(generations.first, '.generation.json')))['state']).to eq('prepared')
  end

  it 'serializes separate processes at the global seven-folder bound' do
    root = File.join(@home, '.pwn', 'backup')
    pids = 4.times.map do
      fork do
        4.times { described_class.capture(path: @source) }
        exit! 0
      rescue StandardError
        exit! 1
      end
    end
    expect(pids.map { |pid| Process.wait2(pid).last.exitstatus }).to eq([0, 0, 0, 0])
    expect(Dir.children(root).count { |name| File.directory?(File.join(root, name)) }).to eq(7)
  end

  it 'requires exact manifest acknowledgement to release interrupted recovery' do
    backup = nil
    expect do
      described_class.transaction do
        backup = described_class.capture(path: @source)
        raise IOError, 'interrupted'
      end
    end.to raise_error(IOError)
    generation = File.basename(File.dirname(backup, 2))
    manifest = File.join(File.dirname(backup, 2), '.generation.json')
    expect { described_class.reconcile(generation: generation, confirmed: true, expected_sha256: 'wrong') }.to raise_error(IOError)
    result = described_class.reconcile(generation: generation, confirmed: true, expected_sha256: Digest::SHA256.file(manifest).hexdigest, pinned: false)
    expect(result).to include(state: 'complete', pinned: false)
    expect(File.read(backup)).to eq('original')
  end

  it 'relocates only explicitly selected unreferenced legacy copies after quiescence confirmation' do
    root = File.join(@home, '.pwn')
    FileUtils.mkdir_p(root)
    legacy = File.join(root, 'learning.jsonl.bak-lean-20200101')
    File.write(legacy, 'legacy bytes')
    expect(described_class.relocate_legacy(paths: [legacy])[:moved]).to eq([])
    expect { described_class.relocate_legacy(paths: [legacy], dry_run: false) }.to raise_error(ArgumentError, /writers/)
    File.write(File.join(root, 'memory.json'), JSON.generate(evidence: legacy))
    expect { described_class.relocate_legacy(paths: [legacy], dry_run: false, writers_stopped: true) }.to raise_error(IOError, /referenced/)
    File.write(File.join(root, 'memory.json'), '{}')
    result = described_class.relocate_legacy(paths: [legacy], dry_run: false, writers_stopped: true)
    expect(File).not_to exist(legacy)
    expect(File.read(result[:moved].fetch(legacy))).to eq('legacy bytes')
  end

  it 'tightens an owned group-writable backup directory before writing' do
    root = File.join(@home, '.pwn', 'backup')
    FileUtils.mkdir_p(root)
    File.chmod(0o775, root)
    described_class.capture(path: @source, label: 'fixture')
    expect(File.stat(root).mode & 0o777).to eq(0o700)
  end
end
