# frozen_string_literal: true

require 'spec_helper'
require File.expand_path('../../../etc/default_cron/session_cleanup', __dir__)

RSpec.describe PWN::SessionCleanup do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(File.join(@tmp, 'home'))
    @root = File.join(Dir.home, '.pwn')
    FileUtils.mkdir_p(File.join(@root, 'logs'))
    FileUtils.mkdir_p(File.join(@root, 'sessions'))
    File.write(File.join(@root, 'sessions', '.maintenance.lock'), '')
    @path = File.join(@root, 'logs', 'pwn-ai-DEBUG-abc123-R1.log')
    File.write(@path, 'debug session stop')
    File.utime(Time.at(1), Time.at(1), @path)
    allow(described_class).to receive(:legacy_open_files).and_return([])
    @manifest = File.join(@tmp, 'expiry.json.gz')
  end

  it 'retains open descriptors, referenced paths, recent and unrecognized logs' do
    File.write(File.join(@root, 'memory.json'), JSON.generate(evidence: @path))
    expect(described_class.expire_legacy[:retained].first[:reason]).to eq('evidence_reference')
    File.unlink(File.join(@root, 'memory.json'))
    stat = File.stat(@path)
    allow(described_class).to receive(:legacy_open_files).and_return([[stat.dev, stat.ino]])
    expect(described_class.expire_legacy[:retained].first[:reason]).to eq('open_descriptor')
    allow(described_class).to receive(:legacy_open_files).and_return([])
    File.utime(Time.now, Time.now, @path)
    expect(described_class.expire_legacy[:candidates]).to be_empty
    File.utime(Time.at(1), Time.at(1), @path)
    File.rename(@path, File.join(@root, 'logs', 'unknown.log'))
    expect(described_class.expire_legacy[:candidates]).to be_empty
  end

  it 'fails closed on symlinks, changed inodes, unreadable proc and held maintenance locks' do
    original = @path
    File.rename(original, "#{original}.save")
    File.symlink("#{original}.save", original)
    expect { described_class.expire_legacy }.to raise_error(IOError, /Unsafe/)
    File.unlink(original)
    File.rename("#{original}.save", original)
    allow(described_class).to receive(:legacy_open_files).and_raise(Errno::EACCES)
    expect { described_class.expire_legacy }.to raise_error(Errno::EACCES)
    allow(described_class).to receive(:legacy_open_files).and_return([])
    File.open(File.join(@root, 'sessions', '.maintenance.lock'), 'r+') do |lock|
      lock.flock(File::LOCK_EX)
      expect { described_class.expire_legacy }.to raise_error(IOError, /Maintenance active/)
    end
    allow(described_class).to receive(:legacy_manifest).and_wrap_original do |method, *args|
      method.call(*args)
      File.write(original, 'replacement')
    end
    expect { described_class.expire_legacy(dry_run: false, manifest: @manifest) }.to raise_error(IOError, /changed/)
    expect(File.read(original)).to eq('replacement')
  end

  it 'requires external metadata and preserves unclosed diagnostics' do
    expect { described_class.expire_legacy(dry_run: false, manifest: File.join(@root, 'manifest.gz')) }.to raise_error(ArgumentError)
    File.write(@path, 'still running')
    File.utime(Time.at(1), Time.at(1), @path)
    expect(described_class.expire_legacy[:candidates]).to be_empty
  end

  it 'expires triage cache only when byte-identical evidence survives outside the cache' do
    directory = File.join(@root, 'cache', 'triage')
    FileUtils.mkdir_p(directory)
    cache = File.join(directory, "#{'a' * 64}.json")
    File.write(cache, JSON.generate(sha256: 'a' * 64, path: '/missing/input'))
    File.utime(Time.at(1), Time.at(1), cache)
    FileUtils.mkdir_p(File.join(@root, 'artifacts', 'test'))
    evidence = File.join(@root, 'artifacts', 'test', 'copy.bin')
    FileUtils.cp(cache, evidence)
    result = described_class.expire_legacy(dry_run: false, manifest: @manifest)
    expect(result[:removed].map { |row| row[:path] }).to include(cache)
    expect(File.exist?(evidence)).to be(true)
  end

  it 'keeps three valid recovery copies per known family and preserves exact evidence pins' do
    File.write(File.join(@root, 'learning.jsonl'), "{}\n")
    backups = (1..5).map do |day|
      path = File.join(@root, format('learning.jsonl.bak-lean-202001%02d', day))
      File.write(path, "{}\n")
      File.utime(Time.at(day), Time.at(day), path)
      path
    end
    File.write(File.join(@root, 'memory.json'), JSON.generate(evidence: backups.first))
    result = described_class.expire_legacy(dry_run: false, manifest: @manifest)
    expect(result[:removed].map { |row| row[:path] }).to include(backups[1])
    expect(backups.select { |path| File.exist?(path) }).to eq(backups.values_at(0, 2, 3, 4))
  end

  it 'expires only closed recognized diagnostics with an external metadata manifest' do
    result = described_class.expire_legacy(dry_run: false, manifest: @manifest)
    expect(result[:removed].map { |row| row[:path] }).to eq([@path])
    expect(File.exist?(@path)).to be(false)
    expect(JSON.parse(Zlib::GzipReader.open(@manifest, &:read))['removed'].first['sha256']).to eq(Digest::SHA256.hexdigest('debug session stop'))
    expect(Dir.children(File.join(@root, 'logs'))).to be_empty
  end
end
