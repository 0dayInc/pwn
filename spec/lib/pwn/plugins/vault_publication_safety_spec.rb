# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'timeout'

RSpec.describe PWN::Plugins::Vault, 'serialized publication safety' do
  before do
    @root = Dir.mktmpdir('vault-publication-safety-')
    allow(Dir).to receive(:home).and_return(@root)
    @device = double('offline YubiKey')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) { |opts| OpenSSL::HMAC.digest('SHA1', 'fixture-slot', opts[:challenge]) }
    @path = File.join(@root, 'vault')
    @legacy = { key: Base64.strict_encode64('k' * 32), iv: Base64.strict_encode64('i' * 16) }
    @document = { token: 'fixture', retained: 'original' }
    @threads = []
  end

  after do
    @threads.each do |thread|
      thread.kill if thread.alive?
      thread.join(1)
    end
    FileUtils.remove_entry(@root)
  end

  def writer_thread(role, &block)
    thread = Thread.new do
      Thread.current.report_on_exception = false
      Thread.current[:vault_publication_role] = role
      block.call
    end
    @threads << thread
    thread
  end

  def prepare_vault(backend = :hardware)
    access = backend == :hardware ? { yubikey: {} } : @legacy
    File.binwrite(@path, described_class.encrypt_data(access.merge(data: YAML.dump(@document))))
  end

  def fake_editor
    allow(File).to receive(:executable?).and_call_original
    allow(File).to receive(:executable?).with('/offline-editor').and_return(true)
    allow(described_class).to receive(:system).with('/offline-editor', anything) do |_editor, path|
      File.write(path, YAML.dump(@document.merge(edited: true)))
      true
    end
  end

  %i[refresh_encryption_secrets edit].each do |writer|
    it "serializes #{writer} against update even when paused after its baseline check", :aggregate_failures do
      prepare_vault
      fake_editor if writer == :edit
      ready = Queue.new
      release = Queue.new
      attempts = Queue.new
      allow(File).to receive(:rename).and_wrap_original do |rename, from, to|
        if to == @path && Thread.current[:vault_publication_role] == :first
          ready << true
          release.pop
        end
        rename.call(from, to)
      end
      # Probe the updater's actual flock before blocking. This makes the old
      # unchecked-rename interleaving deterministic, without sleeps or polling.
      allow(File).to receive(:open).and_wrap_original do |open, *args, **kwargs, &block|
        if args == [@root, File::RDONLY] && Thread.current[:vault_publication_role] == :updater
          open.call(*args) do |lock|
            allow(lock).to receive(:flock).and_wrap_original do |flock, operation|
              if operation == File::LOCK_EX
                acquired = flock.call(operation | File::LOCK_NB)
                attempts << (acquired ? :acquired : :blocked)
                acquired || flock.call(operation)
              else
                flock.call(operation)
              end
            end
            block.call(lock)
          end
        else
          open.call(*args, **kwargs, &block)
        end
      end
      attempt = nil
      Timeout.timeout(5) do
        first = writer_thread(:first) { described_class.public_send(writer, file: @path, editor: '/offline-editor') }
        ready.pop
        updater = writer_thread(:updater) { described_class.update(file: @path) { |cfg| cfg[:updated] = true } }
        attempt = attempts.pop
        updater.value if attempt == :acquired
        release << true
        first.value
        expect(updater.value).to eq(:saved)
      end
      expect(attempt).to eq(:blocked)
      expected = @document.merge(updated: true)
      expected[:edited] = true if writer == :edit
      expect(described_class.dump(file: @path)).to eq(expected)
      expect(Dir.glob(File.join(@root, '.pwn-vault-*'))).to be_empty
    end
  end

  %i[update refresh_encryption_secrets edit encrypt decrypt create legacy_refresh legacy_create].each do |writer|
    it "holds the shared directory lock through every #{writer} rename" do
      if %i[encrypt create legacy_create].include?(writer)
        File.write(@path, YAML.dump(@document))
      else
        prepare_vault(writer == :legacy_refresh ? :legacy : :hardware)
      end
      fake_editor if writer == :edit
      publications = 0
      allow(File).to receive(:rename).and_wrap_original do |rename, from, to|
        if to == @path
          File.open(@root, File::RDONLY) do |probe|
            expect(probe.flock(File::LOCK_EX | File::LOCK_NB)).to be(false)
          end
          publications += 1
        end
        rename.call(from, to)
      end
      Timeout.timeout(5) do
        case writer
        when :update
          described_class.update(file: @path) { |cfg| cfg[:updated] = true }
        when :legacy_refresh
          described_class.refresh_encryption_secrets(@legacy.merge(file: @path))
        when :legacy_create
          described_class.create(file: @path, decryptor_file: "#{@path}.decryptor")
        when :create, :encrypt
          described_class.public_send(writer, file: @path, yubikey: {})
        else
          described_class.public_send(writer, file: @path, editor: '/offline-editor')
        end
      end
      expect(publications).to be_positive
    end
  end

  it 'allows nested updates in one directory without reacquiring its own lock' do
    prepare_vault
    sibling = File.join(@root, 'sibling')
    File.binwrite(sibling, File.binread(@path))
    Timeout.timeout(5) do
      described_class.update(file: @path) do |cfg|
        described_class.update(file: sibling) { |other| other[:nested] = true }
        cfg[:outer] = true
      end
    end
    expect(described_class.dump(file: @path)).to eq(@document.merge(outer: true))
    expect(described_class.dump(file: sibling)).to eq(@document.merge(nested: true))
  end

  it 'retains expected-byte conflict detection for nested writes to the same vault' do
    prepare_vault
    Timeout.timeout(5) do
      expect do
        described_class.update(file: @path) do |cfg|
          described_class.refresh_encryption_secrets(file: @path)
          cfg[:stale] = true
        end
      end.to raise_error(IOError, /changed before replacement/)
    end
    expect(described_class.dump(file: @path)).to eq(@document)
  end

  it 'does not overwrite changes from a writer that bypasses the advisory lock' do
    prepare_vault
    replacement = described_class.encrypt_data(data: YAML.dump(@document.merge(external: true)), yubikey: {})
    expect do
      described_class.update(file: @path) do |cfg|
        File.binwrite(@path, replacement)
        cfg[:stale] = true
      end
    end.to raise_error(IOError, /changed before replacement/)
    expect(File.binread(@path)).to eq(replacement)
    expect(Dir.children(@root)).to eq(['vault'])
  end

  it 'recognizes directory aliases when reentering its own publication lock' do
    prepare_vault
    sibling = File.join(@root, 'sibling')
    File.binwrite(sibling, File.binread(@path))
    File.symlink(@root, File.join(@root, 'alias'))
    Timeout.timeout(5) do
      described_class.update(file: @path) do |cfg|
        described_class.update(file: File.join(@root, 'alias', 'sibling')) { |other| other[:aliased] = true }
        cfg[:outer] = true
      end
    end
    expect(described_class.dump(file: sibling)).to eq(@document.merge(aliased: true))
    expect(described_class.dump(file: @path)).to eq(@document.merge(outer: true))
  end

  it 'does not treat a lock inherited across fork as owned by the child' do
    prepare_vault
    reader, writer = IO.pipe
    pid = nil
    Timeout.timeout(8) do
      described_class.update(file: @path) do |cfg|
        pid = fork do
          reader.close
          allow(File).to receive(:open).and_wrap_original do |open, *args, **kwargs, &block|
            if args == [@root, File::RDONLY]
              open.call(*args) do |lock|
                allow(lock).to receive(:flock).and_wrap_original do |flock, operation|
                  if operation == File::LOCK_EX
                    acquired = flock.call(operation | File::LOCK_NB)
                    writer.puts(acquired ? 'acquired' : 'blocked')
                    acquired || flock.call(operation)
                  else
                    flock.call(operation)
                  end
                end
                block.call(lock)
              end
            else
              open.call(*args, **kwargs, &block)
            end
          end
          begin
            described_class.update(file: @path) { |child| child[:child] = true }
            writer.puts('saved')
            exit! 0
          rescue StandardError, RSpec::Mocks::MockExpectationError
            writer.puts('failed')
            exit! 1
          end
        end
        writer.close
        expect(reader.gets).to eq("blocked\n")
        cfg[:parent] = true
      end
      expect(reader.gets).to eq("saved\n")
      _, status = Process.waitpid2(pid)
      pid = nil
      expect(status.success?).to be(true)
    end
    expect(described_class.dump(file: @path)).to eq(@document.merge(parent: true, child: true))
  ensure
    if pid
      Process.kill('KILL', pid)
      Process.waitpid(pid)
    end
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end

  it 'preserves original ciphertext and removes staging files when publication fails' do
    prepare_vault
    original = File.binread(@path)
    allow(File).to receive(:rename).and_raise(IOError, 'fixture rename failure')
    expect { described_class.update(file: @path) { |cfg| cfg[:changed] = true } }.to raise_error(IOError, 'fixture rename failure')
    expect(File.binread(@path)).to eq(original)
    expect(Dir.children(@root)).to eq(['vault'])
  end
end
