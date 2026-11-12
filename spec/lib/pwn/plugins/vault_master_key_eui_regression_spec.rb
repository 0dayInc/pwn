# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

RSpec.describe PWN::Plugins::Vault, 'EUI-SEC-001 software master key safety' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @key_path = File.join(@tmp, '.pwn-vault.key')
    @box_path = File.join(@tmp, '.pwn', 'engagements', 'default', 'loot.json')
  end

  def expect_key_rejected
    ciphertext = File.binread(@box_path)
    allow(OpenSSL::Random).to receive(:random_bytes).and_call_original
    expect(OpenSSL::Random).not_to receive(:random_bytes).with(32)
    expect { described_class.store(label: 'original', secret: 'synthetic-replacement') }.to raise_error(IOError, /software vault master key/) do |error|
      expect(error.cause).to be_nil
    end
    expect { described_class.fetch(label: 'original') }.to raise_error(IOError, /software vault master key/)
    expect(File.binread(@box_path) == ciphertext).to be(true)
  end

  [0o644, 0o640, 0o660, 0o700, 0o4600, 0o000].each do |mode|
    it "rejects existing key permissions #{mode.to_s(8)} without repair or ciphertext loss" do
      described_class.store(label: 'original', secret: 'synthetic-original')
      key = File.binread(@key_path)
      File.chmod(mode, @key_path)
      expect_key_rejected
      expect(File.stat(@key_path).mode & 0o7777).to eq(mode)
      File.chmod(0o600, @key_path)
      expect(File.binread(@key_path) == key).to be(true)
      expect(described_class.fetch(label: 'original') == 'synthetic-original').to be(true)
    end
  end

  [0, 31, 33, 1_048_576].each do |size|
    it "rejects an existing #{size}-byte key without silently replacing it" do
      described_class.store(label: 'original', secret: 'synthetic-original')
      File.binwrite(@key_path, 'k' * size)
      expect_key_rejected
      expect(File.size(@key_path)).to eq(size)
    end
  end

  %w[symlink directory fifo hardlink].each do |kind|
    it "rejects an existing #{kind} key before reading or modifying it" do
      described_class.store(label: 'original', secret: 'synthetic-original')
      saved = File.join(@tmp, 'saved-key')
      File.rename(@key_path, saved)
      case kind
      when 'symlink' then File.symlink(saved, @key_path)
      when 'directory' then Dir.mkdir(@key_path)
      when 'fifo' then File.mkfifo(@key_path, 0o600)
      when 'hardlink' then File.link(saved, @key_path)
      end
      before = File.lstat(@key_path)
      Timeout.timeout(2) { expect_key_rejected }
      expect(File.lstat(@key_path).ino).to eq(before.ino)
      expect(File.lstat(@key_path).ftype).to eq(before.ftype)
    end
  end

  it 'rejects foreign ownership metadata before reading the existing key' do
    described_class.store(label: 'original', secret: 'synthetic-original')
    allow(Process).to receive(:uid).and_return(Process.uid + 1)
    expect_key_rejected
  end

  %w[default another].each do |engagement|
    it "refuses to recreate a missing key used by existing #{engagement} ciphertext" do
      described_class.store(engagement: engagement, label: 'original', secret: 'synthetic-original')
      path = File.join(@tmp, '.pwn', 'engagements', engagement, 'loot.json')
      ciphertext = File.binread(path)
      File.unlink(@key_path)
      expect { described_class.store(label: 'new', secret: 'synthetic-new') }.to raise_error(IOError, /software vault master key/)
      expect { described_class.fetch(engagement: engagement, label: 'original') }.to raise_error(IOError, /software vault master key/)
      expect(File).not_to exist(@key_path)
      expect(File.binread(path) == ciphertext).to be(true)
    end
  end

  def stop_vault_child(pid)
    Process.kill('KILL', pid)
  rescue Errno::ESRCH
    nil
  ensure
    begin
      Process.wait(pid)
    rescue Errno::ECHILD
      nil
    end
  end

  def vault_child(&operation)
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      begin
        writer.puts(JSON.generate(operation.call))
        exit! 0
      rescue StandardError, Interrupt => e
        writer.puts(JSON.generate(child_error: e.class.name))
        exit! 1
      end
    end
    writer.close
    result = JSON.parse(Timeout.timeout(10) { reader.read }, symbolize_names: true)
    _, status = Process.wait2(pid)
    pid = nil
    expect(status.success?).to be(true), result.inspect
    result
  ensure
    stop_vault_child(pid) if pid
    [reader, writer].compact.each { |io| io.close unless io.closed? }
  end

  [Interrupt, IOError].each do |failure|
    it "cleans private staging on #{failure} before publication and allows public store retry" do
      observed = vault_child do
        File.umask(0o022)
        modes = []
        allow(OpenSSL::Random).to receive(:random_bytes).and_call_original
        allow(OpenSSL::Random).to receive(:random_bytes).with(32) do
          modes = Dir.glob(File.join(@tmp, '.pwn-vault-key-*')).map { |path| File.stat(path).mode & 0o777 }
          raise failure, 'synthetic-private-error-marker'
        end
        begin
          described_class.store(label: 'cancelled', secret: 'synthetic-cancelled')
        rescue Interrupt, IOError => e
          safe = e.is_a?(Interrupt) || (!e.message.include?('synthetic-private-error-marker') && e.cause.nil?)
          caught = e.is_a?(failure)
        end
        absent = !File.exist?(@key_path) && !File.exist?(@box_path)
        cleaned = Dir.glob(File.join(@tmp, '.pwn-vault-key-*')).empty?
        allow(OpenSSL::Random).to receive(:random_bytes).with(32).and_call_original
        retry_result = described_class.store(label: 'retry', secret: 'synthetic-retry')
        { modes: modes, caught: caught, safe: safe, absent: absent, cleaned: cleaned, stored: retry_result[:stored],
          roundtrip: described_class.fetch(label: 'retry') == 'synthetic-retry' }
      end
      expect(observed).to eq(modes: [0o600], caught: true, safe: true, absent: true, cleaned: true, stored: true, roundtrip: true)
    end
  end

  it 'retains a complete key after a publication error without exposing the cause or rotating it' do
    allow(File).to receive(:link).and_wrap_original do |method, source, destination|
      method.call(source, destination)
      raise IOError, 'synthetic-private-error-marker' if destination == @key_path
    end
    expect { described_class.store(label: 'failed', secret: 'synthetic-failed') }.to raise_error(IOError, /software vault master key/) do |error|
      expect(error.message).not_to include('synthetic-private-error-marker')
      expect(error.cause).to be_nil
    end
    expect(File.stat(@key_path).mode & 0o777).to eq(0o600)
    expect(Dir.glob(File.join(@tmp, '.pwn-vault-key-*'))).to be_empty
    key = File.binread(@key_path)
    described_class.store(label: 'retry', secret: 'synthetic-retry')
    expect(File.binread(@key_path) == key).to be(true)
    expect(described_class.fetch(label: 'retry') == 'synthetic-retry').to be(true)
  end

  it 'serializes two public creators across processes and preserves every ciphertext' do
    children = []
    start_r, start_w = IO.pipe
    result_r, result_w = IO.pipe
    2.times do |index|
      children << fork do
        start_w.close
        result_r.close
        begin
          File.umask(0o022)
          start_r.read(1)
          3.times do |number|
            described_class.store(engagement: "group#{index}", label: "item#{number}", secret: "synthetic-#{index}-#{number}")
          end
          result_w.puts(JSON.generate(index: index, stored: true))
          exit! 0
        rescue StandardError, Interrupt => e
          result_w.puts(JSON.generate(index: index, error: e.class.name))
          exit! 1
        end
      end
    end
    start_r.close
    result_w.close
    start_w.write('go')
    start_w.close
    records = Timeout.timeout(10) { result_r.read.lines.map { |line| JSON.parse(line, symbolize_names: true) } }
    statuses = children.map { |pid| Process.wait2(pid)[1] }
    children.clear
    expect(records).to contain_exactly({ index: 0, stored: true }, { index: 1, stored: true })
    expect(statuses.all?(&:success?)).to be(true)
    2.times do |index|
      expect(described_class.query(engagement: "group#{index}").size).to eq(3)
      3.times do |number|
        expect(described_class.fetch(engagement: "group#{index}", label: "item#{number}") == "synthetic-#{index}-#{number}").to be(true)
      end
    end
    expect(File.stat(@key_path).mode & 0o777).to eq(0o600)
  ensure
    children&.each { |pid| stop_vault_child(pid) }
    [start_r, start_w, result_r, result_w].compact.each { |io| io.close unless io.closed? }
  end

  it 'publishes a private key under child umask 022 even when cancelled at first visibility' do
    observed = vault_child do
      File.umask(0o022)
      File.chmod(0o755, @tmp)
      mode = nil
      interrupted = false
      # Interrupt on the first completed native operation exposing the final
      # key path, before any later chmod can conceal unsafe creation modes.
      trace = TracePoint.new(:c_return) do
        next unless File.exist?(@key_path)

        trace.disable
        mode = File.stat(@key_path).mode & 0o777
        raise Interrupt
      end
      begin
        trace.enable { described_class.store(label: 'cancelled', secret: 'synthetic-cancelled') }
      rescue Interrupt
        interrupted = true
      ensure
        trace.disable
      end
      key = File.binread(@key_path)
      stored = described_class.store(label: 'retry', secret: 'synthetic-retry')
      {
        interrupted: interrupted, mode_at_publication: mode,
        retry_stored: stored[:stored], same_key: File.binread(@key_path) == key,
        retry_mode: File.stat(@key_path).mode & 0o777,
        roundtrip: described_class.fetch(label: 'retry') == 'synthetic-retry',
        labels: described_class.query.map { |row| row[:label] }
      }
    end
    expect(observed).to eq(interrupted: true, mode_at_publication: 0o600, retry_stored: true,
                           same_key: true, retry_mode: 0o600, roundtrip: true, labels: ['retry'])
  end
end
