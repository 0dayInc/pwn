# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe 'Sandbox isolation' do
  it 'executes a real safe fixture through a native Ruby worker' do
    require 'pwn/plugins/sandbox'
    expect(Open3).not_to receive(:capture3).with('/usr/bin/python3', any_args)
    result = PWN::Plugins::Sandbox.run(binary: '/bin/true', backend: 'bwrap', timeout: 2)
    expect(result).to include(ok: true, exit: 0, network: 'none', artifact_mount: 'ro')
    expect(result[:strace]).to include('execve')
  end

  it 'triages a real isolated crash with GDB without shell argument injection' do
    Dir.mktmpdir('pwn-gdb-marker-') do |dir|
      marker = File.join(dir, 'marker')
      result = PWN::Plugins::Sandbox.run(binary: '/bin/sh', backend: 'bwrap', argv: ['-c', 'kill -SEGV $$', "$(touch #{marker})"], timeout: 2, memory_mb: 1024)
      expect(result).to include(ok: true, signal: 'SIGSEGV')
      expect(result[:gdb]).to include('SIGSEGV')
      expect(result[:backtrace]).not_to be_empty
      expect(result[:faulting_address]).to match(/\A0x/)
      expect(File.exist?(marker)).to be(false)
    end
  end

  it 'snapshots input, rolls it back in isolation and rejects tampering' do
    Dir.mktmpdir do |home|
      original = Dir.home
      ENV['HOME'] = home
      saved = PWN::Plugins::Sandbox.snapshot(binary: '/bin/true')
      expect(saved[:ok]).to be(true)
      expect(saved[:sha256]).to eq(Digest::SHA256.file('/bin/true').hexdigest)
      expect(PWN::Plugins::Sandbox.rollback(snapshot: saved[:snapshot], backend: 'bwrap')).to include(ok: true, exit: 0)
      File.chmod(0o700, File.join(saved[:snapshot], 'target'))
      File.binwrite(File.join(saved[:snapshot], 'target'), 'tampered')
      expect(PWN::Plugins::Sandbox.rollback(snapshot: saved[:snapshot], backend: 'bwrap')).to include(ok: false, error: 'snapshot integrity failure')
    ensure
      ENV['HOME'] = original
    end
  end

  it 'reproduces seeded byte-exact fuzz crashes in real isolated workers' do
    Dir.mktmpdir do |corpus|
      File.binwrite(File.join(corpus, 'seed'), "\xff".b)
      options = { target: '/bin/sh', argv: ['-c', 'kill -SEGV $$'], backend: 'bwrap', corpus: corpus, minutes: 0.003, seed: 42, timeout: 0.02 }
      File.binwrite(File.join(corpus, 'seed'), '')
      empty = PWN::Plugins::Sandbox.fuzz(options)
      expect(empty[:ok]).to be(true)
      expect(Base64.strict_decode64(empty[:crashes].first[:input_base64]).bytesize).to eq(1)
      File.binwrite(File.join(corpus, 'seed'), "\xff".b)
      first = PWN::Plugins::Sandbox.fuzz(options)
      second = PWN::Plugins::Sandbox.fuzz(options)
      expect(first).to include(ok: true, seed: 42)
      expect(first[:iterations]).to be > 0
      input = first[:crashes].first.fetch(:input_base64)
      expect(second[:crashes].first[:input_base64]).to eq(input)
      byte = Base64.strict_decode64(input).bytes.fetch(0)
      expect((byte ^ 255).digits(2).sum).to eq(1)
    end
  end

  it 'hides home, makes artifacts read-only and has no network route' do
    result = PWN::Plugins::Sandbox.run(binary: '/bin/sh', backend: 'bwrap', timeout: 2,
                                       argv: ['-c', 'test ! -e /home && ! touch /artifacts/new && cat /proc/net/route && cat /proc/self/limits'])
    expect(result).to include(ok: true, exit: 0)
    expect(result[:stderr]).to include('Read-only file system')
    expect(result[:stdout]).to include('Max address space', '268435456', 'Max core file size')
    expect(result[:stdout]).not_to match(/^eth\d/)
  end

  it 'times out and removes its disposable artifact directory' do
    artifact_path = nil
    allow(Dir).to receive(:mktmpdir).and_call_original
    expect(Dir).to receive(:mktmpdir).with('pwn-sandbox-').and_wrap_original do |original, *args, &block|
      original.call(*args) do |path|
        artifact_path = path
        block.call(path)
      end
    end
    result = PWN::Plugins::Sandbox.run(binary: '/bin/sleep', backend: 'bwrap', argv: ['5'], timeout: 0.1)
    expect(result).to include(ok: true, timed_out: true, signal: 'SIGKILL')
    expect(artifact_path).not_to be_nil
    expect(File).not_to exist(artifact_path)
  end

  it 'rejects malformed arguments and resource budgets' do
    [{ timeout: 0 }, { timeout: 301 }, { memory_mb: 31 }, { memory_mb: 4097 }, { argv: 'bad' }, { argv: ["a\0b"] }].each do |invalid|
      expect(PWN::Plugins::Sandbox.run({ binary: '/bin/true', backend: 'bwrap' }.merge(invalid))[:ok]).to be(false)
    end
  end

  it 'runs the standalone Ruby controller in a fresh process' do
    runner = File.expand_path('../../../../lib/pwn/plugins/sandbox/driver.rb', __dir__)
    output, error, status = Open3.capture3(RbConfig.ruby, runner, stdin_data: JSON.generate(binary: '/bin/true', backend: 'bwrap'))
    expect(status.success?).to be(true), error
    expect(JSON.parse(output)).to include('ok' => true, 'exit' => 0)
  end

  it 'fails closed when Docker is missing' do
    original = ENV.fetch('PATH', '')
    ENV['PATH'] = ''
    result = PWN::Plugins::Sandbox.run(binary: '/bin/true')
    expect(result).to include(ok: false, error: 'sandbox backend unavailable: docker')
  ensure
    ENV['PATH'] = original
  end

  it 'keeps target stdin a byte-exact pipe' do
    result = PWN::Plugins::Sandbox.run(binary: '/bin/sh', backend: 'bwrap', stdin_base64: Base64.strict_encode64("\xff\x00".b),
                                       argv: ['-c', 'test -p /proc/self/fd/0 && od -An -tx1'])
    expect(result).to include(ok: true, exit: 0)
    expect(result[:stdout].strip).to eq('ff 00')
  end

  it 'registers runnable sandbox tools' do
    require 'pwn/ai/agent/tools/sandbox'
    entry = PWN::AI::Agent::Registry.lookup(name: 'sandbox_run')
    expect(entry.schema[:parameters][:required]).to include('binary')
    result = entry.handler.call('binary' => '/bin/true', 'backend' => 'not-a-backend')
    expect(result[:ok]).to eq(false)
    expect(PWN::AI::Agent::Registry.lookup(name: 'sandbox_fuzz')).not_to be_nil
  end
  it 'fails closed for an unavailable backend without executing the target' do
    require 'pwn/plugins/sandbox'
    result = PWN::Plugins::Sandbox.run(binary: '/bin/true', backend: 'not-a-backend')
    expect(result[:ok]).to eq(false)
    expect(result[:error]).to include('backend')
  end
end
