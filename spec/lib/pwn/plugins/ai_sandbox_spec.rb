# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'json'
require 'tmpdir'

describe PWN::Plugins::AISandbox do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'enforces read-only roots in real workers while preserving outside writes and host cwd' do
    Dir.mktmpdir('pwn-boundary') do |root|
      protected = File.join(root, 'source')
      workspace = File.join(root, 'work')
      FileUtils.mkdir_p([protected, workspace])
      target = File.join(protected, 'keep')
      File.write(target, 'original')
      File.symlink(protected, File.join(workspace, 'alias'))
      cwd = Dir.pwd
      result = described_class.protect_call(roots: [protected], workspace: workspace, write_roots: [File.join(workspace, 'outside.txt')]) do
        errors = [target, File.join(workspace, 'alias', 'keep'), File.join(protected, '..', 'source', 'new')].map do |path|
          File.write(path, 'bad')
          'allowed'
        rescue Errno::EACCES, Errno::EPERM
          'denied'
        end
        File.write('outside.txt', 'allowed')
        { errors: errors, original: File.read(target), cwd: Dir.pwd }
      end
      expect(result).to include(errors: %w[denied denied denied], original: 'original', cwd: workspace)
      expect(File.read(File.join(workspace, 'outside.txt'))).to eq('allowed')
      expect(File.read(target)).to eq('original')
      metadata = described_class.protect_call(roots: [protected], workspace: workspace) do
        File.chmod(0o600, target)
        { changed: true }
      end
      expect(metadata[:success]).to be false
      expect(metadata[:error]).to match(/Read-only file system|Permission denied|Operation not permitted/)
      expect(Dir.pwd).to eq(cwd)
    end
  end

  it 'writes only in the runtime workspace unless the original request names another path' do
    Dir.mktmpdir('pwn-boundary') do |root|
      source = File.join(root, 'source')
      workspace = File.join(root, 'runtime')
      named = File.join(root, 'named', 'report.txt')
      FileUtils.mkdir_p([source, workspace])
      File.write(File.join(source, 'keep'), 'original')
      outside = File.join(root, 'unstated.txt')
      result = described_class.protect_call(roots: [source], workspace: workspace, write_roots: [named, File.join(source, 'keep')]) do
        File.write(named, 'allowed')
        unstated = begin
          File.write(outside, 'no')
          'allowed'
        rescue Errno::EACCES, Errno::EPERM
          'denied'
        end
        protected_write = begin
          File.write(File.join(source, 'keep'), 'bad')
          'allowed'
        rescue Errno::EACCES, Errno::EPERM
          'denied'
        end
        { named: File.read(named), unstated: unstated, protected_write: protected_write }
      end
      expect(result).to include(named: 'allowed', unstated: 'denied', protected_write: 'denied')
      expect(File.read(File.join(source, 'keep'))).to eq('original')
      expect(described_class.workspace).to eq(File.expand_path(File.join(Dir.home, '.pwn', 'workspaces', 'runtime')))
      Dir.chdir(root) { expect(described_class.workspace).to eq(File.expand_path(File.join(Dir.home, '.pwn', 'workspaces', 'runtime'))) }
    end
  end

  it 'allows mv onto an extensionless destination named by the original request' do
    Dir.mktmpdir('pwn-boundary') do |root|
      source = File.join(root, 'source')
      workspace = File.join(root, 'runtime')
      dest_dir = File.join(root, 'dest')
      FileUtils.mkdir_p([source, workspace, dest_dir])
      destination = File.join(dest_dir, 'test')
      result = described_class.protect_call(roots: [source], workspace: workspace, write_roots: [workspace, destination]) do
        File.write('foo', 'data')
        moved = begin
          File.rename('foo', destination)
          'allowed'
        rescue Errno::EACCES, Errno::EPERM
          'denied'
        end
        { moved: moved, body: File.read(destination), still_dir: File.directory?(destination) }
      end
      expect(result).to include(moved: 'allowed', body: 'data', still_dir: false)
    end
  end

  it 'creates a named file when the destination parent contains an unreadable directory' do
    Dir.mktmpdir('pwn-boundary') do |root|
      source = File.join(root, 'source')
      workspace = File.join(root, 'runtime')
      parent = File.join(root, 'dest')
      hidden = File.join(parent, 'private')
      destination = File.join(parent, 'test')
      FileUtils.mkdir_p([source, workspace, parent, hidden])
      File.chmod(0, hidden)
      result = described_class.protect_call(roots: [source], workspace: workspace, write_roots: [destination]) do
        created = begin
          File.write(destination, 'data')
          'allowed'
        rescue Errno::EACCES, Errno::EPERM
          'denied'
        end
        body = File.read(destination) if created == 'allowed'
        { created: created, body: body }
      end
      expect(result).to include(created: 'allowed', body: 'data')
    ensure
      File.chmod(0o700, hidden) if hidden && File.directory?(hidden)
    end
  end

  it 'fails closed on unsupported kernels and existing external hardlink aliases' do
    Dir.mktmpdir('pwn-boundary') do |root|
      source = File.join(root, 'source')
      work = File.join(root, 'work')
      FileUtils.mkdir_p([source, work])
      path = File.join(source, 'protected')
      File.write(path, 'original')
      File.link(path, File.join(work, 'alias'))
      result = described_class.protect_call(roots: [source], workspace: work) { File.write(File.join(work, 'alias'), 'bad') }
      expect(result[:success]).to be false
      expect(File.read(path)).to eq('original')
      File.unlink(File.join(work, 'alias'))
      allow(described_class).to receive(:repository_restrict!).and_raise(NotImplementedError, 'kernel unsupported')
      expect { described_class.protect_call(roots: [source], workspace: work) { File.write(path, 'bad') } }.to raise_error(described_class::NotStarted, /kernel unsupported/)
      expect(File.read(path)).to eq('original')
    end
  end

  it 'keeps nested dispatch and detached subprocesses inside the inherited boundary' do
    Dir.mktmpdir('pwn-boundary') do |root|
      source = File.join(root, 'source')
      work = File.join(root, 'work')
      FileUtils.mkdir_p([source, work])
      path = File.join(source, 'protected')
      File.write(path, 'original')
      jobs = File.join(work, 'jobs')
      stub_const('PWN::Plugins::Jobs::JOBS_DIR', jobs)
      result = described_class.protect_call(roots: [source], workspace: work, write_roots: [work]) do
        PWN::AI::Agent::Registry.register(name: 'nested_boundary_fixture', toolset: 'test', schema: { name: 'nested_boundary_fixture', parameters: { type: 'object' } }, handler: ->(_args) { File.write(path, 'bad') })
        nested = JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'nested_boundary_fixture', arguments: '{}' } }))
        job = PWN::Plugins::Jobs.start(command: "printf bad > #{path}; printf done > #{work}/done", max_runtime: 10)
        { nested: nested, job: job }
      end
      expect(result.dig(:nested, :success)).to be(false), result.inspect
      expect(result.dig(:job, :id)).to be_a(String), result.inspect
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
      sleep 0.02 until File.exist?(File.join(work, 'done')) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      expect(File.read(File.join(work, 'done'))).to eq('done')
      expect(File.read(path)).to eq('original')
    end
  end

  it 'protects controller writes after a worker redirects checkpoint ancestry' do
    Dir.mktmpdir('pwn-controller-boundary') do |root|
      source = File.join(root, 'source')
      work = File.join(root, 'work')
      FileUtils.mkdir_p([source, work])
      script = <<~RUBY
        require 'pwn'
        require 'json'
        source, work = ARGV
        PWN::Plugins::AISandbox.define_singleton_method(:protected_roots) { [source, '/opt/pwn'] }
        runtime = PWN::AI::Agent::RequestRuntime.new(request: 'Create a report', session_id: 'boundary', artifact_root: File.join(work, 'state'), trace: false, retrieve: false)
        Thread.current[:pwn_request_runtime] = runtime
        directory = File.dirname(runtime.checkpoint_path)
        PWN::AI::Agent::Registry.register(name: 'boundary_fixture', toolset: 'fixture', schema: { name: 'boundary_fixture', parameters: { type: 'object' } }, handler: lambda { |_args|
          FileUtils.rm_rf(directory)
          File.symlink(source, directory)
          { redirected: true }
        })
        result = JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'boundary_fixture', arguments: '{}' } }))
        puts JSON.generate(changed: !Dir.children(source).empty?, result: result)
      RUBY
      command = [RbConfig.ruby, '-I', File.expand_path('lib'), '-e', script, source, work]
      stdout, stderr, status = Open3.capture3({ 'HOME' => work }, *command)
      expect(status.success?).to be(true), stderr
      row = JSON.parse(stdout)
      expect(row['changed']).to be(false), row.inspect
      expect(row.dig('result', 'success')).to be(false)
      expect(Dir.children(source)).to be_empty
    end
  end

  it 'brokers actual spawn and ask without granting state redirection or handler bypass' do
    Dir.mktmpdir('pwn-swarm-control') do |root|
      work = File.join(root, 'work')
      home = File.join(root, 'home')
      FileUtils.mkdir_p([work, home])
      tool = lambda do |command, id|
        { role: 'assistant', content: '', tool_calls: [{ id: id, type: 'function', function: { name: 'shell', arguments: JSON.generate(command: command, timeout: 10) } }] }
      end
      fixture = File.join(work, 'provider.json')
      File.write(fixture, JSON.generate(toolsets: %w[shell swarm], responses: [tool.call("printf 'alpha\\n' > result.txt", 'write'), tool.call('cat result.txt', 'read')] + Array.new(8) { { role: 'assistant', content: 'FIXTURE_COMPLETE', tool_calls: [] } }))
      env = { 'HOME' => home, 'PWN_HARNESS_FIXTURE' => fixture, 'PWN_HARNESS_EVENTS' => File.join(work, 'events.jsonl'), 'PWN_HARNESS_FINGERPRINT' => File.join(work, 'fingerprint.json') }
      command = [RbConfig.ruby, '-I', File.expand_path('lib'), '-r', File.expand_path('spec/support/harness/fake_provider.rb'), File.expand_path('spec/support/harness/swarm_control.rb'), work]
      stdout, stderr, status = Open3.capture3(env, *command, chdir: work)
      expect(status.success?).to be(true), "#{stderr}\n#{stdout}"
      row = JSON.parse(stdout.lines.last)
      expect(row.dig('spawn', 'success')).to be(true), row.inspect
      expect(row.dig('ask', 'success')).to be(true), row.inspect
      expect(row.dig('ask', 'result', 'reply')).to eq('FIXTURE_COMPLETE')
      expect(row['bytes']).to eq("alpha\n")
      expect(row['sentinel']).to eq('unchanged')
      expect(row.dig('attack', 'result').values).to all(start_with('denied:'))
      expect(row.dig('replacement', 'success')).to be(false)
      expect(row.dig('observations', File.join(work, 'result.txt'), 'child_request_id')).to be_a(String)
      persisted = YAML.safe_load_file(File.join(home, '.pwn', 'agents.yml'))
      expect(persisted.fetch('fixture_worker').fetch('model')).to eq('offline-scripted-v1')
    end
  end

  it 'uses aarch64 directory open bits instead of the x86_64 O_DIRECT bit' do
    aarch64 = described_class.send(:directory_open_flags, platform: 'aarch64-linux')
    x86_64 = described_class.send(:directory_open_flags, platform: 'x86_64-linux')
    expect(aarch64.anybits?(1 << 14)).to be(true)
    expect(aarch64.anybits?(1 << 16)).to be(false)
    expect(x86_64.anybits?(1 << 16)).to be(true)
    expect(x86_64.anybits?(1 << 14)).to be(false)
  end

  it 'pins controller directories across pathname replacement and rejects source ancestry' do
    Dir.mktmpdir('pwn-control-fd') do |root|
      source = File.join(root, 'source')
      state = File.join(root, 'state')
      moved = File.join(root, 'moved')
      FileUtils.mkdir_p([source, state])
      allow(described_class).to receive(:protected_roots).and_return([source])
      described_class.control_directory(path: state) do |fd_path|
        File.rename(state, moved)
        File.symlink(source, state)
        File.open(File.join(fd_path, 'receipt'), File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write('safe') }
      end
      expect(File.read(File.join(moved, 'receipt'))).to eq('safe')
      expect(Dir.children(source)).to be_empty
      expect { described_class.control_directory(path: state) { raise 'must not run' } }.to raise_error(Errno::ENOTDIR)
      expect { described_class.control_directory(path: File.join(source, 'new')) { raise 'must not run' } }.to raise_error(described_class::NotStarted, /protected source/)
      expect(Dir.children(source)).to be_empty
    end
  end

  it 'denies rm -rf /tmp/fake_root in strict mode without touching disk' do
    root = '/tmp/fake_root'
    FileUtils.mkdir_p(root)
    marker = File.join(root, 'keep')
    File.write(marker, 'safe')
    begin
      out = described_class.exec(kind: :shell, payload: 'rm -rf /tmp/fake_root', mode: 'strict')
      expect(out[:error].to_s).to match(/sandbox violation/i)
      expect(File.file?(marker)).to be true
    ensure
      FileUtils.rm_rf(root)
    end
  end

  it 'denies FileUtils.rm_rf("/tmp/fake_root") in strict mode without touching disk' do
    root = '/tmp/fake_root'
    FileUtils.mkdir_p(root)
    marker = File.join(root, 'keep')
    File.write(marker, 'safe')
    begin
      out = described_class.exec(kind: :ruby, payload: "FileUtils.rm_rf('/tmp/fake_root')", mode: 'strict')
      expect(out[:error].to_s).to match(/sandbox violation/i)
      expect(File.file?(marker)).to be true
    ensure
      FileUtils.rm_rf(root)
    end
  end
end
