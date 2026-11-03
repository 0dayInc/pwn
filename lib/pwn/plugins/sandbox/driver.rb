# frozen_string_literal: true

require 'base64'
require 'digest'
require 'fileutils'
require 'json'
require 'securerandom'
require 'shellwords'
require 'tempfile'
require 'tmpdir'

# Standalone stdlib controller; target execution occurs only in the worker.
module PWNSandboxDriver
  public_class_method def self.authors
    'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
  end

  public_class_method def self.help
    puts "Internal standalone Ruby sandbox controller/worker; use PWN::Plugins::Sandbox for the supported API.
      # Print the module author information.
      #{self}.authors"
  end

  class << self
    def available?(name)
      ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, name)) }
    end

    def bounded(command, seconds, input = '', memory = nil)
      Tempfile.create('pwn-out') do |out|
        Tempfile.create('pwn-err') do |err|
          source, sink = IO.pipe
          begin
            source.binmode
            sink.binmode
            limits = { pgroup: true, in: source, out: out, err: err, rlimit_fsize: [8 * 1024 * 1024] * 2, rlimit_core: [0, 0] }
            limits[:rlimit_as] = [memory * 1024 * 1024] * 2 if memory
            pid = Process.spawn(*command, **limits)
            source.close
            writer = Thread.new do
              sink.write(input)
            rescue Errno::EPIPE, IOError
              nil
            ensure
              sink.close unless sink.closed?
            end
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
            expired = false
            status = nil
            loop do
              waited = Process.waitpid2(pid, Process::WNOHANG)
              if waited
                status = waited.last
                break
              end
              if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
                expired = true
                Process.kill('KILL', -pid)
                status = Process.waitpid2(pid).last
                break
              end
              sleep 0.005
            end
            { exit: status.signaled? ? -status.termsig : status.exitstatus,
              stdout: File.binread(out.path, 65_536).to_s.dup.force_encoding('UTF-8').scrub,
              stderr: File.binread(err.path, 65_536).to_s.dup.force_encoding('UTF-8').scrub, timed_out: expired }
          ensure
            source.close unless source.closed?
            writer&.kill
            writer&.join(1)
            sink.close unless sink.closed?
            if pid
              begin
                Process.kill('KILL', -pid)
              rescue Errno::ESRCH
                nil
              end
              begin
                Process.waitpid(pid)
              rescue Errno::ECHILD
                nil
              end
            end
          end
        end
      end
    end

    def inside(request)
      command = ['/artifacts/target'] + request.fetch(:argv, [])
      data = Base64.strict_decode64(request.fetch(:input))
      seconds = request.fetch(:timeout)
      memory = request.fetch(:memory_mb)
      result = bounded(command, seconds, data, memory)
      sig = result[:exit].negative? ? Signal.signame(-result[:exit]) : nil
      result.merge!(ok: true, signal: sig && "SIG#{sig}", faulting_address: nil, backtrace: [], exploitability: 'unknown')
      if available?('strace')
        result[:strace] = bounded(['strace', '-f', '-qq', '-s', '128', '--'] + command, seconds, data, memory)[:stderr]
      else
        result[:strace_error] = 'strace unavailable in sandbox image'
      end
      if sig && available?('gdb')
        File.binwrite('/tmp/pwn-input', data)
        run = "run #{command.drop(1).shelljoin} < /tmp/pwn-input"
        replay = bounded(['gdb', '-q', '-nx', '-nh', '-batch', '-iex', 'set auto-load off', '-ex', run,
                          '-ex', 'p/x $pc', '-ex', 'bt', '-ex', 'exploitable', '--args', command.first], seconds, '', memory)
        text = replay[:stdout] + replay[:stderr]
        result[:gdb] = text
        result[:faulting_address] = text[/\$\d+ = (0x[0-9a-f]+)/, 1]
        result[:backtrace] = text.lines.map(&:chomp).grep(/\A#\d+\s/)
        result[:exploitability] = text[/Exploitability Classification:\s*(\S+)/, 1] || 'unknown: GDB exploitable plugin unavailable or failed'
      elsif sig
        result[:gdb_error] = 'gdb unavailable in sandbox image'
      end
      result
    end
  end

  # Host-side orchestration never launches a target outside a backend.
  class << self
    def execute(request)
      backend = request.fetch(:backend, 'docker')
      raise ArgumentError, "sandbox backend unavailable: #{backend}" unless %w[docker bwrap].include?(backend) && available?(backend)

      if backend == 'docker'
        probe = bounded(['docker', 'info', '--format', '{{.ServerVersion}}'], 10)
        raise ArgumentError, "docker backend unavailable: #{probe[:stderr]}" unless probe[:exit].zero?
      end
      seconds = Float(request.fetch(:timeout, 10))
      memory = Integer(request.fetch(:memory_mb, 256))
      raise ArgumentError, 'timeout or memory budget out of range' unless seconds.positive? && seconds <= 300 && memory.between?(32, 4096)

      argv = request.fetch(:argv, [])
      raise ArgumentError, 'argv must be an array of strings without NUL' unless argv.is_a?(Array) && argv.all? { |arg| arg.is_a?(String) && !arg.include?("\0") }

      binary = File.realpath(request.fetch(:binary))
      raise ArgumentError, 'binary must be a regular file' unless File.file?(binary)

      Dir.mktmpdir('pwn-sandbox-') do |artifacts|
        FileUtils.copy_file(binary, File.join(artifacts, 'target'))
        File.chmod(0o555, File.join(artifacts, 'target'))
        FileUtils.copy_file(__FILE__, File.join(artifacts, 'worker.rb'))
        payload = request.merge(timeout: seconds, memory_mb: memory, input: request.fetch(:stdin_base64) { Base64.strict_encode64(request.fetch(:stdin, '')) })
        container = "pwn-sandbox-#{SecureRandom.hex(16)}"
        if backend == 'docker'
          image = request.fetch(:image, 'pwn-sandbox:local')
          raise ArgumentError, 'invalid image' unless %r{\A[a-zA-Z0-9][a-zA-Z0-9_./:@-]*\z}.match?(image)

          File.chmod(0o755, artifacts)
          command = ['docker', 'run', '--rm', '--pull=never', '--name', container, '-i', '--network=none', '--read-only', '--cap-drop=ALL',
                     '--security-opt=no-new-privileges', '--pids-limit=64', '--memory', "#{memory}m", '--memory-swap', "#{memory}m",
                     '--cpus=1', '--user=65534:65534', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
                     '--mount', "type=bind,src=#{artifacts},dst=/artifacts,readonly", '--entrypoint=/usr/bin/ruby', image, '/artifacts/worker.rb', '--inside']
        else
          command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--ro-bind', '/usr', '/usr']
          %w[/lib /lib64 /bin /sbin].each { |name| command.push('--ro-bind', name, name) if File.exist?(name) }
          command.push('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--ro-bind', artifacts, '/artifacts', '--chdir', '/tmp', File.realpath('/usr/bin/ruby'), '/artifacts/worker.rb', '--inside')
          # A nonroot caller inside a user namespace may retain capabilities;
          # bubblewrap rejects those before creating its own namespace.
          effective = File.read('/proc/self/status')[/^CapEff:\s+(\h+)/, 1].to_i(16)
          command.unshift('setpriv', '--ambient-caps=-all', '--inh-caps=-all', '--bounding-set=-all', '--') if !Process.uid.zero? && effective.positive?
        end
        begin
          result = bounded(command, (seconds * 3) + 10, JSON.generate(payload))
        ensure
          bounded(['docker', 'rm', '-f', container], 10) if backend == 'docker'
        end
        raise ArgumentError, "sandbox backend failed: #{result[:stderr]}" if !result[:exit].zero? || result[:timed_out]

        JSON.parse(result[:stdout], symbolize_names: true).merge(backend: backend, network: 'none', artifact_mount: 'ro', memory_mb: memory, timeout: seconds,
                                                                 isolation_limitations: backend == 'bwrap' ? 'bwrap uses per-process RLIMIT_AS, not aggregate cgroup memory/pid limits' : nil)
      end
    end

    def snapshot(request)
      root = File.join(Dir.home, '.pwn', 'sandbox_snapshots')
      FileUtils.mkdir_p(root, mode: 0o700)
      target = File.realpath(request.fetch(:binary))
      raise ArgumentError, 'binary must be a regular file' unless File.file?(target)

      data = File.binread(target)
      digest = Digest::SHA256.hexdigest(data)
      dest = File.join(root, SecureRandom.hex(16))
      Dir.mkdir(dest, 0o700)
      File.binwrite(File.join(dest, 'target'), data)
      File.chmod(0o500, File.join(dest, 'target'))
      File.write(File.join(dest, 'manifest.json'), JSON.generate(sha256: digest))
      { ok: true, snapshot: dest, sha256: digest, semantics: 'immutable input snapshot; rollback creates a fresh disposable environment, not a live process checkpoint' }
    end

    def fuzz(request)
      minutes = Float(request.fetch(:minutes, 1))
      raise ArgumentError, 'minutes must be 0..60' unless minutes.positive? && minutes <= 60

      corpus = File.realpath(request.fetch(:corpus))
      seeds = Dir.children(corpus).sort.filter_map do |name|
        path = File.join(corpus, name)
        File.binread(path, 65_536).to_s if File.file?(path) && !File.symlink?(path)
      end.take(256)
      raise ArgumentError, 'empty corpus' if seeds.empty?

      rng = Random.new(request.fetch(:seed, 0))
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + (minutes * 60)
      crashes = []
      iterations = 0
      while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        data = seeds.fetch(rng.rand(seeds.length)).dup
        data = +"\x00" if data.empty?
        index = rng.rand(data.bytesize)
        data.setbyte(index, data.getbyte(index) ^ (1 << rng.rand(8)))
        encoded = Base64.strict_encode64(data)
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        seconds = [Float(request.fetch(:timeout, 2)), (remaining / 3).clamp(0.01, Float::INFINITY)].min
        result = execute(request.merge(stdin_base64: encoded, timeout: seconds))
        return result unless result[:ok]

        iterations += 1
        crashes << result.merge(input_base64: encoded) if result[:signal]
        break if crashes.length >= 16
      end
      { ok: true, backend: request.fetch(:backend, 'docker'), iterations: iterations, crashes: crashes, seed: request.fetch(:seed, 0) }
    end

    def main(request)
      case request.fetch(:action, 'run')
      when 'fuzz'
        fuzz(request)
      when 'snapshot'
        snapshot(request)
      when 'rollback'
        path = File.realpath(request.fetch(:snapshot))
        root = File.realpath(File.join(Dir.home, '.pwn', 'sandbox_snapshots'))
        raise ArgumentError, 'unknown snapshot' unless File.dirname(path) == root

        target = File.join(path, 'target')
        expected = JSON.parse(File.read(File.join(path, 'manifest.json'))).fetch('sha256')
        raise ArgumentError, 'snapshot integrity failure' unless Digest::SHA256.file(target).hexdigest == expected

        execute(request.merge(binary: target))
      else
        execute(request)
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    request = JSON.parse($stdin.read, symbolize_names: true)
    response = ARGV == ['--inside'] ? PWNSandboxDriver.inside(request) : PWNSandboxDriver.main(request)
  rescue StandardError => e
    response = { ok: false, error: e.message }
  end
  puts JSON.generate(response)
end
