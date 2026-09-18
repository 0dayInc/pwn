# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'
require 'open3'
require 'time'
require 'timeout'
require 'rbconfig'
require 'base64'
require 'digest'

module PWN
  module Plugins
    # Background jobs that survive a pwn-ai turn (scans, fuzz campaigns).
    module Jobs
      JOBS_DIR = File.join(Dir.home, '.pwn', 'jobs')

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.start(opts = {})
        cmd = opts[:command] || opts[:cmd]
        raise 'ERROR: command is required' if cmd.to_s.empty?

        root = File.expand_path(JOBS_DIR)
        FileUtils.mkdir_p(root, mode: 0o700)
        File.chmod(0o700, root)
        runtime = Float(opts[:max_runtime] || 0)
        raise ArgumentError, 'max_runtime must be finite and nonnegative' unless runtime.finite? && runtime >= 0

        env = opts[:env] || {}
        raise ArgumentError, 'env must be a string map' unless env.is_a?(Hash) && env.all? { |key, value| key.is_a?(String) && value.is_a?(String) }

        File.open(File.join(root, '.start.lock'), File::RDWR | File::CREAT, 0o600) do |lock|
          lock.flock(File::LOCK_EX)
          key = opts[:idempotency_key]
          id = key ? Digest::SHA256.hexdigest(key.to_s)[0, 12] : SecureRandom.hex(6)
          return status(id: id) if File.exist?(File.join(root, "#{id}.json"))

          row = { id: id, handle: id, command: cmd.to_s, cwd: File.expand_path(opts[:cwd] || Dir.pwd),
                  env: env, session_id: opts[:session_id], max_runtime: runtime,
                  log: File.join(root, "#{id}.log"), status: 'RUNNING', created_at: Time.now.utc.iso8601(6) }
          File.open(row[:log], File::WRONLY | File::CREAT, 0o600, &:close)
          persist(root: root, row: row)
          begin
            worker = spawn(RbConfig.ruby, '-I', File.expand_path('../..', __dir__), '-rpwn', '-e',
                           'PWN::Plugins::Jobs.supervise(root: ARGV[0], id: ARGV[1])', root, id,
                           in: File::NULL, out: File::NULL, err: File::NULL, close_others: true)
            Process.detach(worker)
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
            loop do
              row = load_job(id: id)
              break if row[:worker_pid] || row[:status] != 'RUNNING' || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

              sleep 0.02
            end
          rescue StandardError => e
            row.merge!(status: 'FAILED', error: "#{e.class}: #{e.message}", finished_at: Time.now.utc.iso8601(6))
            persist(root: root, row: row)
          end
          row.except(:env)
        end
      end

      public_class_method def self.run(opts = {})
        start(opts)
      end

      public_class_method def self.job_run(opts = {})
        start(opts)
      end

      public_class_method def self.job_status(opts = {})
        status(id: opts[:handle] || opts[:id])
      end

      public_class_method def self.job_tail(opts = {})
        tail(opts.merge(id: opts[:handle] || opts[:id]))
      end

      public_class_method def self.job_kill(opts = {})
        stop(id: opts[:handle] || opts[:id])
      end

      public_class_method def self.watch(opts = {})
        row = load_job(opts)
        pattern = opts[:pattern].to_s
        raise 'ERROR: pattern is required' if pattern.empty?

        log = row[:log].to_s
        return { id: row[:id], hits: [] } unless File.file?(log)

        rx = Regexp.new(pattern)
        hits = File.readlines(log).grep(rx).last(20)
        { id: row[:id], hits: hits.map(&:chomp), pattern: pattern }
      end

      public_class_method def self.status(opts = {})
        row = load_job(opts)
        unless row[:status]
          row.merge!(status: 'LOST', error: 'Legacy unsupervised job; command outcome unknown', finished_at: Time.now.utc.iso8601(6))
          persist(root: JOBS_DIR, row: row)
        end
        if row[:status] == 'RUNNING'
          File.open(File.join(JOBS_DIR, "#{row[:id]}.worker"), File::RDWR | File::CREAT, 0o600) do |lock|
            if lock.flock(File::LOCK_EX | File::LOCK_NB)
              row = load_job(opts)
              if row[:status] == 'RUNNING' && (row[:worker_pid] || Time.now - Time.parse(row[:created_at]) > 5)
                row.merge!(status: 'LOST', error: 'Supervisor disappeared; command outcome unknown', finished_at: Time.now.utc.iso8601(6))
                persist(root: JOBS_DIR, row: row)
              end
            end
          end
        end
        row.except(:env).merge(alive: row[:status] == 'RUNNING')
      end

      public_class_method def self.tail(opts = {})
        row = status(opts)
        File.open(row[:log], 'rb') do |io|
          unless opts.key?(:offset)
            io.seek([io.size - 65_536, 0].max)
            return io.read.force_encoding(Encoding::UTF_8).scrub.lines.last((opts[:lines] || 40).to_i.clamp(0, 2000)).join
          end
          offset = Integer(opts[:offset])
          length = Integer(opts[:length] || 16_384)
          raise ArgumentError, 'offset must be nonnegative and length positive' if offset.negative? || length <= 0

          io.seek(offset)
          data = (io.read([length, 65_536].min) || String.new).force_encoding(Encoding::UTF_8)
          bytes = data.bytesize
          encoding = data.valid_encoding? ? 'utf-8' : 'base64'
          body = encoding == 'base64' ? Base64.strict_encode64(data) : data
          { id: row[:id], body: body, data: body,
            bytes: bytes, next_offset: offset + bytes, encoding: encoding,
            eof: offset + bytes >= io.size, status: row[:status] }
        end
      end

      public_class_method def self.result(opts = {})
        row = status(opts)
        row.merge(tail: tail(opts.merge(lines: opts[:lines] || 80)))
      end

      public_class_method def self.harvest(opts = {})
        result(opts)
      end

      public_class_method def self.list(opts = {})
        limit = Integer(opts[:limit] || 20)
        raise ArgumentError, 'limit must be nonnegative' if limit.negative?

        rows = Dir[File.join(JOBS_DIR, '*.json')].filter_map do |path|
          row = JSON.parse(File.read(path), symbolize_names: true)
          next if opts[:session_id] && row[:session_id] != opts[:session_id]

          status(id: row[:id])
        rescue StandardError
          nil
        end
        rows.sort_by { |row| row[:created_at].to_s }.reverse.first(limit)
      end

      public_class_method def self.stop(opts = {}) # rubocop:disable Naming/PredicateMethod -- Preserve the existing boolean stop API.
        row = status(opts)
        return false unless row[:status] == 'RUNNING'

        File.open(File.join(JOBS_DIR, "#{row[:id]}.cancel"), File::WRONLY | File::CREAT, 0o600) do |io|
          io.write(Time.now.utc.iso8601(6))
          io.flush
          io.fsync
        end
        true
      end

      public_class_method def self.graph(opts = {})
        jobs = Array(opts[:jobs])
        raise ArgumentError, 'jobs must be an Array of hashes with id and command' unless jobs.all?(Hash)

        dir = opts[:artifact_dir] || File.join(JOBS_DIR, "graph-#{SecureRandom.hex(4)}")
        FileUtils.mkdir_p(dir)
        remaining = jobs.map { |job| job.transform_keys(&:to_sym) }
        done = {}
        until remaining.empty?
          loop do
            failed = done.select { |_id, row| row[:ok] == false }.keys
            blocked = remaining.select { |job| Array(job[:needs]).any? { |need| failed.include?(need.to_s) } }
            break if blocked.empty?

            blocked.each do |job|
              done[job[:id].to_s] = { id: job[:id], ok: false, skipped: true, stdout: '', stderr: 'upstream failed' }
              remaining.delete(job)
            end
          end
          ready = remaining.select { |job| Array(job[:needs]).all? { |need| done[need.to_s] && done[need.to_s][:ok] } }
          raise ArgumentError, 'job graph deadlock or missing needs' if ready.empty? && remaining.any?

          threads = ready.map do |job|
            remaining.delete(job)
            Thread.new do
              timeout = (job[:timeout] || opts[:timeout]).to_f
              timeout = 3_600 if timeout <= 0
              out = err = ''
              st = nil
              begin
                Timeout.timeout(timeout) do
                  out, err, st = Open3.capture3(job[:command].to_s, chdir: dir)
                end
                { id: job[:id], ok: st.success?, stdout: out, stderr: err, exit: st.exitstatus }
              rescue Timeout::Error
                { id: job[:id], ok: false, stdout: out, stderr: 'timeout', exit: 124, timeout: true }
              end
            end
          end
          threads.each do |thr|
            row = thr.value
            done[row[:id].to_s] = row
          end
        end
        { jobs: done, artifact_dir: dir, ok: done.values.none? { |row| row[:ok] == false && row[:skipped] != true } && done.values.any? { |row| row[:ok] } }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Launch a detached shell command; return durable metadata after a bounded startup handshake.
          #{self}.start(
            command: 'optional - shell command string; required unless cmd is supplied',
            cmd: 'optional - alias for command',
            cwd: 'optional - working directory; defaults to caller working directory',
            env: 'optional - string-to-string environment overrides; defaults to an empty map',
            session_id: 'optional - originating session label; never limits job lifetime',
            max_runtime: 'optional - nonnegative seconds; zero or nil means unlimited; accepts 21600 and above',
            idempotency_key: 'optional - durable global retry key; the same key returns the first job even with different options'
          )

          # Alias of start with the same detached semantics.
          #{self}.run(
            command: 'optional - shell command string; required unless cmd is supplied',
            cmd: 'optional - alias for command',
            cwd: 'optional - working directory; defaults to caller working directory',
            env: 'optional - string-to-string environment overrides; defaults to an empty map',
            session_id: 'optional - originating session label',
            max_runtime: 'optional - seconds; zero or nil means unlimited',
            idempotency_key: 'optional - durable global retry key'
          )

          # Alias of start for job tool callers.
          #{self}.job_run(
            command: 'optional - shell command string; required unless cmd is supplied',
            cmd: 'optional - alias for command',
            cwd: 'optional - working directory; defaults to caller working directory',
            env: 'optional - string-to-string environment overrides; defaults to an empty map',
            session_id: 'optional - originating session label',
            max_runtime: 'optional - seconds; zero or nil means unlimited',
            idempotency_key: 'optional - durable global retry key'
          )

          # Read RUNNING, COMPLETED, FAILED, TIMEOUT, STOPPED or LOST without waiting for the command.
          #{self}.status(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id'
          )

          # Alias of status; LOST means the supervisor vanished and the command outcome is unknown.
          #{self}.job_status(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id'
          )

          # Read bounded logs; offset mode returns body/data, bytes, next_offset, encoding, eof and status.
          #{self}.tail(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id',
            offset: 'optional - nonnegative byte offset; omit for a legacy String tail',
            length: 'optional - positive byte count in offset mode; default 16384, capped at 65536',
            lines: 'optional - legacy tail lines; default 40, maximum 2000 within the last 65536 bytes'
          )

          # Alias of tail; eof is current log EOF, not command completion; invalid UTF-8 uses base64.
          #{self}.job_tail(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id',
            offset: 'optional - nonnegative byte offset; omit for a legacy String tail',
            length: 'optional - positive byte count; default 16384, capped at 65536',
            lines: 'optional - legacy tail lines; default 40, maximum 2000 within 65536 bytes'
          )

          # Return status plus a bounded tail; legacy String tails replace invalid UTF-8.
          #{self}.result(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id',
            offset: 'optional - nonnegative byte offset for a structured tail',
            length: 'optional - positive byte count; default 16384, capped at 65536',
            lines: 'optional - legacy tail line count; default 80, maximum 2000 within 65536 bytes'
          )

          # Alias of result for harvesting from another session.
          #{self}.harvest(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id',
            offset: 'optional - nonnegative byte offset for a structured tail',
            length: 'optional - positive byte count; default 16384, capped at 65536',
            lines: 'optional - legacy tail lines; default 80, maximum 2000 within 65536 bytes'
          )

          # List durable job metadata newest first.
          #{self}.list(
            limit: 'optional - nonnegative result cap; default 20',
            session_id: 'optional - exact originating session filter; omit to include every session'
          )

          # Persist cancellation; return true if requested, false if already terminal. Worker sends TERM then KILL.
          #{self}.stop(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id'
          )

          # Alias of stop; never signals a PID read from metadata.
          #{self}.job_kill(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id'
          )

          # Search a job log for a regex and return the last twenty matching lines.
          #{self}.watch(
            id: 'optional - twelve lowercase hexadecimal job id; required unless handle is supplied',
            handle: 'optional - alias for id',
            pattern: 'required - Ruby regex string to match in the job log'
          )

          # Run a synchronous declarative DAG; this method itself is not detached.
          #{self}.graph(
            jobs: 'required - Array of hashes with id, command, optional needs and timeout',
            artifact_dir: 'optional - shared working directory; defaults to a new directory under JOBS_DIR',
            timeout: 'optional - default per-job timeout in seconds; nonpositive or omitted uses 3600'
          )

          # Internal exec-only supervisor entry point; callers should use start instead.
          #{self}.supervise(
            root: 'required - existing private job directory owned by the current user',
            id: 'required - twelve lowercase hexadecimal id with previously persisted RUNNING metadata'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      # Exec-only worker; the held file lock is the authoritative worker identity.
      public_class_method def self.supervise(opts = {})
        root = File.realpath(opts[:root].to_s)
        stat = File.stat(root)
        raise ArgumentError, 'worker root must be private and owned by this user' unless stat.uid == Process.uid && stat.mode.nobits?(0o077)

        id = opts[:id].to_s
        raise ArgumentError, 'invalid job id' unless id.match?(/\A[0-9a-f]{12}\z/)

        File.open(File.join(root, "#{id}.worker"), File::RDWR | File::CREAT, 0o600) do |lock|
          next unless lock.flock(File::LOCK_EX | File::LOCK_NB)

          row = JSON.parse(File.read(File.join(root, "#{id}.json")), symbolize_names: true)
          next unless row[:status] == 'RUNNING'

          begin
            Process.setsid
            row.merge!(worker_pid: Process.pid, worker_identity: SecureRandom.hex(16), started_at: Time.now.utc.iso8601(6))
            pid = spawn(row[:env].transform_keys(&:to_s), '/bin/sh', '-c', row[:command], chdir: row[:cwd],
                                                                                          in: File::NULL, %i[out err] => [row[:log], 'ab'], pgroup: true, close_others: true)
            row[:pid] = pid
            persist(root: root, row: row)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            forced = nil
            child_status = nil
            loop do
              cancelled = File.exist?(File.join(root, "#{id}.cancel"))
              if cancelled || (row[:max_runtime].positive? && Process.clock_gettime(Process::CLOCK_MONOTONIC) - started >= row[:max_runtime])
                forced = cancelled ? 'STOPPED' : 'TIMEOUT'
                terminate_group(pid: pid)
                _, child_status = Process.wait2(pid)
                break
              end
              waited = Process.wait2(pid, Process::WNOHANG)
              if waited
                child_status = waited.last
                break
              end
              sleep 0.05
            end
            row.merge!(status: forced || (child_status.success? ? 'COMPLETED' : 'FAILED'), exit_code: child_status.exitstatus, signal: child_status.termsig)
          rescue StandardError => e
            row.merge!(status: 'FAILED', error: "#{e.class}: #{e.message}")
          ensure
            row[:finished_at] = Time.now.utc.iso8601(6)
            persist(root: root, row: row)
          end
        end
        nil
      end

      # Do not reap the group leader before escalation: its PID pins the PGID.
      private_class_method def self.terminate_group(opts = {})
        pid = opts[:pid]
        Process.kill('TERM', -pid)
        sleep 0.5
        Process.kill('KILL', -pid)
      rescue Errno::ESRCH
        nil
      end

      private_class_method def self.persist(opts = {})
        row = opts[:row]
        path = File.join(opts[:root], "#{row[:id]}.json")
        tmp = "#{path}.#{SecureRandom.hex(6)}.tmp"
        begin
          File.open(tmp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |io|
            io.write(JSON.generate(row))
            io.flush
            io.fsync
          end
          File.rename(tmp, path)
        ensure
          FileUtils.rm_f(tmp)
        end
      end

      private_class_method def self.load_job(opts = {})
        id = (opts[:handle] || opts[:id]).to_s
        raise ArgumentError, 'invalid job id' unless id.match?(/\A[0-9a-f]{12}\z/)

        path = File.join(JOBS_DIR, "#{id}.json")
        raise "ERROR: unknown job #{id}" unless File.file?(path)

        JSON.parse(File.read(path), symbolize_names: true)
      end
    end
  end
end
