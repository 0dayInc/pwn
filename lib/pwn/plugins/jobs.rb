# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'
require 'open3'
require 'time'
require 'timeout'

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

        FileUtils.mkdir_p(JOBS_DIR)
        id = SecureRandom.hex(6)
        log = File.join(JOBS_DIR, "#{id}.log")
        meta = File.join(JOBS_DIR, "#{id}.json")
        pid = spawn(cmd.to_s, %i[out err] => [log, 'a'], pgroup: true)
        Process.detach(pid)
        row = {
          id: id,
          pid: pid,
          command: cmd.to_s,
          log: log,
          session_id: opts[:session_id],
          max_runtime: opts[:max_runtime].to_i,
          started_at: Time.now.utc.iso8601
        }
        File.write(meta, JSON.generate(row))
        PWN::Plugins::ArtifactRegistry.register(session_id: opts[:session_id], path: log, kind: 'job-log') if opts[:session_id] && defined?(PWN::Plugins::ArtifactRegistry) && File.file?(log)
        row
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
        tail(id: opts[:handle] || opts[:id], lines: opts[:lines])
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
        alive = begin
          Process.kill(0, row[:pid].to_i)
          true
        rescue Errno::ESRCH, Errno::EPERM
          false
        end
        max = row[:max_runtime].to_i
        if alive && max.positive?
          started = begin
            Time.parse(row[:started_at].to_s)
          rescue StandardError
            Time.now
          end
          if Time.now - started > max
            Process.kill('TERM', row[:pid].to_i)
            alive = false
            row[:status] = 'TIMEOUT'
          end
        end
        row.merge(alive: alive, status: row[:status] || (alive ? 'RUNNING' : 'COMPLETED'))
      end

      public_class_method def self.tail(opts = {})
        row = load_job(opts)
        n = (opts[:lines] || 40).to_i
        return '' unless File.file?(row[:log])

        File.readlines(row[:log]).last(n).join
      end

      public_class_method def self.result(opts = {})
        row = status(opts)
        row.merge(tail: tail(opts.merge(lines: opts[:lines] || 80)))
      end

      public_class_method def self.harvest(opts = {})
        result(opts)
      end

      public_class_method def self.list(opts = {})
        _limit = opts[:limit]
        Dir[File.join(JOBS_DIR, '*.json')].filter_map do |path|
          row = JSON.parse(File.read(path), symbolize_names: true)
          status(id: row[:id])
        rescue StandardError
          nil
        end
      end

      public_class_method def self.stop(opts = {})
        row = load_job(opts)
        Process.kill('TERM', row[:pid].to_i)
        true
      rescue Errno::ESRCH
        false
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

          # Run start and return its result
          #{self}.start(
            command: 'required - command value consumed by #start (defaults to opts[:cmd])',
            cmd: 'required - command string to run',
            session_id: 'optional - session id value consumed by #start',
            max_runtime: 'optional - seconds after which a live job is killed (TIMEOUT)'
          )

          # Run status and return its result
          #{self}.status

          # Run tail and return its result
          #{self}.tail(
            lines: 'optional - lines value consumed by #tail'
          )

          # Return status plus log tail for a job id.
          #{self}.result(
            id: 'required - job id from #start',
            lines: 'optional - tail line count (defaults to 80)'
          )

          # Alias of result for harvesting a detached job from a later session.
          #{self}.harvest(
            id: 'required - job id from #start',
            lines: 'optional - tail line count (defaults to 80)'
          )

          # List job metadata rows under ~/.pwn/jobs.
          #{self}.list(
            limit: 'optional - unused cap reserved for callers'
          )

          # Run stop and return its result
          #{self}.stop

          # Tail a job log for a regex (AFL new-crash lines).
          #{self}.watch(
            id: 'required - job id from #start',
            pattern: 'required - regex to match in the job log'
          )

          # Alias of start that returns a job handle immediately.
          #{self}.run(
            command: 'required - command string to run',
            cmd: 'optional - alias for command',
            session_id: 'optional - pwn-ai session id',
            max_runtime: 'optional - seconds after which a live job is killed'
          )

          # Alias of #run.
          #{self}.job_run(
            command: 'required - command string to run',
            cmd: 'optional - alias for command'
          )

          # Status by handle or id.
          #{self}.job_status(
            handle: 'optional - job handle from #run',
            id: 'optional - job id alias for handle'
          )

          # Tail a job log by handle.
          #{self}.job_tail(
            handle: 'optional - job handle from #run',
            id: 'optional - job id alias for handle',
            lines: 'optional - number of trailing lines'
          )

          # Kill a job by handle.
          #{self}.job_kill(
            handle: 'optional - job handle from #run',
            id: 'optional - job id alias for handle'
          )

          # Run a declarative DAG of shell jobs with needs and a shared artifact dir.
          #{self}.graph(
            jobs: 'required - Array of hashes with id, command, optional needs and timeout',
            artifact_dir: 'optional - working directory shared by every job',
            timeout: 'optional - default per-job timeout in seconds'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.load_job(opts = {})
        id = opts[:id].to_s
        path = File.join(JOBS_DIR, "#{id}.json")
        raise "ERROR: unknown job #{id}" unless File.file?(path)

        JSON.parse(File.read(path), symbolize_names: true)
      end
    end
  end
end
