# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'
require 'open3'

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
          started_at: Time.now.utc.iso8601
        }
        File.write(meta, JSON.generate(row))
        PWN::Plugins::ArtifactRegistry.register(session_id: opts[:session_id], path: log, kind: 'job-log') if opts[:session_id] && defined?(PWN::Plugins::ArtifactRegistry) && File.file?(log)
        row
      end

      public_class_method def self.status(opts = {})
        row = load_job(opts)
        alive = begin
          Process.kill(0, row[:pid].to_i)
          true
        rescue Errno::ESRCH, Errno::EPERM
          false
        end
        row.merge(alive: alive)
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

      public_class_method def self.stop(opts = {})
        row = load_job(opts)
        Process.kill('TERM', row[:pid].to_i)
        true
      rescue Errno::ESRCH
        false
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
            session_id: 'optional - session id value consumed by #start'
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

          # Run stop and return its result
          #{self}.stop

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
