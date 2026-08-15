# frozen_string_literal: true

require 'yaml'
require 'fileutils'
require 'time'
require 'securerandom'
require 'rbconfig'

module PWN
  # PWN::Cron provides cron / scheduled task management for the pwn-ai agent.
  # Jobs are defined in ~/.pwn/cron/jobs.yml and can be triggered by system
  # cron, manual run, or from within pwn-ai agent loops.
  #
  # Each job can contain a prompt (for pwn-ai), a ruby script snippet, or
  # reference to external script. Delivery can be 'log' (default), 'email', etc.
  # (email would require additional plugins).
  module Cron
    CRON_DIR = if ENV['PWN_CRON_DIR'].to_s.strip.empty?
                 File.join(Dir.home, '.pwn', 'cron')
               else
                 ENV.fetch('PWN_CRON_DIR', nil)
               end
    JOBS_FILE = File.join(CRON_DIR, 'jobs.yml')

    # Supported Method Parameters::
    #   dir = PWN::Cron.cron_dir
    public_class_method def self.cron_dir
      FileUtils.mkdir_p(CRON_DIR)
      CRON_DIR
    end

    # Supported Method Parameters::
    #   jobs = PWN::Cron.list
    public_class_method def self.list
      load_jobs
    end

    # Supported Method Parameters::
    #   job = PWN::Cron.create(
    #     name: 'optional',
    #     schedule: 'required e.g. "0 * * * *" or "30m" or "every 2h"',
    #     prompt: 'optional - pwn-ai prompt to run',
    #     ruby: 'optional - ruby snippet to eval',
    #     script: 'optional - path to external script',
    #     delivery: 'log|stdout (default log)',
    #     enabled: true
    #   )
    public_class_method def self.create(opts = {})
      jobs = load_jobs
      id = SecureRandom.hex(6)
      name = opts[:name] || "job-#{id}"
      job = {
        id: id,
        name: name,
        schedule: opts[:schedule] || '0 * * * *',
        prompt: opts[:prompt],
        ruby: opts[:ruby],
        script: opts[:script],
        delivery: opts[:delivery] || 'log',
        enabled: opts.fetch(:enabled, true),
        created_at: Time.now.utc.iso8601,
        last_run: nil,
        last_status: nil
      }
      jobs[id] = job
      save_jobs(jobs: jobs)

      # Optionally install a crontab entry (user must have permission)
      install_crontab_entry(job: job) if opts[:install_crontab]

      job
    end

    # Supported Method Parameters::
    #   PWN::Cron.run(id: 'required or name')
    #   Executes the job (for pwn-ai prompt it will use current active AI engine
    #   via PWN::AI::* but without full REPL hook unless in pwn-ai).
    public_class_method def self.run(opts = {})
      id = opts[:id].to_s
      jobs = load_jobs
      job = jobs[id] || jobs.values.find { |j| j[:name] == id || j[:id] == id }
      raise "Job #{id} not found" unless job

      start = Time.now
      result = nil
      status = 'success'

      begin
        if job[:prompt]
          engine = begin
            PWN::Env[:ai][:active].to_s.downcase.to_sym
          rescue StandardError
            :grok
          end
          case engine
          when :grok
            result = PWN::AI::Grok.chat(request: job[:prompt], spinner: false)
          when :ollama
            result = PWN::AI::Ollama.chat(request: job[:prompt], spinner: false)
          when :openai
            result = PWN::AI::OpenAI.chat(request: job[:prompt], spinner: false)
          when :anthropic
            result = PWN::AI::Anthropic.chat(request: job[:prompt], spinner: false)
          when :gemini
            result = PWN::AI::Gemini.chat(request: job[:prompt], spinner: false)
          end
          result = begin
            result[:choices].last[:content]
          rescue StandardError
            result.to_s
          end
        elsif job[:ruby]
          result = eval(job[:ruby], TOPLEVEL_BINDING) # rubocop:disable Security/Eval
        elsif job[:script] && File.exist?(job[:script])
          result = `#{job[:script]} 2>&1`
        else
          result = 'No prompt/ruby/script defined'
        end

        if job[:delivery] == 'log'
          log_path = File.join(cron_dir, "#{job[:id]}.log")
          File.open(log_path, 'a') do |f|
            f.puts("[#{Time.now}] RUN #{job[:name]} (#{job[:id]})\n#{result}\n---")
          end
        end
      rescue StandardError => e
        status = 'error'
        result = "ERROR: #{e.class} - #{e.message}\n#{e.backtrace.first(5).join("\n")}"
      end

      job[:last_run] = Time.now.utc.iso8601
      job[:last_status] = status
      jobs[job[:id]] = job
      save_jobs(jobs: jobs)

      { job: job, result: result, duration: Time.now - start, status: status }
    end

    # Supported Method Parameters::
    #   PWN::Cron.remove(id:)
    public_class_method def self.remove(opts = {}) # rubocop:disable Naming/PredicateMethod
      id = opts[:id].to_s
      jobs = load_jobs
      jobs.delete(id)
      save_jobs(jobs: jobs)
      true
    end

    # Supported Method Parameters::
    #   PWN::Cron.enable/disable(id:)
    public_class_method def self.enable(opts = {})
      toggle(id: opts[:id], enabled: true)
    end

    public_class_method def self.disable(opts = {})
      toggle(id: opts[:id], enabled: false)
    end

    # Install a crontab line that invokes this job via pwn
    # (assumes /opt/pwn and the active rvm ruby@pwn gemset - user can edit crontab)
    public_class_method def self.install_crontab_entry(opts = {})
      job = opts[:job]
      cron_line = "#{job[:schedule]} cd /opt/pwn && /usr/local/rvm/bin/rvm ruby-#{RUBY_VERSION}@pwn do ruby -I lib -e 'require \"pwn\"; PWN::Cron.run(id: \"#{job[:id]}\")' >> #{File.join(cron_dir, 'cron.log')} 2>&1"
      # Append to user's crontab (non-destructive)
      existing = `crontab -l 2>/dev/null || true`
      unless existing.include?(job[:id])
        new_cron = existing + "\n# pwn-cron #{job[:name]} (#{job[:id]})\n#{cron_line}\n"
        IO.popen('crontab -', 'w') { |io| io.write(new_cron) }
      end
      cron_line
    end

    private_class_method def self.load_jobs
      FileUtils.mkdir_p(cron_dir)
      path = jobs_file
      return {} unless File.exist?(path)

      raw = YAML.safe_load_file(
        path,
        permitted_classes: [Symbol, Time],
        symbolize_names: true
      ) || {}
      # Normalize outer job-id keys to String (create() uses String ids;
      # symbolize_names would otherwise turn them into Symbols on reload
      # and break jobs[id] / jobs.delete(id) / toggle lookups).
      raw.each_with_object({}) { |(k, v), h| h[k.to_s] = v }
    rescue StandardError => e
      warn("[PWN::Cron] load_jobs failed: #{e.class}: #{e.message}")
      {}
    end

    private_class_method def self.save_jobs(opts = {})
      jobs = opts[:jobs] ||= {}
      File.write(jobs_file, YAML.dump(jobs))
    end

    private_class_method def self.toggle(opts = {})
      id = opts[:id].to_s
      enabled = opts[:enabled]
      jobs = load_jobs
      if jobs[id]
        jobs[id][:enabled] = enabled
        save_jobs(jobs: jobs)
      end
      jobs[id]
    end

    # Supported Method Parameters::
    #   PWN::Cron.install_defaults
    # Idempotently seed the RL feedback-loop cron jobs so a fresh install
    # closes the loop by default (S1 practice + P3 offline_judge + W2 train dry-run + M1 consolidate).
    # Re-running is a no-op if jobs with these names already exist.
    # These are seeded to jobs.yml only — pass install_crontab: true to
    # PWN::Cron.create yourself if you also want a system crontab entry.
    public_class_method def self.install_defaults
      jobs = load_jobs
      names = jobs.values.map { |j| j[:name] }
      seeded = []

      unless names.include?('curriculum_practice_nightly')
        seeded << create(
          name: 'curriculum_practice_nightly',
          schedule: '0 3 * * *',
          ruby: 'PWN::AI::Agent::Curriculum.practice(limit: 3) if defined?(PWN::AI::Agent::Curriculum)',
          delivery: 'log',
          enabled: true
        )
      end

      unless names.include?('curriculum_train_weekly')
        seeded << create(
          name: 'curriculum_train_weekly',
          schedule: '0 4 * * 0',
          ruby: 'PWN::AI::Agent::Curriculum.train_and_gate(dry_run: true) if defined?(PWN::AI::Agent::Curriculum)',
          delivery: 'log',
          enabled: true
        )
      end

      # P3 — backfill ORM/PRM labels when local :failure_only introspect is on.
      # P13 — treat legacy alias offline_judge_nightly as the same job so
      # install_defaults never double-seeds the 30 3 * * * slot.
      offline_names = %w[curriculum_offline_judge offline_judge_nightly]
      unless names.intersect?(offline_names)
        seeded << create(
          name: 'curriculum_offline_judge',
          schedule: '30 3 * * *',
          ruby: 'PWN::AI::Agent::Curriculum.offline_judge(since_hours: 24, limit: 40) if defined?(PWN::AI::Agent::Curriculum)',
          delivery: 'log',
          enabled: true
        )
      end
      # Disable duplicate alias if both exist (idempotent cleanup).
      if names.include?('curriculum_offline_judge') && names.include?('offline_judge_nightly')
        begin
          dup = jobs.values.find { |j| j[:name].to_s == 'offline_judge_nightly' }
          disable(id: dup[:id]) if dup && dup[:enabled]
        rescue StandardError
          nil
        end
      end

      # M1/M3 — nightly memory GC so the injected MEMORY block stays high-signal
      unless names.include?('learning_consolidate_nightly')
        seeded << create(
          name: 'learning_consolidate_nightly',
          schedule: '0 5 * * *',
          ruby: 'PWN::AI::Agent::Learning.consolidate if defined?(PWN::AI::Agent::Learning)',
          delivery: 'log',
          enabled: true
        )
      end

      seeded
    rescue StandardError => e
      warn("[PWN::Cron] install_defaults failed: #{e.class}: #{e.message}")
      []
    end

    # ------------------------------------------------------------------
    # In-process scheduler. System crontab is optional (install_crontab)
    # and install_defaults never writes it, so last_run only moves when
    # something ticks jobs.yml. The worker is that something: poll once
    # or loop, fire due enabled jobs via PWN::Cron.run, and stay alive
    # behind a pidfile so `pwn setup` can start / restart it.
    #
    # Spawned workers honor PWN_CRON_DIR so tests can sandbox the daemon
    # without touching the operator's real ~/.pwn/cron.
    # ------------------------------------------------------------------

    DEFAULT_INTERVAL = 60
    DEFAULT_LOCK_STALE = 7_200

    # Supported Method Parameters::
    #   PWN::Cron.jobs_file / PWN::Cron.pid_file / PWN::Cron.worker_log
    # Runtime paths follow cron_dir (and therefore a stubbed CRON_DIR).
    public_class_method def self.jobs_file
      File.join(cron_dir, 'jobs.yml')
    end

    public_class_method def self.pid_file
      File.join(cron_dir, 'worker.pid')
    end

    public_class_method def self.worker_log
      File.join(cron_dir, 'worker.log')
    end

    # Kept for callers / older snippets. Prefer the methods above.
    PID_FILE = File.join(CRON_DIR, 'worker.pid')
    WORKER_LOG = File.join(CRON_DIR, 'worker.log')

    # Supported Method Parameters::
    #   PWN::Cron.due?(
    #     schedule: 'required - 5-field cron or relative ("30m", "every 2h")',
    #     last_run: 'optional - Time / iso8601 / nil',
    #     now:      'optional - Time (default Time.now)'
    #   )
    public_class_method def self.due?(opts = {})
      schedule = opts[:schedule].to_s.strip
      return false if schedule.empty?

      now = opts[:now] || Time.now
      last = parse_time(value: opts[:last_run])

      if (secs = relative_seconds(schedule: schedule))
        return true if last.nil?

        return (now - last) >= secs
      end

      fields = schedule.split
      return false unless fields.length == 5

      prev = last || (now - (24 * 60 * 60))
      # Walk minute-aligned slots from the minute AFTER last_run
      # (or the last 24h if never run) up to `now`.
      t = Time.at(((prev.to_i / 60) + 1) * 60)
      t = Time.local(t.year, t.month, t.day, t.hour, t.min, 0)
      limit = Time.local(now.year, now.month, now.day, now.hour, now.min, 0)
      safety = 0
      while t <= limit && safety < 10_080
        return true if cron_match?(fields: fields, time: t)

        t += 60
        safety += 1
      end
      false
    rescue StandardError
      false
    end

    # Supported Method Parameters::
    #   PWN::Cron.due_jobs(now: Time)
    public_class_method def self.due_jobs(opts = {})
      now = opts[:now] || Time.now
      load_jobs.each_with_object({}) do |(id, job), acc|
        next unless job.is_a?(Hash)
        next unless job[:enabled]
        next unless due?(schedule: job[:schedule], last_run: job[:last_run], now: now)

        acc[id] = job
      end
    end

    # Supported Method Parameters::
    #   PWN::Cron.run_due(now: Time, jobs: optional Hash)
    # Fires every currently-due enabled job via run(). Returns the list
    # of {id:, status:, duration:} hashes (empty when nothing is due).
    public_class_method def self.run_due(opts = {})
      now = opts[:now] || Time.now
      jobs = opts[:jobs] || due_jobs(now: now)
      jobs.map do |id, _job|
        res = run(id: id)
        { id: id, status: res[:status], duration: res[:duration] }
      rescue StandardError => e
        { id: id, status: 'error', error: "#{e.class}: #{e.message}" }
      end
    end

    # Supported Method Parameters::
    #   PWN::Cron.worker_status
    public_class_method def self.worker_status
      pid = read_pid
      running = pid && process_alive?(pid: pid)
      {
        running: running ? true : false,
        pid: running ? pid : nil,
        pid_file: pid_file,
        log: worker_log
      }
    end

    # Supported Method Parameters::
    #   PWN::Cron.start_worker(
    #     interval: 60,
    #     foreground: false,
    #     restart: true
    #   )
    # Idempotent. With restart:true (default) a live worker is replaced
    # so `pwn setup` always leaves a current worker running.
    public_class_method def self.start_worker(opts = {})
      interval = (opts[:interval] || DEFAULT_INTERVAL).to_i
      interval = DEFAULT_INTERVAL if interval <= 0
      foreground = opts[:foreground] ? true : false
      restart = opts.fetch(:restart, true)

      st = worker_status
      return { started: false, already_running: true, pid: st[:pid], interval: interval } if st[:running] && !restart && !foreground

      stop_worker if st[:running] && (restart || foreground)

      if foreground
        write_pid(pid: Process.pid)
        begin
          worker_loop(interval: interval)
        ensure
          clear_pid(pid: Process.pid)
        end
        return { started: true, pid: Process.pid, foreground: true, interval: interval }
      end

      FileUtils.mkdir_p(cron_dir)
      spawn_env = ENV.to_h.merge('PWN_CRON_DIR' => cron_dir.to_s)
      pid = Process.spawn(
        spawn_env,
        RbConfig.ruby,
        '-I', File.expand_path('..', __dir__),
        '-e', worker_spawn_snippet(interval: interval),
        %i[out err] => [worker_log, 'a'],
        in: File::NULL,
        pgroup: true
      )
      Process.detach(pid)

      # The child writes the pidfile; wait briefly.
      waited = 0
      live = nil
      while waited < 50
        live = read_pid
        break if live && process_alive?(pid: live)

        sleep 0.1
        waited += 1
      end
      {
        started: !(live && process_alive?(pid: live)).nil?,
        pid: live,
        spawn_pid: pid,
        interval: interval,
        log: worker_log,
        pid_file: pid_file
      }
    end

    # Supported Method Parameters::
    #   PWN::Cron.stop_worker
    public_class_method def self.stop_worker
      pid = read_pid
      killed = false
      if pid && process_alive?(pid: pid)
        begin
          Process.kill('TERM', pid)
          20.times do
            break unless process_alive?(pid: pid)

            sleep 0.05
          end
          Process.kill('KILL', pid) if process_alive?(pid: pid)
          killed = true
        rescue Errno::ESRCH, Errno::EPERM
          nil
        end
      end
      FileUtils.rm_f(pid_file)
      { stopped: true, pid: pid, killed: killed }
    end

    # Single tick used by the loop AND by tests (no sleep).
    public_class_method def self.tick(opts = {})
      run_due(now: opts[:now] || Time.now)
    end

    # Blocking poll loop. `once: true` runs a single tick then returns
    # (used by tests). Otherwise sleep `interval` seconds between ticks
    # until TERM/INT or the pidfile no longer names this process.
    public_class_method def self.worker_loop(opts = {}) # rubocop:disable Naming/PredicateMethod
      interval = (opts[:interval] || DEFAULT_INTERVAL).to_i
      interval = DEFAULT_INTERVAL if interval <= 0
      once = opts[:once] ? true : false
      trap_shutdown! unless once

      loop do
        begin
          tick
        rescue StandardError => e
          warn("[PWN::Cron] worker tick failed: #{e.class}: #{e.message}")
        end
        break if once
        break if @worker_stop
        break if File.exist?(pid_file) && read_pid != Process.pid

        slept = 0
        while slept < interval
          break if @worker_stop

          step = [1, interval - slept].min
          sleep(step)
          slept += step
        end
        break if @worker_stop
      end
      true
    end

    # PWN::Setup hook — start (or restart) the background worker after
    # any setup action so YAML-only default jobs actually fire.
    public_class_method def self.ensure_worker(opts = {})
      start_worker(
        interval: opts[:interval] || DEFAULT_INTERVAL,
        restart: opts.fetch(:restart, false),
        foreground: false
      )
    end

    # Supported Method Parameters::
    #   PWN::Cron.install_worker_crontab
    # Append an @reboot line so the worker comes back after a reboot.
    # Idempotent. Does not remove existing per-job crontab lines.
    public_class_method def self.install_worker_crontab
      marker = 'PWN::Cron.ensure_worker'
      existing = `crontab -l 2>/dev/null || true`
      return existing if existing.include?(marker)

      ruby = worker_ruby_cmd
      cron_line = "@reboot #{ruby} -e 'require \"pwn\"; PWN::Cron.ensure_worker(restart: false)' >> #{worker_log} 2>&1"
      new_cron = "#{existing}\n# pwn-cron worker\n#{cron_line}\n"
      IO.popen('crontab -', 'w') { |io| io.write(new_cron) }
      cron_line
    rescue StandardError => e
      warn("[PWN::Cron] install_worker_crontab failed: #{e.class}: #{e.message}")
      nil
    end

    private_class_method def self.parse_time(opts = {})
      value = opts[:value]
      return nil if value.nil? || value.to_s.empty?
      return value if value.is_a?(Time)

      Time.parse(value.to_s)
    rescue StandardError
      nil
    end

    private_class_method def self.relative_seconds(opts = {})
      schedule = opts[:schedule]
      s = schedule.to_s.strip.downcase
      case s
      when /\A(?:every\s+)?(\d+)\s*(s|sec|secs|second|seconds)\z/
        Regexp.last_match(1).to_i
      when /\A(?:every\s+)?(\d+)\s*(m|min|mins|minute|minutes)\z/
        Regexp.last_match(1).to_i * 60
      when /\A(?:every\s+)?(\d+)\s*(h|hr|hrs|hour|hours)\z/
        Regexp.last_match(1).to_i * 3_600
      end
    end

    private_class_method def self.cron_match?(opts = {})
      fields = opts[:fields]
      time = opts[:time]
      min, hour, mday, mon, wday = fields
      cron_field?(expr: min, value: time.min, min: 0, max: 59) &&
        cron_field?(expr: hour, value: time.hour, min: 0, max: 23) &&
        cron_field?(expr: mday, value: time.day, min: 1, max: 31) &&
        cron_field?(expr: mon, value: time.month, min: 1, max: 12) &&
        cron_field?(expr: wday, value: time.wday, min: 0, max: 7)
    end

    private_class_method def self.cron_field?(opts = {})
      expr = opts[:expr]
      value = opts[:value]
      min = opts[:min]
      max = opts[:max]
      expr.to_s.split(',').any? { |part| cron_atom?(atom: part, value: value, min: min, max: max) }
    end

    private_class_method def self.cron_atom?(opts = {})
      atom = opts[:atom]
      value = opts[:value]
      min = opts[:min]
      max = opts[:max]
      atom = atom.to_s.strip
      return false if atom.empty?
      return (min..max).cover?(value) if atom == '*'

      if atom =~ %r{\A\*/(\d+)\z}
        step = Regexp.last_match(1).to_i
        return false if step <= 0

        return ((value - min) % step).zero?
      end
      if atom =~ %r{\A(\d+)-(\d+)/(\d+)\z}
        a = Regexp.last_match(1).to_i
        b = Regexp.last_match(2).to_i
        step = Regexp.last_match(3).to_i
        return false if step <= 0

        return value.between?(a, b) && ((value - a) % step).zero?
      end
      return value.between?(Regexp.last_match(1).to_i, Regexp.last_match(2).to_i) if atom =~ /\A(\d+)-(\d+)\z/

      n = Integer(atom)
      # cron Sunday is 0 or 7
      return true if n == value
      return true if min.zero? && max == 7 && ((n == 7 && value.zero?) || (n.zero? && value == 7))

      false
    rescue ArgumentError
      false
    end

    private_class_method def self.read_pid
      return nil unless File.exist?(pid_file)

      Integer(File.read(pid_file).to_s.strip)
    rescue ArgumentError, TypeError
      nil
    end

    private_class_method def self.write_pid(opts = {})
      FileUtils.mkdir_p(cron_dir)
      File.write(pid_file, "#{opts[:pid] || Process.pid}\n")
    end

    private_class_method def self.clear_pid(opts = {})
      pid = opts[:pid]
      current = read_pid
      FileUtils.rm_f(pid_file) if pid.nil? || current.nil? || current == pid
    end

    private_class_method def self.process_alive?(opts = {})
      pid = opts[:pid]
      return false if pid.nil? || pid.to_i <= 1

      Process.kill(0, pid.to_i)
      true
    rescue Errno::ESRCH
      false
    rescue Errno::EPERM
      true
    end

    private_class_method def self.trap_shutdown!
      @worker_stop = false
      stopper = ->(_sig) { @worker_stop = true }
      Signal.trap('TERM', &stopper)
      Signal.trap('INT', &stopper)
    rescue ArgumentError
      nil
    end

    private_class_method def self.worker_ruby_cmd
      rvm = '/usr/local/rvm/bin/rvm'
      if File.executable?(rvm)
        "cd /opt/pwn && #{rvm} ruby-#{RUBY_VERSION}@pwn do ruby -I lib"
      else
        "#{RbConfig.ruby} -I #{File.expand_path('..', __dir__)}"
      end
    end

    private_class_method def self.worker_spawn_snippet(opts = {})
      interval = opts[:interval].to_i
      [
        "require 'pwn'",
        "require 'fileutils'",
        'begin; Process.setsid; rescue StandardError; nil; end',
        "Signal.trap('HUP', 'IGNORE') rescue nil",
        'FileUtils.mkdir_p(PWN::Cron.cron_dir)',
        'File.write(PWN::Cron.pid_file, Process.pid.to_s + "\n")',
        "PWN::Cron.worker_loop(interval: #{interval})"
      ].join(';')
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module
    public_class_method def self.help
      puts <<~USAGE
                USAGE:
                  PWN::Cron.create(schedule: '0 * * * *', prompt: 'Run daily recon on target.com using NmapIt and report', name: 'daily-recon')
                  PWN::Cron.list
                  res = PWN::Cron.run(id: 'abc123')
                  PWN::Cron.enable(id: 'abc123')
                  PWN::Cron.disable(id: 'abc123')
                  PWN::Cron.remove(id: 'abc123')
                  # To have system cron call it, use install_crontab_entry or the :install_crontab option on create
        PWN::Cron.install_defaults  # seed S1/P3/W2/M1 curriculum jobs (idempotent)
        PWN::Cron.ensure_worker     # start/restart the background scheduler
        PWN::Cron.worker_status
        PWN::Cron.tick              # fire currently-due jobs once

                  #{self}.authors
      USAGE
    end
  end
end
