# frozen_string_literal: true

require 'yaml'
require 'fileutils'
require 'time'
require 'securerandom'
require 'rbconfig'
require 'shellwords'
require 'etc'

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
      sync_one_job(job: job) if cron_enabled? && !opts[:install_crontab]

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
      gone = jobs.delete(id)
      save_jobs(jobs: jobs)
      remove_native_job(job: gone) if gone
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
      install_native_job(opts.merge(backend: :crontab))
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
        sync_one_job(job: jobs[id])
      end
      jobs[id]
    end

    private_class_method def self.sync_one_job(opts = {})
      job = opts[:job]
      return unless job.is_a?(Hash)

      if job[:enabled] && cron_enabled?
        install_native_job(job: job)
      else
        remove_native_job(job: job)
      end
    rescue StandardError => e
      warn("[PWN::Cron] sync_one_job failed: #{e.class}: #{e.message}")
      nil
    end

    # Supported Method Parameters::
    #   PWN::Cron.install_defaults
    # Idempotently seed the RL feedback-loop cron jobs so a fresh install
    # closes the loop by default (S1 practice + P3 offline_judge + W2 train dry-run + M1 consolidate).
    # Re-running is a no-op if jobs with these names already exist.
    # These are seeded to jobs.yml only — pass install_crontab: true to
    # PWN::Cron.create yourself if you also want a system crontab entry.
    DEFAULT_JOBS = [
      {
        name: 'curriculum_practice_nightly',
        schedule: '0 3 * * *',
        ruby: 'PWN::AI::Agent::Curriculum.practice(limit: 3) if defined?(PWN::AI::Agent::Curriculum)'
      },
      {
        name: 'curriculum_train_weekly',
        schedule: '0 4 * * 0',
        ruby: 'PWN::AI::Agent::Curriculum.train_and_gate(dry_run: true) if defined?(PWN::AI::Agent::Curriculum)'
      },
      {
        name: 'curriculum_offline_judge',
        schedule: '30 3 * * *',
        ruby: 'PWN::AI::Agent::Curriculum.offline_judge(since_hours: 24, limit: 40) if defined?(PWN::AI::Agent::Curriculum)',
        aliases: %w[offline_judge_nightly]
      },
      {
        name: 'learning_consolidate_nightly',
        schedule: '0 5 * * *',
        ruby: 'PWN::AI::Agent::Learning.consolidate if defined?(PWN::AI::Agent::Learning)'
      }
    ].freeze

    public_class_method def self.install_defaults
      jobs = load_jobs
      names = jobs.values.map { |j| j[:name].to_s }
      seeded = []

      DEFAULT_JOBS.each do |spec|
        aliases = Array(spec[:aliases]).map(&:to_s)
        known = [spec[:name].to_s, *aliases]
        next if names.intersect?(known)

        seeded << create(
          name: spec[:name],
          schedule: spec[:schedule],
          ruby: spec[:ruby],
          delivery: 'log',
          enabled: true
        )
        names << spec[:name].to_s
      end

      # P13 - disable the legacy alias when both occupy the 30 3 * * * slot.
      if names.include?('curriculum_offline_judge') && names.include?('offline_judge_nightly')
        begin
          dup = jobs.values.find { |j| j[:name].to_s == 'offline_judge_nightly' }
          disable(id: dup[:id]) if dup && dup[:enabled]
        rescue StandardError
          nil
        end
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
        pgroup: !windows?
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
        rescue StandardError
          windows_taskkill(pid: pid) if windows?
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
    public_class_method def self.install_worker_crontab(opts = {})
      install_crontab_worker(opts)
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
      bits = [
        "require 'pwn'",
        "require 'fileutils'"
      ]
      unless windows?
        bits << 'begin; Process.setsid; rescue StandardError; nil; end'
        bits << "Signal.trap('HUP', 'IGNORE') rescue nil"
      end
      bits += [
        'FileUtils.mkdir_p(PWN::Cron.cron_dir)',
        'File.write(PWN::Cron.pid_file, Process.pid.to_s + "\n")',
        "PWN::Cron.worker_loop(interval: #{interval})"
      ]
      bits.join(';')
    end

    # ------------------------------------------------------------------
    # OS-agnostic native persistence.
    # jobs.yml remains the source of truth (5-field cron + relative
    # "every 30m"). The in-process worker evaluates due? and fires
    # jobs. A native backend only (a) restarts that worker after
    # reboot / login and (b) optionally plants a calendar trigger per
    # 5-field job so the schedule still fires if the worker is down.
    #
    #   linux   -> systemd --user (Restart=always) else crontab @reboot
    #   osx     -> launchd LaunchAgent (RunAtLoad + KeepAlive)
    #   windows -> schtasks ONLOGON
    #   *bsd / cygwin -> crontab @reboot when crontab(1) exists
    #   else    -> in-process worker only (lives with the login)
    # ------------------------------------------------------------------

    SYSTEMD_WORKER_UNIT = 'pwn-cron-worker.service'
    LAUNCHD_WORKER_LABEL = 'com.0dayinc.pwn.cron.worker'
    SCHTASKS_WORKER_NAME = 'PWN\CronWorker'

    public_class_method def self.os_type
      t = begin
        PWN::Plugins::DetectOS.type
      rescue StandardError
        nil
      end
      return t if t

      host = RbConfig::CONFIG['host_os'].to_s.downcase
      return :windows if host.match?(/mswin|mingw|bccwin|wince|emc/)
      return :cygwin if host.include?('cygwin')
      return :osx if host.include?('darwin')
      return :linux if host.include?('linux')
      return :freebsd if host.include?('freebsd')
      return :netbsd if host.include?('netbsd')
      return :openbsd if host.include?('openbsd')

      :unknown
    end

    public_class_method def self.windows?
      os_type == :windows
    end

    public_class_method def self.scheduler_file
      File.join(cron_dir, 'scheduler.yml')
    end

    public_class_method def self.scheduler_config
      path = scheduler_file
      return { enabled: true, backend: nil } unless File.exist?(path)

      raw = YAML.safe_load_file(
        path,
        permitted_classes: [Symbol, Time],
        symbolize_names: true
      ) || {}
      {
        enabled: raw.key?(:enabled) ? raw[:enabled] == true : true,
        backend: raw[:backend]&.to_sym,
        updated_at: raw[:updated_at]
      }
    rescue StandardError
      { enabled: true, backend: nil }
    end

    public_class_method def self.cron_enabled?
      scheduler_config[:enabled] != false
    end

    public_class_method def self.persist_scheduler_config(opts = {})
      cfg = scheduler_config.merge(
        enabled: opts.fetch(:enabled, cron_enabled?),
        backend: (opts[:backend] || scheduler_config[:backend])&.to_sym,
        updated_at: Time.now.utc.iso8601
      )
      FileUtils.mkdir_p(cron_dir)
      File.write(scheduler_file, YAML.dump(cfg))
      cfg
    end

    public_class_method def self.apply_native?(opts = {})
      return opts[:apply] if opts.key?(:apply)
      return false unless ENV['PWN_CRON_DIR'].to_s.empty?

      default = File.join(Dir.home, '.pwn', 'cron')
      File.expand_path(cron_dir.to_s) == File.expand_path(default)
    end

    public_class_method def self.which_bin(opts = {})
      name = opts[:name].to_s
      return '' if name.empty?

      exts = windows? ? %w[.exe .bat .cmd] + [''] : ['']
      ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
        exts.each do |ext|
          cand = File.join(dir, "#{name}#{ext}")
          return cand if File.file?(cand) && File.executable?(cand)
        end
      end
      ''
    end

    public_class_method def self.crontab_available?
      !which_bin(name: 'crontab').empty?
    end

    public_class_method def self.systemd_user_available?
      return false if which_bin(name: 'systemctl').empty?
      return false unless apply_native?

      system('systemctl', '--user', 'show-environment',
             out: File::NULL, err: File::NULL)
    rescue StandardError
      false
    end

    public_class_method def self.schtasks_available?
      !which_bin(name: 'schtasks').empty?
    end

    # Supported Method Parameters::
    #   PWN::Cron.scheduler_backend(os: optional, backend: optional force)
    public_class_method def self.scheduler_backend(opts = {})
      return opts[:backend].to_sym if opts[:backend]

      unless opts[:os]
        persisted = scheduler_config[:backend]
        return persisted if persisted
      end

      os = (opts[:os] || os_type).to_sym
      case os
      when :windows
        schtasks_available? ? :schtasks : :worker
      when :osx
        :launchd
      when :linux
        if systemd_user_available?
          :systemd_user
        elsif crontab_available?
          :crontab
        else
          :worker
        end
      else
        crontab_available? ? :crontab : :worker
      end
    end

    public_class_method def self.native_unit_dir(opts = {})
      backend = (opts[:backend] || scheduler_backend).to_sym
      sandboxed = !ENV['PWN_CRON_DIR'].to_s.empty? || !apply_native?(opts)
      return File.join(cron_dir, 'native') if sandboxed

      case backend
      when :launchd
        File.join(Dir.home, 'Library', 'LaunchAgents')
      when :systemd_user
        File.join(Dir.home, '.config', 'systemd', 'user')
      else
        File.join(cron_dir, 'native')
      end
    end

    public_class_method def self.ruby_lib_dir
      File.expand_path('..', __dir__)
    end

    public_class_method def self.ruby_eval_argv(opts = {})
      snippet = opts[:snippet].to_s
      [RbConfig.ruby, '-I', ruby_lib_dir, '-e', snippet]
    end

    public_class_method def self.ruby_eval_shell(opts = {})
      argv = ruby_eval_argv(opts)
      log = opts[:log]
      if windows?
        cmd = argv.map { |a| /[\s"]/.match?(a) ? "\"#{a.gsub('"', '""')}\"" : a }.join(' ')
        log ? "#{cmd} >> #{log} 2>&1" : cmd
      else
        cmd = Shellwords.join(argv)
        log ? "#{cmd} >> #{Shellwords.escape(log.to_s)} 2>&1" : cmd
      end
    end

    # Convert a 5-field cron expression into a portable calendar hash.
    # Returns nil for relative schedules or expressions we cannot map.
    public_class_method def self.cron_to_calendar(opts = {})
      schedule = opts[:schedule].to_s.strip
      return nil if relative_seconds(schedule: schedule)

      fields = schedule.split
      return nil unless fields.length == 5

      min, hour, mday, mon, wday = fields
      return nil unless min.match?(/\A\d+\z/) && hour.match?(/\A\d+\z/)
      return nil unless mon == '*'

      minute = min.to_i
      hr = hour.to_i
      return nil unless minute.between?(0, 59) && hr.between?(0, 23)

      if mday == '*' && wday == '*'
        { kind: :daily, minute: minute, hour: hr }
      elsif mday == '*' && wday.match?(/\A[0-7]\z/)
        wd = wday.to_i
        wd = 0 if wd == 7
        { kind: :weekly, minute: minute, hour: hr, wday: wd }
      elsif wday == '*' && mday.match?(/\A\d+\z/)
        { kind: :monthly, minute: minute, hour: hr, mday: mday.to_i }
      end
    end

    public_class_method def self.systemd_on_calendar(opts = {})
      cal = opts[:calendar] || cron_to_calendar(schedule: opts[:schedule])
      return nil unless cal

      hhmmss = format('%<h>02d:%<m>02d:00', h: cal[:hour], m: cal[:minute])
      case cal[:kind]
      when :daily then "*-*-* #{hhmmss}"
      when :weekly
        dow = %w[Sun Mon Tue Wed Thu Fri Sat][cal[:wday]]
        "#{dow} *-*-* #{hhmmss}"
      when :monthly then "*-*-#{format('%<d>02d', d: cal[:mday])} #{hhmmss}"
      end
    end

    public_class_method def self.launchd_calendar_interval(opts = {})
      cal = opts[:calendar] || cron_to_calendar(schedule: opts[:schedule])
      return nil unless cal

      ints = { 'Hour' => cal[:hour], 'Minute' => cal[:minute] }
      ints['Weekday'] = cal[:wday] if cal[:kind] == :weekly
      ints['Day'] = cal[:mday] if cal[:kind] == :monthly
      ints
    end

    public_class_method def self.schtasks_spec(opts = {})
      cal = opts[:calendar] || cron_to_calendar(schedule: opts[:schedule])
      return nil unless cal

      st = format('%<h>02d:%<m>02d', h: cal[:hour], m: cal[:minute])
      case cal[:kind]
      when :daily then { sc: 'DAILY', st: st }
      when :weekly
        days = %w[SUN MON TUE WED THU FRI SAT]
        { sc: 'WEEKLY', st: st, d: days[cal[:wday]] }
      when :monthly then { sc: 'MONTHLY', st: st, d: cal[:mday].to_s }
      end
    end
    # Supported Method Parameters::
    #   PWN::Cron.install_scheduler(
    #     enabled: true,
    #     backend: optional force,
    #     apply:   optional (default true unless PWN_CRON_DIR is set),
    #     sync_jobs: true
    #   )
    public_class_method def self.install_scheduler(opts = {})
      enabled = opts.fetch(:enabled, true)
      return uninstall_scheduler(opts) unless enabled

      backend = scheduler_backend(opts)
      apply = apply_native?(opts)
      %i[systemd_user launchd schtasks crontab].each do |other|
        next if other == backend

        uninstall_scheduler(backend: other, apply: apply, persist: false, stop: false)
      end

      persist_scheduler_config(enabled: true, backend: backend)
      result = case backend
               when :systemd_user then install_systemd_user_worker(apply: apply)
               when :launchd then install_launchd_worker(apply: apply)
               when :schtasks then install_schtasks_worker(apply: apply)
               when :crontab then install_crontab_worker(apply: apply)
               else
                 { backend: :worker, persisted: false, note: 'in-process worker only' }
               end

      jobs_sync = if opts.fetch(:sync_jobs, true)
                    sync_native_jobs(backend: backend, apply: apply)
                  else
                    []
                  end
      { ok: true, backend: backend, apply: apply, worker: result, jobs: jobs_sync }
    rescue StandardError => e
      warn("[PWN::Cron] install_scheduler failed: #{e.class}: #{e.message}")
      { ok: false, error: "#{e.class}: #{e.message}" }
    end

    public_class_method def self.uninstall_scheduler(opts = {})
      backend = (opts[:backend] || scheduler_config[:backend] || scheduler_backend).to_sym
      apply = apply_native?(opts)
      persist_scheduler_config(enabled: false, backend: backend) unless opts[:persist] == false
      stop_worker if opts.fetch(:stop, true)

      removed = case backend
                when :systemd_user then uninstall_systemd_user(apply: apply)
                when :launchd then uninstall_launchd(apply: apply)
                when :schtasks then uninstall_schtasks(apply: apply)
                when :crontab then uninstall_crontab(apply: apply)
                else
                  []
                end
      { ok: true, backend: backend, apply: apply, removed: removed }
    rescue StandardError => e
      warn("[PWN::Cron] uninstall_scheduler failed: #{e.class}: #{e.message}")
      { ok: false, error: "#{e.class}: #{e.message}" }
    end

    public_class_method def self.sync_scheduler(opts = {})
      return uninstall_scheduler(opts) unless opts.fetch(:enabled, cron_enabled?)

      install_scheduler(opts.merge(sync_jobs: true))
    end

    public_class_method def self.scheduler_status(opts = {})
      backend = scheduler_backend(opts)
      {
        os: os_type,
        backend: backend,
        enabled: cron_enabled?,
        apply: apply_native?(opts),
        config: scheduler_config,
        worker: worker_status,
        unit_dir: native_unit_dir(backend: backend, apply: apply_native?(opts))
      }
    end

    public_class_method def self.install_native_job(opts = {})
      job = opts[:job]
      return nil unless job.is_a?(Hash) && job[:id]

      backend = (opts[:backend] || scheduler_backend).to_sym
      apply = apply_native?(opts)
      case backend
      when :crontab then install_crontab_job(job: job, apply: apply)
      when :systemd_user then install_systemd_user_job(job: job, apply: apply)
      when :launchd then install_launchd_job(job: job, apply: apply)
      when :schtasks then install_schtasks_job(job: job, apply: apply)
      else
        { backend: backend, skipped: true, reason: :worker_only }
      end
    end

    public_class_method def self.remove_native_job(opts = {})
      job = opts[:job] || { id: opts[:id], name: opts[:name] }
      backend = (opts[:backend] || scheduler_backend).to_sym
      apply = apply_native?(opts)
      case backend
      when :crontab then uninstall_crontab_job(job: job, apply: apply)
      when :systemd_user then uninstall_systemd_user_job(job: job, apply: apply)
      when :launchd then uninstall_launchd_job(job: job, apply: apply)
      when :schtasks then uninstall_schtasks_job(job: job, apply: apply)
      else
        { backend: backend, skipped: true }
      end
    end

    public_class_method def self.sync_native_jobs(opts = {})
      backend = (opts[:backend] || scheduler_backend).to_sym
      apply = apply_native?(opts)
      load_jobs.map do |_id, job|
        next unless job.is_a?(Hash)

        if job[:enabled]
          install_native_job(job: job, backend: backend, apply: apply)
        else
          remove_native_job(job: job, backend: backend, apply: apply)
        end
      end.compact
    end
    # ---- crontab -------------------------------------------------------

    public_class_method def self.install_crontab_worker(opts = {})
      apply = apply_native?(opts)
      marker = 'PWN::Cron.ensure_worker'
      line = "@reboot #{ruby_eval_shell(snippet: 'require "pwn"; PWN::Cron.ensure_worker(restart: false)', log: worker_log)}"
      preview = "# pwn-cron worker\n#{line}\n"
      write_native_preview(name: 'worker.crontab', body: preview)
      return { backend: :crontab, apply: false, line: line } unless apply && crontab_available?

      existing = crontab_read
      return { backend: :crontab, already: true, line: line } if existing.include?(marker)

      crontab_write(body: "#{existing.rstrip}\n#{preview}")
      { backend: :crontab, apply: true, line: line }
    end

    public_class_method def self.install_crontab_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      snippet = "require \"pwn\"; PWN::Cron.run(id: #{job[:id].to_s.inspect})"
      line = "#{job[:schedule]} #{ruby_eval_shell(snippet: snippet, log: File.join(cron_dir, 'cron.log'))}"
      block = "# pwn-cron #{job[:name]} (#{job[:id]})\n#{line}\n"
      write_native_preview(name: "job-#{job[:id]}.crontab", body: block)
      return { backend: :crontab, apply: false, line: line, id: job[:id] } unless apply && crontab_available?

      existing = crontab_read
      return { backend: :crontab, already: true, id: job[:id], line: line } if existing.include?(job[:id].to_s)

      crontab_write(body: "#{existing.rstrip}\n#{block}")
      { backend: :crontab, apply: true, id: job[:id], line: line }
    end

    public_class_method def self.uninstall_crontab(opts = {})
      apply = apply_native?(opts)
      return [:preview] unless apply && crontab_available?

      existing = crontab_read
      cleaned = strip_pwn_crontab(existing: existing)
      crontab_write(body: cleaned) if cleaned != existing
      [:crontab]
    end

    public_class_method def self.uninstall_crontab_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      FileUtils.rm_f(File.join(cron_dir, 'native', "job-#{job[:id]}.crontab"))
      return { backend: :crontab, apply: false, id: job[:id] } unless apply && crontab_available?

      existing = crontab_read
      cleaned = strip_pwn_crontab(existing: existing, id: job[:id].to_s)
      crontab_write(body: cleaned) if cleaned != existing
      { backend: :crontab, apply: true, id: job[:id], removed: true }
    end

    # ---- systemd --user ------------------------------------------------

    public_class_method def self.install_systemd_user_worker(opts = {})
      apply = apply_native?(opts)
      exec_start = ruby_eval_shell(
        snippet: 'require "pwn"; PWN::Cron.start_worker(restart: false, foreground: true)'
      )
      body = <<~UNIT
        [Unit]
        Description=PWN cron worker (evaluates ~/.pwn/cron/jobs.yml schedules)
        After=default.target

        [Service]
        Type=simple
        ExecStart=#{exec_start}
        Restart=always
        RestartSec=5
        Environment=PWN_CRON_DIR=#{cron_dir}
        WorkingDirectory=#{ruby_lib_dir}

        [Install]
        WantedBy=default.target
      UNIT
      path = write_unit_file(backend: :systemd_user, name: SYSTEMD_WORKER_UNIT, body: body, apply: apply)
      if apply
        systemd_user(args: ['daemon-reload'])
        systemd_user(args: ['enable', '--now', SYSTEMD_WORKER_UNIT])
        enable_linger
      end
      { backend: :systemd_user, unit: SYSTEMD_WORKER_UNIT, path: path, apply: apply }
    end

    public_class_method def self.install_systemd_user_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      cal = cron_to_calendar(schedule: job[:schedule])
      oncal = systemd_on_calendar(calendar: cal)
      return { backend: :systemd_user, id: job[:id], skipped: true, reason: :no_calendar } unless oncal

      svc = systemd_job_service(job: job)
      tmr = systemd_job_timer(job: job)
      snippet = "require \"pwn\"; PWN::Cron.run(id: #{job[:id].to_s.inspect})"
      exec_start = ruby_eval_shell(snippet: snippet)
      svc_body = <<~UNIT
        [Unit]
        Description=PWN cron job #{job[:name]} (#{job[:id]})

        [Service]
        Type=oneshot
        ExecStart=#{exec_start}
        Environment=PWN_CRON_DIR=#{cron_dir}
      UNIT
      tmr_body = <<~UNIT
        [Unit]
        Description=PWN cron timer #{job[:name]} (#{job[:schedule]})

        [Timer]
        OnCalendar=#{oncal}
        Persistent=true
        Unit=#{svc}

        [Install]
        WantedBy=timers.target
      UNIT
      svc_path = write_unit_file(backend: :systemd_user, name: svc, body: svc_body, apply: apply)
      tmr_path = write_unit_file(backend: :systemd_user, name: tmr, body: tmr_body, apply: apply)
      if apply
        systemd_user(args: ['daemon-reload'])
        systemd_user(args: ['enable', '--now', tmr])
      end
      { backend: :systemd_user, id: job[:id], service: svc, timer: tmr, on_calendar: oncal,
        paths: [svc_path, tmr_path], apply: apply }
    end

    public_class_method def self.uninstall_systemd_user(opts = {})
      apply = apply_native?(opts)
      names = [SYSTEMD_WORKER_UNIT]
      load_jobs.each_value do |job|
        next unless job.is_a?(Hash)

        names << systemd_job_timer(job: job)
        names << systemd_job_service(job: job)
      end
      if apply
        names.each { |u| systemd_user(args: ['disable', '--now', u]) }
        systemd_user(args: ['daemon-reload'])
      end
      names.each { |n| rm_unit_file(backend: :systemd_user, name: n, apply: apply) }
      names
    end

    public_class_method def self.uninstall_systemd_user_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      svc = systemd_job_service(job: job)
      tmr = systemd_job_timer(job: job)
      if apply
        systemd_user(args: ['disable', '--now', tmr])
        systemd_user(args: ['disable', '--now', svc])
        systemd_user(args: ['daemon-reload'])
      end
      rm_unit_file(backend: :systemd_user, name: svc, apply: apply)
      rm_unit_file(backend: :systemd_user, name: tmr, apply: apply)
      { backend: :systemd_user, id: job[:id], removed: [svc, tmr] }
    end
    # ---- launchd -------------------------------------------------------

    public_class_method def self.install_launchd_worker(opts = {})
      apply = apply_native?(opts)
      label = LAUNCHD_WORKER_LABEL
      plist = launchd_plist(
        label: label,
        argv: ruby_eval_argv(snippet: 'require "pwn"; PWN::Cron.start_worker(restart: false, foreground: true)'),
        keepalive: true,
        run_at_load: true
      )
      path = write_unit_file(backend: :launchd, name: "#{label}.plist", body: plist, apply: apply)
      launchctl_load(path: path, label: label) if apply
      { backend: :launchd, label: label, path: path, apply: apply }
    end

    public_class_method def self.install_launchd_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      ints = launchd_calendar_interval(schedule: job[:schedule])
      return { backend: :launchd, id: job[:id], skipped: true, reason: :no_calendar } unless ints

      label = launchd_job_label(job: job)
      argv = ruby_eval_argv(snippet: "require \"pwn\"; PWN::Cron.run(id: #{job[:id].to_s.inspect})")
      plist = launchd_plist(label: label, argv: argv, keepalive: false, run_at_load: false, calendar: ints)
      path = write_unit_file(backend: :launchd, name: "#{label}.plist", body: plist, apply: apply)
      launchctl_load(path: path, label: label) if apply
      { backend: :launchd, id: job[:id], label: label, path: path, calendar: ints, apply: apply }
    end

    public_class_method def self.uninstall_launchd(opts = {})
      apply = apply_native?(opts)
      labels = [LAUNCHD_WORKER_LABEL]
      load_jobs.each_value do |job|
        next unless job.is_a?(Hash)

        labels << launchd_job_label(job: job)
      end
      labels.each do |label|
        path = unit_file_path(backend: :launchd, name: "#{label}.plist", apply: apply)
        launchctl_unload(path: path, label: label) if apply
        rm_unit_file(backend: :launchd, name: "#{label}.plist", apply: apply)
      end
      labels
    end

    public_class_method def self.uninstall_launchd_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      label = launchd_job_label(job: job)
      path = unit_file_path(backend: :launchd, name: "#{label}.plist", apply: apply)
      launchctl_unload(path: path, label: label) if apply
      rm_unit_file(backend: :launchd, name: "#{label}.plist", apply: apply)
      { backend: :launchd, id: job[:id], removed: label }
    end

    # ---- schtasks (Windows) -------------------------------------------

    public_class_method def self.install_schtasks_worker(opts = {})
      apply = apply_native?(opts)
      tr = ruby_eval_shell(snippet: 'require "pwn"; PWN::Cron.ensure_worker(restart: false)')
      argv = ['schtasks', '/Create', '/F', '/TN', SCHTASKS_WORKER_NAME, '/SC', 'ONLOGON', '/RL', 'LIMITED', '/TR', tr]
      write_native_preview(name: 'worker.schtasks.txt', body: argv.inspect)
      run_argv(argv: argv) if apply && schtasks_available?
      { backend: :schtasks, name: SCHTASKS_WORKER_NAME, tr: tr, apply: apply }
    end

    public_class_method def self.install_schtasks_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      spec = schtasks_spec(schedule: job[:schedule])
      return { backend: :schtasks, id: job[:id], skipped: true, reason: :no_calendar } unless spec

      name = schtasks_job_name(job: job)
      tr = ruby_eval_shell(snippet: "require \"pwn\"; PWN::Cron.run(id: #{job[:id].to_s.inspect})")
      argv = ['schtasks', '/Create', '/F', '/TN', name, '/SC', spec[:sc], '/ST', spec[:st], '/RL', 'LIMITED', '/TR', tr]
      argv += ['/D', spec[:d]] if spec[:d]
      write_native_preview(name: "job-#{job[:id]}.schtasks.txt", body: argv.inspect)
      run_argv(argv: argv) if apply && schtasks_available?
      { backend: :schtasks, id: job[:id], name: name, spec: spec, apply: apply }
    end

    public_class_method def self.uninstall_schtasks(opts = {})
      apply = apply_native?(opts)
      names = [SCHTASKS_WORKER_NAME]
      load_jobs.each_value do |job|
        next unless job.is_a?(Hash)

        names << schtasks_job_name(job: job)
      end
      names.each { |n| run_argv(argv: ['schtasks', '/Delete', '/F', '/TN', n]) if apply && schtasks_available? }
      names
    end

    public_class_method def self.uninstall_schtasks_job(opts = {})
      job = opts[:job]
      apply = apply_native?(opts)
      name = schtasks_job_name(job: job)
      run_argv(argv: ['schtasks', '/Delete', '/F', '/TN', name]) if apply && schtasks_available?
      FileUtils.rm_f(File.join(cron_dir, 'native', "job-#{job[:id]}.schtasks.txt"))
      { backend: :schtasks, id: job[:id], removed: name }
    end
    # ---- helpers -------------------------------------------------------

    private_class_method def self.windows_taskkill(opts = {})
      pid = opts[:pid]
      return unless pid

      system('taskkill', '/PID', pid.to_s, '/F', '/T', out: File::NULL, err: File::NULL)
    rescue StandardError
      nil
    end

    private_class_method def self.write_native_preview(opts = {})
      dir = File.join(cron_dir, 'native')
      FileUtils.mkdir_p(dir)
      File.write(File.join(dir, opts[:name].to_s), opts[:body].to_s)
    end

    private_class_method def self.unit_file_path(opts = {})
      File.join(native_unit_dir(backend: opts[:backend], apply: opts[:apply]), opts[:name].to_s)
    end

    private_class_method def self.write_unit_file(opts = {})
      dir = native_unit_dir(backend: opts[:backend], apply: opts[:apply])
      FileUtils.mkdir_p(dir)
      path = File.join(dir, opts[:name].to_s)
      File.write(path, opts[:body].to_s)
      write_native_preview(name: opts[:name], body: opts[:body]) unless dir == File.join(cron_dir, 'native')
      path
    end

    private_class_method def self.rm_unit_file(opts = {})
      FileUtils.rm_f(unit_file_path(opts))
      FileUtils.rm_f(File.join(cron_dir, 'native', opts[:name].to_s))
    end

    private_class_method def self.crontab_read
      `crontab -l 2>/dev/null`.to_s
    rescue StandardError
      ''
    end

    private_class_method def self.crontab_write(opts = {})
      body = opts[:body]
      IO.popen('crontab -', 'w') { |io| io.write(body.to_s.end_with?("\n") ? body : "#{body}\n") }
    end

    private_class_method def self.strip_pwn_crontab(opts = {})
      existing = opts[:existing]
      id = opts[:id]
      lines = existing.to_s.split("\n")
      out = []
      skip = false
      lines.each do |line|
        if id
          if line.include?("(#{id})") || line.include?(id)
            skip = line.start_with?('#')
            next
          end
          if skip
            skip = false
            next unless line.start_with?('#')
          end
        elsif line.match?(/# pwn-cron\b/) || line.include?('PWN::Cron.ensure_worker') || line.include?('PWN::Cron.run(id:')
          skip = line.start_with?('#')
          next
        elsif skip
          skip = false
          next
        end
        out << line
      end
      "#{out.join("\n").rstrip}\n"
    end

    private_class_method def self.systemd_user(opts = {})
      system('systemctl', '--user', *Array(opts[:args]), out: File::NULL, err: File::NULL)
    rescue StandardError
      nil
    end

    private_class_method def self.enable_linger
      user = begin
        Etc.getlogin || Etc.getpwuid(Process.uid).name
      rescue StandardError
        nil
      end
      return unless user && !which_bin(name: 'loginctl').empty?

      system('loginctl', 'enable-linger', user, out: File::NULL, err: File::NULL)
    rescue StandardError
      nil
    end

    private_class_method def self.systemd_job_service(opts = {})
      job = opts[:job]
      "pwn-cron-j#{job[:id]}.service"
    end

    private_class_method def self.systemd_job_timer(opts = {})
      job = opts[:job]
      "pwn-cron-j#{job[:id]}.timer"
    end

    private_class_method def self.launchd_job_label(opts = {})
      job = opts[:job]
      "com.0dayinc.pwn.cron.job.#{job[:id]}"
    end

    private_class_method def self.schtasks_job_name(opts = {})
      job = opts[:job]
      "PWN\\job-#{job[:id]}"
    end

    private_class_method def self.xml_escape(opts = {})
      opts[:str].to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;').gsub('"', '&quot;')
    end

    private_class_method def self.launchd_plist(opts = {})
      argv_xml = Array(opts[:argv]).map { |a| "    <string>#{xml_escape(str: a)}</string>" }.join("\n")
      cal = opts[:calendar]
      cal_xml = if cal
                  keys = cal.map { |k, v| "    <key>#{k}</key>\n    <integer>#{v}</integer>" }.join("\n")
                  "  <key>StartCalendarInterval</key>\n  <dict>\n#{keys}\n  </dict>\n"
                else
                  ''
                end
      env = "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>PWN_CRON_DIR</key>\n    <string>#{xml_escape(str: cron_dir)}</string>\n  </dict>\n"
      <<~PLIST
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>#{xml_escape(str: opts[:label])}</string>
          <key>ProgramArguments</key>
          <array>
        #{argv_xml}
          </array>
        #{env}  <key>RunAtLoad</key>
          <#{opts[:run_at_load] ? 'true' : 'false'}/>
          <key>KeepAlive</key>
          <#{opts[:keepalive] ? 'true' : 'false'}/>
          <key>StandardOutPath</key>
          <string>#{xml_escape(str: worker_log)}</string>
          <key>StandardErrorPath</key>
          <string>#{xml_escape(str: worker_log)}</string>
        #{cal_xml}</dict>
        </plist>
      PLIST
    end

    private_class_method def self.launchctl_load(opts = {})
      uid = Process.uid
      domain = "gui/#{uid}/#{opts[:label]}"
      system('launchctl', 'bootout', domain, out: File::NULL, err: File::NULL)
      unless system('launchctl', 'bootstrap', "gui/#{uid}", opts[:path].to_s, out: File::NULL, err: File::NULL)
        system('launchctl', 'unload', opts[:path].to_s, out: File::NULL, err: File::NULL)
        system('launchctl', 'load', '-w', opts[:path].to_s, out: File::NULL, err: File::NULL)
      end
    rescue StandardError
      nil
    end

    private_class_method def self.launchctl_unload(opts = {})
      uid = Process.uid
      system('launchctl', 'bootout', "gui/#{uid}/#{opts[:label]}", out: File::NULL, err: File::NULL)
      system('launchctl', 'unload', opts[:path].to_s, out: File::NULL, err: File::NULL)
    rescue StandardError
      nil
    end

    private_class_method def self.run_argv(opts = {})
      system(*Array(opts[:argv]), out: File::NULL, err: File::NULL)
    rescue StandardError
      nil
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
                  # OS-native persistence (systemd --user / launchd / schtasks / crontab)
                  PWN::Cron.install_scheduler
                  PWN::Cron.uninstall_scheduler
                  PWN::Cron.sync_scheduler
                  PWN::Cron.scheduler_backend
        PWN::Cron.install_defaults  # seed S1/P3/W2/M1 curriculum jobs (idempotent)
        PWN::Cron.ensure_worker     # start/restart the background scheduler
        PWN::Cron.worker_status
        PWN::Cron.tick              # fire currently-due jobs once

                  #{self}.authors
      USAGE
    end
  end
end
