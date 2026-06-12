# frozen_string_literal: true

require 'yaml'
require 'fileutils'
require 'time'
require 'securerandom'

module PWN
  # PWN::Cron provides cron / scheduled task management for the pwn-ai agent.
  # Jobs are defined in ~/.pwn/cron/jobs.yml and can be triggered by system
  # cron, manual run, or from within pwn-ai agent loops.
  #
  # Each job can contain a prompt (for pwn-ai), a ruby script snippet, or
  # reference to external script. Delivery can be 'log' (default), 'email', etc.
  # (email would require additional plugins).
  module Cron
    CRON_DIR = File.join(Dir.home, '.pwn', 'cron')
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
      id = opts[:id]
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
      id = opts[:id]
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
    # (assumes /opt/pwn and rvm ruby-4.0.1@pwn - user can edit crontab)
    public_class_method def self.install_crontab_entry(opts = {})
      job = opts[:job]
      cron_line = "#{job[:schedule]} cd /opt/pwn && /usr/local/rvm/bin/rvm ruby-4.0.1@pwn do ruby -I lib -e 'require \"pwn\"; PWN::Cron.run(id: \"#{job[:id]}\")' >> #{File.join(cron_dir, 'cron.log')} 2>&1"
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
      return {} unless File.exist?(JOBS_FILE)

      YAML.safe_load_file(JOBS_FILE, symbolize_names: true) || {}
    rescue StandardError
      {}
    end

    private_class_method def self.save_jobs(opts = {})
      jobs = opts[:jobs] ||= {}
      File.write(JOBS_FILE, YAML.dump(jobs))
    end

    private_class_method def self.toggle(opts = {})
      id = opts[:id]
      enabled = opts[:enabled]
      jobs = load_jobs
      if jobs[id]
        jobs[id][:enabled] = enabled
        save_jobs(jobs: jobs)
      end
      jobs[id]
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

          #{self}.authors
      USAGE
    end
  end
end
