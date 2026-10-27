# frozen_string_literal: true

require 'json'
require 'yaml'
require 'fileutils'
require 'time'
require 'digest'
require 'find'
require 'securerandom'

module PWN
  # PWN::Migrate — the ~/.pwn state **doctor** and **auto-migrator**.
  #
  # PWN persists a growing set of files under `~/.pwn` (encrypted config,
  # memory, learning outcomes, metrics, mistakes, extrospection, cron
  # jobs, agents, skills, sessions, swarm buses, …).  Each file is owned
  # by a different module and each release can add keys or change shape.
  # A user upgrading `gem install pwn` between two versions could
  # therefore hit `KeyError`, `NoMethodError for nil`, or a silent
  # empty-fallback because their on-disk state predates the new loader.
  #
  # `PWN::Migrate` closes that gap.  It is called from:
  #
  #   * `pwn setup --migrate`       — explicit doctor + autofix
  #   * `PWN::Setup.check`          — read-only ~/.pwn state section
  #   * `PWN::Config.refresh_env`   — one-line drift warning on every launch
  #
  # It works by:
  #
  #   1. Stamping `~/.pwn/.schema` with `{ schema:, pwn_version:, at: }`
  #      the first time it runs.  Any release that changes the on-disk
  #      shape of a `~/.pwn` file bumps `SCHEMA_VERSION` here and appends
  #      an idempotent lambda to `MIGRATIONS`.
  #   2. Declaratively verifying every state file against its OWNING
  #      module's own loader (`STATE_FILES`) — no re-implemented parsers.
  #      If the raw file has bytes but the owner returned its
  #      empty-fallback, the file is flagged incompatible.
  #   3. Autofixing:  timestamped backup → ordered schema migrations →
  #      per-file repair (quarantine corrupt / re-seed missing) →
  #      `pwn.yaml` deep-key backfill (missing keys from the current
  #      `PWN::Config.env_template` are merged in-place under the user's
  #      values, then the vault is re-encrypted with the SAME key/iv).
  #
  # Everything is idempotent, dry-run capable, and never overwrites a
  # user-set value.
  module Migrate
    PWN_ROOT       = File.join(Dir.home, '.pwn')
    SCHEMA_FILE    = File.join(PWN_ROOT, '.schema')
    BACKUP_ROOT    = File.join(PWN_ROOT, 'backup')
    QUARANTINE_DIR = File.join(PWN_ROOT, 'quarantine')

    # Bump this whenever the shape of any file under ~/.pwn changes in a
    # way that requires a one-time transform.  Add the transform as an
    # entry in MIGRATIONS keyed by the NEW schema number.
    SCHEMA_VERSION = 11

    OK   = "\e[32mok\e[0m"
    BAD  = "\e[31mFAIL\e[0m"
    WARN = "\e[33mdrift\e[0m"

    # ──────────────────────────────────────────────────────────────────
    # Declarative registry of every persisted ~/.pwn artefact.
    #
    # Each entry knows how to (a) locate itself, (b) ask its owning
    # module to load it, and (c) decide whether the loaded shape is what
    # this pwn version expects.  Verifiers are intentionally SHALLOW —
    # they detect "loader gave up and returned the fallback" rather than
    # re-validating every key, so ownership stays with the module.
    #
    # :fix values:
    #   :quarantine — move the file aside; owner re-seeds on next write
    #   :vault      — deep-merge missing keys from PWN::Config.env_template
    #   :seed       — call the owner's idempotent seeder (dirs / defaults)
    #   :jsonl      — strip unparsable lines only (keeps good history)
    #   :skills     — PWN::Config.migrate_legacy_skills
    # ──────────────────────────────────────────────────────────────────
    STATE_FILES = {
      'pwn.yaml' => {
        owner: 'PWN::Config',
        kind: :vault,
        fix: :vault,
        verify: lambda { |p, _raw|
          return { ok: false, why: 'missing' } unless File.file?(p)

          enc = PWN::Plugins::Vault.file_encrypted?(file: p)
          # Shape (missing keys vs env_template) is checked separately in
          # .vault_drift because it requires the decryptor.
          { ok: enc, why: enc ? nil : 'not encrypted (run PWN::Plugins::Vault.create)' }
        }
      },
      'memory.json' => {
        owner: 'PWN::Memory',
        kind: :json,
        fix: :quarantine,
        verify: lambda { |_p, raw|
          m = PWN::Memory.load
          bad = m.reject { |_k, v| v.is_a?(Hash) && v.key?(:value) }
          { ok: !(m.empty? && raw.to_s.length > 4) && bad.empty?,
            why: bad.any? ? "#{bad.length} entries missing :value" : nil }
        }
      },
      'memory.idx' => {
        owner: 'PWN::MemoryIndex',
        kind: :blob,
        fix: :quarantine,
        verify: ->(_p, _raw) { { ok: true } }
      },
      'learning.jsonl' => {
        owner: 'PWN::AI::Agent::Learning',
        kind: :jsonl,
        fix: :jsonl,
        verify: :jsonl
      },
      'preferences.jsonl' => {
        owner: 'PWN::AI::Agent::Reward',
        kind: :jsonl,
        fix: :jsonl,
        verify: :jsonl
      },
      'metrics.json' => {
        owner: 'PWN::AI::Agent::Metrics',
        kind: :json,
        fix: :quarantine,
        verify: lambda { |_p, raw|
          m = PWN::AI::Agent::Metrics.load
          fell_back = m == { tools: {}, updated_at: nil } && raw.to_s.length > 4
          { ok: m.is_a?(Hash) && m.key?(:tools) && !fell_back,
            why: fell_back ? 'loader fell back to empty (unparsable / wrong shape)' : nil }
        }
      },
      'mistakes.json' => {
        owner: 'PWN::AI::Agent::Mistakes',
        kind: :json,
        fix: :quarantine,
        verify: lambda { |_p, raw|
          m = PWN::AI::Agent::Mistakes.load
          fell_back = m.empty? && raw.to_s.length > 4
          { ok: m.is_a?(Hash) && !fell_back, why: fell_back ? 'loader fell back to {}' : nil }
        }
      },
      'extrospection.json' => {
        owner: 'PWN::AI::Agent::Extrospection',
        kind: :json,
        fix: :quarantine,
        verify: lambda { |_p, raw|
          m = PWN::AI::Agent::Extrospection.load
          shape = m.is_a?(Hash) && m.key?(:observations) && m[:observations].is_a?(Array)
          fell_back = shape && m[:snapshot].to_h.empty? && m[:observations].empty? && raw.to_s.length > 8
          { ok: shape && !fell_back, why: shape ? nil : 'missing :observations array' }
        }
      },
      'reward_sentinel.json' => {
        owner: 'PWN::AI::Agent::Reward',
        kind: :json,
        fix: :quarantine,
        verify: ->(_p, _raw) { { ok: true } }
      },
      'agents.yml' => {
        owner: 'PWN::AI::Agent::Swarm',
        kind: :yaml,
        fix: :quarantine,
        verify: lambda { |_p, raw|
          m = PWN::AI::Agent::Swarm.personas
          fell_back = m.empty? && raw.to_s.strip.length > 4
          bad = m.reject { |_k, v| v.is_a?(Hash) && v[:role] }
          { ok: !fell_back && bad.empty?,
            why: (fell_back && 'loader fell back to {}') || (bad.any? && "#{bad.length} personas missing :role") || nil }
        }
      },
      'cron/jobs.yml' => {
        owner: 'PWN::Cron',
        kind: :yaml,
        fix: :seed,
        verify: lambda { |_p, raw|
          j = PWN::Cron.list
          fell_back = j.empty? && raw.to_s.strip.length > 8
          bad = j.reject { |_id, v| v.is_a?(Hash) && v[:schedule] }
          { ok: !fell_back && bad.empty?,
            why: (fell_back && 'loader fell back to {}') || (bad.any? && "#{bad.length} jobs missing :schedule") || nil }
        }
      },
      'skills/' => {
        owner: 'PWN::Config',
        kind: :dir,
        fix: :skills,
        verify: lambda { |p, _raw|
          return { ok: true } unless File.directory?(p)

          legacy = Dir.glob(File.join(p, '*.{rb,md,txt,skill,yml,yaml}')).length
          { ok: legacy.zero?, why: legacy.zero? ? nil : "#{legacy} legacy flat skill file(s)" }
        }
      },
      'sessions/' => { owner: 'PWN::Sessions', kind: :dir, fix: :seed, verify: ->(_p, _r) { { ok: true } } },
      'swarm/' => { owner: 'PWN::AI::Agent::Swarm', kind: :dir, fix: :seed, verify: ->(_p, _r) { { ok: true } } },
      'curriculum/' => { owner: 'PWN::AI::Agent::Curriculum', kind: :dir, fix: :seed, verify: ->(_p, _r) { { ok: true } } },
      'finetune/' => { owner: 'PWN::AI::Agent::Curriculum', kind: :dir, fix: :seed, verify: ->(_p, _r) { { ok: true } } },
      'extrospection/' => { owner: 'PWN::AI::Agent::Extrospection', kind: :dir, fix: :seed, verify: ->(_p, _r) { { ok: true } } }
    }.freeze

    # Ordered, idempotent one-shot transforms.  Key == the schema number
    # a ~/.pwn tree is AT after the lambda runs.  Add a new entry every
    # time SCHEMA_VERSION is bumped.  Each lambda receives (root, io).
    MIGRATIONS = {
      1 => lambda { |root, io|
        # v0 → v1 : agentskills.io directory layout + seeded RL cron jobs
        #           + ensure all state subdirs exist.
        %w[skills sessions swarm cron curriculum finetune extrospection].each do |d|
          FileUtils.mkdir_p(File.join(root, d))
        end
        r = begin
          PWN::Config.migrate_legacy_skills
        rescue StandardError
          { migrated: 0 }
        end
        io.puts "    · migrate_legacy_skills → #{r[:migrated]} converted" if r[:migrated].to_i.positive?
        PWN::Config.install_default_skills if defined?(PWN::Config)
        PWN::Cron.install_defaults if defined?(PWN::Cron)
      },
      2 => lambda { |root, io|
        path = File.join(root, 'agents.yml')
        r = if defined?(PWN::AI::Agent::Swarm) && PWN::AI::Agent::Swarm.respond_to?(:migrate_personas)
              PWN::AI::Agent::Swarm.migrate_personas(path: path)
            else
              { changed: false }
            end
        io.puts "    · agents.yml #{Array(r[:patched]).join(', ')}" if r[:changed]
      },
      3 => lambda { |root, io|
        path = File.join(root, 'agents.yml')
        next unless File.file?(path)

        raw = YAML.safe_load_file(path, permitted_classes: [Symbol], aliases: true)
        next unless raw.is_a?(Hash)

        patched = 0
        raw.each_value do |persona|
          next unless persona.is_a?(Hash)
          next if persona.key?('model') || persona.key?(:model)

          persona['model'] = nil
          patched += 1
        end
        next if patched.zero?

        File.write(path, YAML.dump(raw))
        io.puts "    · agents.yml added default model to #{patched} personas"
      },
      4 => lambda { |_root, io|
        io.puts '    · pwn.yaml ai_sandbox, ai_router, model_routes task classes'
        PWN::Migrate.backfill_vault(io: io)
      },
      5 => lambda { |_root, io|
        io.puts '    · pwn.yaml ai.agent.skill_review'
        PWN::Migrate.backfill_vault(io: io)
      },
      6 => lambda { |_root, io|
        io.puts '    · pwn.yaml ai.tui.theme'
        PWN::Migrate.backfill_vault(io: io)
      },
      7 => lambda { |_root, io|
        io.puts '    · pwn.yaml ai.tui.theme.title'
        PWN::Migrate.backfill_vault(io: io)
      },
      8 => lambda { |_root, io|
        io.puts '    · guarded session_cleanup default cron payload and job'
        PWN::Cron.install_defaults
      },
      9 => lambda { |_root, io|
        io.puts '    · pwn.yaml plugins.meshtastic.channel short_name'
        PWN::Migrate.backfill_vault(io: io)
      },
      10 => lambda { |_root, io|
        io.puts '    · pwn.yaml ai reasoning_effort for anthropic, gemini, ollama, openwebui'
        PWN::Migrate.backfill_vault(io: io)
      },
      11 => lambda { |_root, io|
        io.puts '    · versioned housekeeping policy and managed session_cleanup helper'
        PWN::Cron.install_defaults
      }
    }.freeze

    # ──────────────────────────────────────────────────────────────────
    # public api
    # ──────────────────────────────────────────────────────────────────

    # Supported Method Parameters::
    # schema = PWN::Migrate.installed_schema
    #
    # → Integer schema number stamped in ~/.pwn/.schema (0 when absent).

    public_class_method def self.installed_schema
      return 0 unless File.file?(SCHEMA_FILE)

      JSON.parse(File.read(SCHEMA_FILE))['schema'].to_i
    rescue StandardError
      0
    end

    # Supported Method Parameters::
    # bool = PWN::Migrate.needed?
    #
    # Cheap predicate for PWN::Config.refresh_env — schema stamp only,
    # no per-file probes, so it adds ~0 to launch time.

    public_class_method def self.needed?
      File.directory?(PWN_ROOT) && installed_schema < SCHEMA_VERSION
    rescue StandardError
      false
    end

    # Supported Method Parameters::
    # rows = PWN::Migrate.status
    #
    # Per-file compatibility report — the machine-readable half of
    # `.check`.  Never writes.  Never raises (each verifier is rescued).

    public_class_method def self.status
      files = STATE_FILES.map do |rel, meta|
        path = File.join(PWN_ROOT, rel)
        exists = meta[:kind] == :dir ? File.directory?(path) : File.file?(path)
        raw = exists && meta[:kind] != :dir ? safe_read(path: path) : nil
        v = verify_one(path: path, raw: raw, meta: meta)
        {
          rel: rel, path: path, owner: meta[:owner], kind: meta[:kind],
          exists: exists, size: exists ? File.size?(path) : nil,
          ok: v[:ok], why: v[:why], fix: meta[:fix]
        }
      end
      {
        root: PWN_ROOT,
        schema_installed: installed_schema,
        schema_current: SCHEMA_VERSION,
        pwn_version: (defined?(PWN::VERSION) ? PWN::VERSION : nil),
        needs_migration: needed?,
        files: files,
        incompatible: files.reject { |f| f[:ok] }
      }
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # PWN::Migrate.check(
    #   io: 'optional - IO to write the report to (default $stdout)'
    # )
    #
    # Human-readable ~/.pwn state doctor.  Read-only.  Called from
    # PWN::Setup.check so `pwn setup` shows this alongside the
    # native-gem / toolchain report.

    public_class_method def self.check(opts = {})
      io = opts[:io] || $stdout
      st = status

      io.puts "~/.pwn state         schema #{st[:schema_installed]} → #{st[:schema_current]} " \
              "#{st[:needs_migration] ? "(#{WARN} — run `pwn setup --migrate`)" : "(#{OK})"}"
      st[:files].each do |f|
        mark = f[:ok] ? OK : BAD
        note = f[:ok] ? '' : "→ #{f[:why]}  [fix: #{f[:fix]}]"
        sz   = f[:exists] ? human_size(bytes: f[:size]) : '—'
        io.puts "  #{f[:rel].ljust(22)} #{mark}   #{sz.to_s.ljust(8)} #{f[:owner].to_s.ljust(30)} #{note}"
      end
      unless st[:incompatible].empty?
        io.puts
        io.puts "#{st[:incompatible].length} file(s) incompatible with pwn #{st[:pwn_version]} — " \
                'run `pwn setup --migrate --fix` to autofix (a timestamped backup is taken first).'
      end
      st
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # report = PWN::Migrate.run(
    #   fix:     'optional - also autofix incompatible files (default: schema-migrations only)',
    #   backup:  'optional - take timestamped backup of ~/.pwn first (default true)',
    #   dry_run: 'optional - report what WOULD happen, write nothing (default false)',
    #   key:     'optional - vault key   (default: read ~/.pwn/pwn.yaml.decryptor)',
    #   iv:      'optional - vault iv    (default: read ~/.pwn/pwn.yaml.decryptor)',
    #   io:      'optional - IO to write to (default $stdout)'
    # )
    #
    # 1. backup  2. schema migrations installed→current  3. per-file
    # autofix (when fix:true)  4. pwn.yaml key backfill (when fix:true
    # and decryptor available)  5. stamp .schema.

    public_class_method def self.run(opts = {})
      fix     = opts[:fix] ? true : false
      dry_run = opts[:dry_run] ? true : false
      backup  = opts.fetch(:backup, true)
      io      = opts[:io] || $stdout

      FileUtils.mkdir_p(PWN_ROOT) unless dry_run
      before = status
      io.puts "PWN::Migrate — pwn #{before[:pwn_version]} · ~/.pwn schema " \
              "#{before[:schema_installed]} → #{before[:schema_current]}" \
              "#{'  (dry-run)' if dry_run}"

      drift = fix ? vault_drift(key: opts[:key], iv: opts[:iv]) : nil
      changes = before[:schema_installed] < SCHEMA_VERSION ||
                (fix && (!before[:incompatible].empty? || (drift && !drift[:missing].empty?)))
      bpath = nil
      if backup && changes && !dry_run && File.directory?(PWN_ROOT)
        bpath = backup!
        io.puts "  backup   : #{bpath}"
      end

      # ── ordered schema migrations ────────────────────────────────────
      applied = []
      ((before[:schema_installed] + 1)..SCHEMA_VERSION).each do |n|
        m = MIGRATIONS[n]
        next unless m

        io.puts "  migrate  : v#{n - 1} → v#{n}"
        m.call(PWN_ROOT, io) unless dry_run
        applied << n
      end

      # ── per-file autofix ─────────────────────────────────────────────
      fixed = []
      if fix
        before[:incompatible].each do |f|
          io.puts "  fix      : #{f[:rel].ljust(22)} [#{f[:fix]}]  #{f[:why]}"
          next if dry_run

          fixed << f.merge(result: apply_fix(file: f))
        end

        # pwn.yaml key backfill runs even when the vault verifier passed —
        # "encrypted" ≠ "has every key this release added".
        vd = backfill_vault(key: opts[:key], iv: opts[:iv], dry_run: dry_run, io: io)
        fixed << vd if vd && vd[:added].to_i.positive?
      end

      stamp! if !dry_run && changes

      after = status
      io.puts
      io.puts "  result   : #{after[:incompatible].length} incompatible remaining " \
              "(was #{before[:incompatible].length}) · schema now #{after[:schema_installed]}"

      { backup: bpath, applied_migrations: applied, fixed: fixed,
        before: before, after: after, dry_run: dry_run }
    rescue StandardError => e
      raise e
    end

    # Supported Method Parameters::
    # drift = PWN::Migrate.vault_drift(
    #   key: 'optional - vault key', iv: 'optional - vault iv'
    # )
    #
    # Deep-diff the user's decrypted pwn.yaml against the current
    # PWN::Config.env_template.  → { missing: [dotted.paths], user: {…} }
    # Returns nil when the decryptor is unavailable (never prompts).

    public_class_method def self.vault_drift(opts = {})
      key, iv = decryptor(opts)
      return nil unless key && iv

      yaml = File.join(PWN_ROOT, 'pwn.yaml')
      return nil unless File.file?(yaml) && PWN::Plugins::Vault.file_encrypted?(file: yaml)

      user = PWN::Plugins::Vault.dump(file: yaml, key: key, iv: iv)
      tmpl = env_template
      { missing: missing_paths(tmpl: tmpl, user: user), user: user, template: tmpl }
    rescue StandardError
      nil
    end

    # Supported Method Parameters::
    # r = PWN::Migrate.backfill_vault(
    #   key: 'optional', iv: 'optional', dry_run: false, io: $stdout
    # )
    #
    # Decrypt → deep-merge template UNDER user (never overwrites) →
    # re-encrypt with the SAME key/iv.  This is the fix for the #1
    # upgrade break: `NoMethodError: undefined method '[]' for nil` when
    # a release added `env[:ai][:new_engine][:…]` and the user's vault
    # predates it.

    public_class_method def self.backfill_vault(opts = {})
      io      = opts[:io] || $stdout
      dry_run = opts[:dry_run] ? true : false
      d = vault_drift(key: opts[:key], iv: opts[:iv])
      unless d
        io.puts '  vault    : skipped (no decryptor available — run with --pwn-dec or set key:/iv:)'
        return nil
      end
      if d[:missing].empty?
        io.puts "  vault    : #{OK} (no missing keys vs PWN::Config.env_template)"
        return { rel: 'pwn.yaml', added: 0, missing: [] }
      end

      io.puts "  vault    : #{WARN} #{d[:missing].length} missing key(s) — backfilling under user values"
      d[:missing].first(8).each { |p| io.puts "             + #{p}" }
      io.puts "             … (+#{d[:missing].length - 8} more)" if d[:missing].length > 8
      return { rel: 'pwn.yaml', added: d[:missing].length, missing: d[:missing], dry_run: true } if dry_run

      merged = deep_defaults(user: d[:user], tmpl: d[:template])
      yaml   = File.join(PWN_ROOT, 'pwn.yaml')
      key, iv = decryptor(opts)
      # Same colon-stripping default_env uses so the file stays diff-clean.
      File.write(yaml, YAML.dump(merged).gsub(/^(\s*):/, '\1'))
      File.chmod(0o600, yaml)
      PWN::Plugins::Vault.encrypt(file: yaml, key: key, iv: iv)

      { rel: 'pwn.yaml', added: d[:missing].length, missing: d[:missing] }
    rescue StandardError => e
      io.puts "  vault    : #{BAD} #{e.class}: #{e.message}"
      nil
    end

    # Supported Method Parameters::
    # tmpl = PWN::Migrate.env_template
    #
    # The canonical current-release pwn.yaml shape, WITHOUT the I/O
    # side-effects of PWN::Config.default_env.  Prefers
    # PWN::Config.env_template when that refactor is present.

    public_class_method def self.env_template
      return PWN::Config.env_template if PWN::Config.respond_to?(:env_template)

      # Fallback: intercept default_env's write path.  Never reached once
      # PWN::Config.env_template ships, but keeps Migrate self-sufficient.
      {}
    end

    # ──────────────────────────────────────────────────────────────────
    # internals
    # ──────────────────────────────────────────────────────────────────

    private_class_method def self.verify_one(opts = {})
      meta = opts[:meta]
      path = opts[:path]
      raw  = opts[:raw]
      # Nonexistent leaf files are fine — owners lazily seed on first
      # write.  A missing pwn.yaml IS a problem though (kind :vault).
      return { ok: true } if !File.exist?(path) && meta[:kind] != :vault

      # Raw parseability first (owners rescue → fallback so we'd never see it).
      case meta[:kind]
      when :json
        JSON.parse(raw.to_s) if raw
      when :yaml
        YAML.safe_load(raw.to_s, permitted_classes: [Symbol, Time, Date], aliases: true) if raw
      end

      v = meta[:verify]
      return jsonl_verify(path: path) if v == :jsonl

      v.call(path, raw)
    rescue JSON::ParserError, Psych::SyntaxError => e
      { ok: false, why: "unparsable #{meta[:kind]}: #{e.message[0, 60]}" }
    rescue StandardError => e
      { ok: false, why: "#{e.class}: #{e.message[0, 80]}" }
    end

    private_class_method def self.jsonl_verify(opts = {})
      path  = opts[:path]
      total = 0
      bad   = 0
      File.foreach(path) do |l|
        next if l.strip.empty?

        total += 1
        JSON.parse(l)
      rescue StandardError
        bad += 1
      end
      { ok: bad.zero?, why: bad.zero? ? nil : "#{bad}/#{total} lines unparsable" }
    end

    private_class_method def self.apply_fix(opts = {})
      f = opts[:file]
      case f[:fix]
      when :quarantine
        quarantine!(rel: f[:rel])
      when :jsonl
        strip_bad_jsonl!(rel: f[:rel])
      when :skills
        PWN::Config.migrate_legacy_skills
        PWN::Config.install_default_skills if PWN::Config.respond_to?(:install_default_skills)
      when :seed
        FileUtils.mkdir_p(File.join(PWN_ROOT, f[:rel])) if f[:kind] == :dir
        PWN::Cron.install_defaults if f[:rel].start_with?('cron/') && defined?(PWN::Cron)
        :seeded
      when :vault
        :deferred_to_backfill
      else
        :noop
      end
    rescue StandardError => e
      "#{e.class}: #{e.message}"
    end

    private_class_method def self.quarantine!(opts = {})
      src = File.join(PWN_ROOT, opts[:rel])
      return :absent unless File.exist?(src)

      dst = File.join(QUARANTINE_DIR, Time.now.utc.strftime('%Y%m%d_%H%M%S'))
      FileUtils.mkdir_p(dst)
      FileUtils.mv(src, File.join(dst, File.basename(opts[:rel])))
      "quarantined → #{dst}"
    end

    private_class_method def self.strip_bad_jsonl!(opts = {})
      path = File.join(PWN_ROOT, opts[:rel])
      return :absent unless File.file?(path)

      good = []
      bad  = 0
      File.foreach(path) do |l|
        next if l.strip.empty?

        JSON.parse(l)
        good << l
      rescue StandardError
        bad += 1
      end
      File.write(path, good.join)
      "dropped #{bad} bad line(s), kept #{good.length}"
    end

    # Supported Method Parameters::
    # PWN::Migrate.prune_backups(dry_run: true, keep: 3, limit: 10, admission: nil)
    # Default duplicate-only pruning is nondestructive to unique history.
    # Explicit expire_history policy bounds recovery generations instead.
    public_class_method def self.prune_backups(opts = {})
      return expire_backup_generations(opts) if opts[:expire_history] || backup_retention_policy['expire_history']

      dry_run = opts.fetch(:dry_run, true)
      keep = [Integer(opts.fetch(:keep, 3)), 3].max
      limit = Integer(opts.fetch(:limit, 10))
      admission = opts[:admission]
      result = { eligible: [], deleted: [], retained: [], incomplete: false }
      return result unless File.directory?(BACKUP_ROOT)
      raise IOError, 'Unsafe backup root' unless File.realpath(BACKUP_ROOT) == BACKUP_ROOT && File.stat(BACKUP_ROOT).uid == Process.uid

      work = lambda do
        names = Dir.children(BACKUP_ROOT).grep(/\A\d{8}_\d{6}(?:_[a-f0-9]{8})?\z/).sort
        retained = names.last(keep)
        manifests = retained.to_h { |name| [name, backup_inventory(path: File.join(BACKUP_ROOT, name), admission: admission)] }
        names[0...-keep].to_a.last(limit).reverse_each do |name|
          path = File.join(BACKUP_ROOT, name)
          inventory = backup_inventory(path: path, admission: admission)
          match = manifests.find { |_other, rows| rows == inventory }
          unless match
            result[:retained] << name
            next
          end
          result[:eligible] << name
          next if dry_run

          canonical = File.join(BACKUP_ROOT, match.first)
          raise IOError, 'Backup changed before pruning' unless backup_inventory(path: canonical, admission: admission) == inventory && backup_inventory(path: path, admission: admission) == inventory

          FileUtils.remove_entry_secure(path)
          raise IOError, 'Backup pruning failed' if File.exist?(path)

          result[:deleted] << name
        end
        result
      end
      return work.call if dry_run

      File.open(File.join(BACKUP_ROOT, '.retention.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        raise IOError, 'Backup maintenance active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

        work.call
      end
    rescue IOError => e
      result[:incomplete] = true
      result[:error] = e.message
      result
    end

    # Explicit opt-in expires historical versions, not merely duplicate bytes.
    private_class_method def self.backup_retention_policy
      path = File.join(BACKUP_ROOT, '.retention-policy.json')
      return { 'keep' => 3, 'pins' => [], 'expire_history' => false } unless File.exist?(path) || File.symlink?(path)
      raise IOError, 'Unsafe retention policy' unless File.realpath(path) == path && File.stat(path).uid == Process.uid

      value = JSON.parse(File.binread(path))
      valid = value['version'] == 1 && [true, false].include?(value['expire_history']) && value['keep'].is_a?(Integer) && value['keep'] >= 3 && value['pins'].is_a?(Array)
      valid &&= value['pins'].all? { |name| name.is_a?(String) && name.match?(/\A\d{8}_\d{6}(?:_[a-f0-9]{8})?\z/) }
      raise IOError, 'Invalid retention policy' unless valid

      value
    end

    private_class_method def self.backup_input_names
      (STATE_FILES.keys.map { |rel| rel.delete_suffix('/') } + %w[.schema pwn.yaml.decryptor]).uniq.reject { |rel| %w[sessions swarm].include?(rel.split('/').first) }
    end

    # Conservative literal-path protection in current evidence/continuation stores.
    # Historical log/history/metrics copies are not operational dependencies.
    private_class_method def self.backup_reference_pins(opts = {})
      admission = opts[:admission]
      pins = []
      roots = %w[learning learning.jsonl memory.json mistakes.json policy.json policy_traj.jsonl preferences.jsonl engagements artifacts sessions swarm jobs runs open_goals open_goal.json curriculum finetune extrospection skill_review.jsonl maintenance]
      roots.each do |name|
        path = File.join(PWN_ROOT, name)
        next unless File.exist?(path) || File.symlink?(path)

        Find.find(path) do |file|
          stat = File.lstat(file)
          raise IOError, 'Unsafe current evidence entry' unless stat.file? || stat.directory?
          next unless stat.file? && file.match?(/\.jsonl?\z/)
          raise IOError, 'Backup work budget exhausted' if admission && !admission.call(stat.size + 1)

          documents = file.end_with?('.jsonl') ? File.foreach(file).reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) } : [JSON.parse(File.binread(file))]
          documents.select! { |row| row.is_a?(Hash) && (%w[prepared interrupted].include?(row['state']) || row['pinned'] == true) } if name == 'maintenance'
          until documents.empty?
            value = documents.pop
            case value
            when Hash then documents.concat(value.values)
            when Array then documents.concat(value)
            when String
              match = value.match(%r{\A(?:#{Regexp.escape(BACKUP_ROOT)}/|backup/)(\d{8}_\d{6}(?:_[a-f0-9]{8})?)(?:/|\z)})
              pins << match[1] if match
            end
          end
        end
      end
      pins.uniq
    end

    private_class_method def self.expire_backup_generations(opts = {})
      require 'zlib'
      result = { eligible: [], deleted: [], retained: [], incomplete: false, permanent_history_expiry: true }
      return result unless File.directory?(BACKUP_ROOT)
      raise IOError, 'Unsafe backup root' unless File.realpath(PWN_ROOT) == PWN_ROOT && File.realpath(BACKUP_ROOT) == BACKUP_ROOT && File.stat(BACKUP_ROOT).uid == Process.uid

      dry_run = opts.fetch(:dry_run, true)
      admission = opts[:admission]
      policy = backup_retention_policy
      keep = [Integer(opts.fetch(:keep, policy['keep'])), 3].max
      limit = Integer(opts.fetch(:limit, 10))
      raise ArgumentError, 'Invalid retention limit' unless limit.positive?

      operation = lambda do
        names = Dir.children(BACKUP_ROOT).grep(/\A\d{8}_\d{6}(?:_[a-f0-9]{8})?\z/).sort
        raise IOError, 'Pinned backup missing' unless (policy['pins'] - names).empty?

        if (names - (names.last(keep) + policy['pins'])).empty?
          result[:retained] = names
          result[:pins] = policy['pins']
          result[:evidence_scan] = 'not_needed_no_expiry'
          return result
        end

        pins = (policy['pins'] + backup_reference_pins(admission: admission)).uniq
        raise IOError, 'Pinned backup missing' unless (pins - names).empty?

        retained = (names.last(keep) + pins).uniq.sort
        result[:retained] = retained
        result[:pins] = pins
        return result if (names - retained).empty?
        raise IOError, 'Insufficient recovery generations' if retained.length < keep

        current = backup_inventory(path: PWN_ROOT, names: backup_input_names, admission: admission)
        inventories = retained.to_h { |name| [name, backup_inventory(path: File.join(BACKUP_ROOT, name), admission: admission)] }
        newest = inventories.fetch(names.last)
        raise IOError, 'Current migration input coverage missing' unless current.all? { |path, row| newest[path] && newest[path].first == row.first }

        %w[pwn.yaml pwn.yaml.decryptor].each do |name|
          raise IOError, 'Current encrypted configuration recovery missing' if current.key?(name) && newest[name] != current[name]
        end
        result[:coverage] = { current_paths: current.length, newest: names.last, legacy_completeness_certified: false, restore: 'copy migration-owned paths only; never overlay entire legacy trees or edit shared inodes' }
        candidates = (names - retained).first(limit)
        expired = candidates.to_h { |name| [name, backup_inventory(path: File.join(BACKUP_ROOT, name), admission: admission)] }
        result[:eligible] = candidates
        return result if dry_run

        # Recheck everything before publishing the single private metadata ledger.
        raise IOError, 'Current migration input changed' unless current == backup_inventory(path: PWN_ROOT, names: backup_input_names, admission: admission)
        raise IOError, 'Backup references changed' unless pins == (policy['pins'] + backup_reference_pins(admission: admission)).uniq

        inventories.merge(expired).each do |name, rows|
          raise IOError, 'Backup changed before expiry' unless rows == backup_inventory(path: File.join(BACKUP_ROOT, name), admission: admission)
        end
        ledger = File.join(BACKUP_ROOT, '.retention-manifest.json.gz')
        raise IOError, 'Unsafe retention manifest' if File.symlink?(ledger)

        record = { version: 1, state: 'prepared', policy: policy, coverage: result[:coverage], retained: inventories, expiring: expired, deleted: [] }
        verification_bytes = inventories.values.sum { |rows| rows.values.sum { |row| row.first == 'file' ? row[4] + 1 : 0 } }
        reserved_bytes = (JSON.generate(record).bytesize * 2) + verification_bytes
        raise IOError, 'Backup commit budget exhausted' if admission && !admission.call(reserved_bytes)

        publish_backup_retention(path: ledger, record: record)
        candidates.each do |name|
          FileUtils.remove_entry_secure(File.join(BACKUP_ROOT, name))
          raise IOError, 'Backup expiry failed' if File.exist?(File.join(BACKUP_ROOT, name))

          result[:deleted] << name
          record[:deleted] << name
        end
        inventories.each do |name, rows|
          raise IOError, 'Retained backup changed' unless rows == backup_inventory(path: File.join(BACKUP_ROOT, name))
        end
        record[:state] = 'committed'
        publish_backup_retention(path: ledger, record: record)
        result
      end
      return operation.call if dry_run

      File.open(File.join(BACKUP_ROOT, '.retention.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        raise IOError, 'Backup maintenance active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

        operation.call
      end
    rescue IOError => e
      result[:incomplete] = true
      result[:error] = e.message
      result
    end

    private_class_method def self.publish_backup_retention(opts = {})
      path = opts[:path]
      temporary = "#{path}.#{SecureRandom.hex(8)}"
      File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
        writer = Zlib::GzipWriter.new(file)
        writer.write(JSON.generate(opts[:record]))
        writer.finish
        file.flush
        file.fsync
      end
      File.rename(temporary, path)
      File.open(BACKUP_ROOT, File::RDONLY, &:fsync)
    end

    private_class_method def self.backup_inventory(opts = {})
      path = opts[:path]
      admission = opts[:admission]
      names = opts[:names]
      raise IOError, 'Unsafe backup directory' unless File.realpath(path) == path && File.directory?(path)

      rows = {}
      Find.find(path) do |file|
        next if file == path

        rel = file.delete_prefix("#{path}/")
        Find.prune if names && names.none? { |name| rel == name || rel.start_with?("#{name}/") || name.start_with?("#{rel}/") }
        stat = File.lstat(file)
        raise IOError, 'Unsafe backup entry' unless (stat.file? || stat.directory?) && stat.uid == Process.uid
        next if names && names.none? { |name| rel == name || rel.start_with?("#{name}/") }
        raise IOError, 'Backup work budget exhausted' if admission && !admission.call(stat.file? ? stat.size + 1 : 0)

        row = [stat.ftype, stat.mode, stat.uid, stat.gid]
        if stat.file?
          row += [stat.size, Digest::SHA256.file(file).hexdigest]
          after = File.lstat(file)
          raise IOError, 'Backup changed while hashing' unless [stat.ino, stat.size, stat.mtime, stat.ctime] == [after.ino, after.size, after.mtime, after.ctime]
        end
        rows[rel] = row
      end
      rows
    end

    private_class_method def self.backup!
      FileUtils.mkdir_p(BACKUP_ROOT, mode: 0o700)
      raise IOError, 'Unsafe backup root' unless File.realpath(BACKUP_ROOT) == BACKUP_ROOT

      File.open(File.join(BACKUP_ROOT, '.retention.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        lock.flock(File::LOCK_EX)
        ts = "#{Time.now.utc.strftime('%Y%m%d_%H%M%S')}_#{SecureRandom.hex(4)}"
        dst = File.join(BACKUP_ROOT, ts)
        partial = File.join(BACKUP_ROOT, ".partial-#{ts}")
        Dir.mkdir(partial, 0o700)
        # Only state owned by the migration registry. Logs, caches, artifacts,
        # jobs and prior maintenance archives are not schema migration inputs.
        names = backup_input_names
        inventory = backup_inventory(path: PWN_ROOT, names: names)
        names.each do |name|
          src = File.join(PWN_ROOT, name)
          next unless File.exist?(src)

          target = File.join(partial, name)
          FileUtils.mkdir_p(File.dirname(target), mode: 0o700)
          FileUtils.cp_r(src, target, preserve: true)
        end
        raise IOError, 'Migration input changed during backup' unless inventory == backup_inventory(path: PWN_ROOT, names: names)
        raise IOError, 'Backup verification failed' unless inventory == backup_inventory(path: partial, names: names)

        manifest = JSON.generate(version: 1, complete: true, scope: names.sort, files: inventory)
        File.open(File.join(partial, '.snapshot-manifest.json'), File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          file.write(manifest)
          file.flush
          file.fsync
        end
        File.rename(partial, dst)
        File.open(BACKUP_ROOT, File::RDONLY, &:fsync)
        dst
      end
    end

    private_class_method def self.stamp!
      FileUtils.mkdir_p(PWN_ROOT)
      File.write(
        SCHEMA_FILE,
        JSON.pretty_generate(
          schema: SCHEMA_VERSION,
          pwn_version: (defined?(PWN::VERSION) ? PWN::VERSION : nil),
          at: Time.now.utc.iso8601
        )
      )
      SCHEMA_VERSION
    end

    private_class_method def self.decryptor(opts = {})
      key = opts[:key]
      iv  = opts[:iv]
      return [key, iv] if key && iv

      dec = File.join(PWN_ROOT, 'pwn.yaml.decryptor')
      return [nil, nil] unless File.file?(dec)

      d = YAML.load_file(dec, symbolize_names: true)
      [d[:key], d[:iv]]
    rescue StandardError
      [nil, nil]
    end

    private_class_method def self.safe_read(opts = {})
      path = opts[:path]
      File.size(path) > 5_000_000 ? nil : File.read(path)
    rescue StandardError
      nil
    end

    private_class_method def self.human_size(opts = {})
      bytes = opts[:bytes]
      return '' if bytes.nil?

      u = %w[B K M G]
      i = 0
      n = bytes.to_f
      while n >= 1024 && i < u.length - 1
        n /= 1024
        i += 1
      end
      format('%<n>.4g%<u>s', n: n, u: u[i])
    end

    # template UNDER user — user values always win; template only fills
    # holes.  Arrays are treated as leaves (never element-merged).
    private_class_method def self.deep_defaults(opts = {})
      user = opts[:user]
      tmpl = opts[:tmpl]
      return user unless tmpl.is_a?(Hash)
      return tmpl unless user.is_a?(Hash)

      out = user.dup
      tmpl.each do |k, tv|
        uv = out.key?(k) ? out[k] : out[k.to_s]
        out[k] = if tv.is_a?(Hash)
                   deep_defaults(user: uv, tmpl: tv)
                 elsif uv.nil? && !out.key?(k) && !out.key?(k.to_s)
                   tv
                 else
                   uv
                 end
      end
      out
    end

    private_class_method def self.missing_paths(opts = {})
      tmpl   = opts[:tmpl]
      user   = opts[:user]
      prefix = opts[:prefix] || ''
      out    = []
      return out unless tmpl.is_a?(Hash)

      tmpl.each do |k, tv|
        dotted = prefix.empty? ? k.to_s : "#{prefix}.#{k}"
        uv = nil
        if user.is_a?(Hash)
          uv = user[k]
          uv = user[k.to_s] if uv.nil?
        end
        if tv.is_a?(Hash)
          if uv.is_a?(Hash)
            out.concat(missing_paths(tmpl: tv, user: uv, prefix: dotted))
          else
            out << dotted
          end
        elsif !user.is_a?(Hash) || (!user.key?(k) && !user.key?(k.to_s))
          out << dotted
        end
      end
      out
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):
        0day Inc. <support@0dayinc.com>
      "
    end

    # Display Usage for this Module

    public_class_method def self.help
      puts "USAGE:
        # Run installed schema and return its result
        #{self}.installed_schema

        # Run needed and return its result
        #{self}.needed?

        # Run status and return its result
        #{self}.status

        # Human-readable ~/.pwn state doctor.  Read-only.  Called from
        #{self}.check(
          io: 'optional - IO to write the report to (default $stdout)'
        )

        # Run run and return its result
        #{self}.run(
          fix: 'optional - also autofix incompatible files (default: schema-migrations only)',
          backup: 'optional - take timestamped backup of ~/.pwn first (default true)',
          dry_run: 'optional - report what WOULD happen, write nothing (default false)',
          key: 'optional - vault key   (default: read ~/.pwn/pwn.yaml.decryptor)',
          iv: 'optional - vault iv    (default: read ~/.pwn/pwn.yaml.decryptor)',
          io: 'optional - IO to write to (default $stdout)'
        )

        # Run vault drift and return its result
        #{self}.vault_drift(
          key: 'optional - vault key, iv: optional - vault iv'
        )

        # Run backfill vault and return its result
        #{self}.backfill_vault(
          key: 'optional - optional, iv: optional, dry_run: false, io: $stdout',
          io: 'optional - io value consumed by #backfill_vault',
          dry_run: 'optional - dry run value consumed by #backfill_vault',
          iv: 'optional - iv value consumed by #backfill_vault'
        )

        # Prune duplicate trees, or explicitly expire historical generations.
        #{self}.prune_backups(
          expire_history: 'optional - permanently expire old unpinned history after current recovery coverage verification; default reads backup/.retention-policy.json',
          dry_run: 'optional - preview without writes, default true',
          keep: 'optional - recent recovery points to retain, minimum three',
          limit: 'optional - maximum older snapshots examined per invocation, default ten',
          admission: 'optional - callable byte/work budget admission guard'
        )

        # Run env template and return its result
        #{self}.env_template

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
      constants.sort
    end
  end
end
