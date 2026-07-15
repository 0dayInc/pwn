# frozen_string_literal: true

require 'json'
require 'yaml'
require 'fileutils'
require 'time'

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
    SCHEMA_VERSION = 1

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
        PWN::Cron.install_defaults if defined?(PWN::Cron)
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

      FileUtils.mkdir_p(PWN_ROOT)
      before = status
      io.puts "PWN::Migrate — pwn #{before[:pwn_version]} · ~/.pwn schema " \
              "#{before[:schema_installed]} → #{before[:schema_current]}" \
              "#{'  (dry-run)' if dry_run}"

      bpath = nil
      if backup && !dry_run && File.directory?(PWN_ROOT)
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

      stamp! unless dry_run

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

    private_class_method def self.backup!
      ts  = Time.now.utc.strftime('%Y%m%d_%H%M%S')
      dst = File.join(BACKUP_ROOT, ts)
      FileUtils.mkdir_p(dst)
      Dir.children(PWN_ROOT).each do |c|
        next if %w[backup quarantine sessions swarm].include?(c) # large / regenerable

        src = File.join(PWN_ROOT, c)
        FileUtils.cp_r(src, dst)
      rescue StandardError
        next
      end
      dst
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
        # Is ~/.pwn older than this pwn release's schema?
        #{self}.needed?             # => true/false (cheap; used by refresh_env)

        # Read-only per-file compatibility report.
        #{self}.status              # => { schema_installed:, schema_current:, files:[…], incompatible:[…] }
        #{self}.check               # human-readable to $stdout

        # Apply schema migrations + (optionally) autofix incompatible files.
        # Always takes a timestamped backup under ~/.pwn/backup/<ts>/ first.
        #{self}.run(
          fix:     'optional - also autofix per-file (default false)',
          backup:  'optional - default true',
          dry_run: 'optional - default false',
          key:     'optional - vault key (default: ~/.pwn/pwn.yaml.decryptor)',
          iv:      'optional - vault iv'
        )

        # pwn.yaml specifically — deep-merge missing keys from the
        # current release template UNDER the user's values, re-encrypt.
        #{self}.vault_drift         # => { missing: [dotted.paths], … } or nil
        #{self}.backfill_vault

        # Data:
        #{self}::SCHEMA_VERSION     # bump when a ~/.pwn file shape changes
        #{self}::STATE_FILES        # rel-path → owner → verifier → fix
        #{self}::MIGRATIONS         # ordered idempotent transforms

        # From the shell:
        pwn setup --migrate                # == #{self}.run
        pwn setup --migrate --fix          # == #{self}.run(fix: true)
        pwn setup --migrate --dry-run

        #{self}.authors
      "
    end
  end
end
