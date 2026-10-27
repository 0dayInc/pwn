# frozen_string_literal: true

# PWN managed default: session_cleanup v10
# No provider calls or broad store GC. Unsummarized candidates are backed up first.
require 'pwn'
require 'json'
require 'fileutils'
require 'time'
require 'digest'
require 'securerandom'

module PWN
  # Provenance-based session cleanup, shared by seeded cron payloads.
  module SessionCleanup
    VERSION = 10

    # Logical categories deliberately preserve existing literal evidence paths.
    STORAGE = {
      'sessions' => %w[sessions],
      'learning' => %w[learning.jsonl learning lessons.json memory.json memory.archive.json memory.idx mistakes.json policy policy.json policy_traj.jsonl curriculum curriculum_kpi.jsonl extrospection.json finetune preferences.jsonl reward_sentinel.json skill_review.jsonl operator-learning-review.jsonl],
      'artifacts' => %w[artifacts exports findings.jsonl engagements corpora binws redb ghidra sandbox_snapshots],
      'state' => %w[swarm cron agents.yml open_goal.json jobs missions runs metrics metrics.json capabilities.json],
      'logs' => %w[logs], 'cache' => %w[cache], 'tmp' => %w[tmp],
      'maintenance' => %w[maintenance session_cleanup_archive],
      'backups' => %w[backup]
    }.freeze
    POLICY = { 'version' => 1, 'batch_size' => 100, 'scan_limit' => 100_000, 'work_items' => 100_000, 'work_seconds' => 30, 'work_bytes' => 67_108_864,
               'retention_days' => { 'sessions' => 0, 'learning' => nil, 'artifacts' => nil, 'state' => nil,
                                     'logs' => 30, 'cache' => 7, 'tmp' => 1, 'maintenance' => 90 },
               'budget_bytes' => { 'logs' => 268_435_456, 'cache' => 536_870_912, 'tmp' => 268_435_456, 'maintenance' => 1_073_741_824 } }.freeze

    # Versioned additive setup: no old path moves or permission rewrites.
    def self.install(root: File.join(Dir.home, '.pwn'))
      directory = private_directory(File.join(root, 'maintenance'))
      File.open(File.join(directory, '.setup.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        lock.flock(File::LOCK_EX)
        path = File.join(directory, 'policy.json')
        raise IOError, 'Symlinked maintenance policy' if File.symlink?(path)

        publish(path, JSON.pretty_generate(POLICY)) unless File.exist?(path)
        %w[cache tmp].each { |name| private_directory(File.join(root, name)) unless File.exist?(File.join(root, name)) }
        layout = File.join(directory, 'layout.json')
        raise IOError, 'Unsafe maintenance inventory' if File.symlink?(layout)

        previous = File.file?(layout) ? JSON.parse(File.binread(layout)) : nil
        raise IOError, 'Unknown maintenance inventory version' if previous && ![1, 2].include?(previous['version'])

        publish(layout, JSON.generate(version: 2, categories: STORAGE)) unless previous && previous['version'] == 2
      end
      { version: 2, root: directory }
    end

    # Startup performs only fixed-path checks and one coalesced request write.
    # The existing cron worker owns all scanning, migration and deletion.
    def self.request_background(root: File.join(Dir.home, '.pwn'))
      directory = File.join(root, 'maintenance')
      return { state: 'not_installed' } unless File.directory?(directory)
      raise IOError, 'Unsafe maintenance directory' unless File.realpath(directory) == directory

      File.open(File.join(directory, '.schedule.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        return { state: 'coalesced' } unless lock.flock(File::LOCK_EX | File::LOCK_NB)

        path = File.join(directory, 'background.json')
        raise IOError, 'Unsafe background request' if File.symlink?(path)

        if File.file?(path)
          prior = JSON.parse(File.binread(path))
          return { state: 'coalesced' } if prior['state'] == 'pending' || prior.fetch('requested_at', 0) > Time.now.to_i - 86_400
        end
        publish(path, JSON.generate(version: 1, state: 'pending', requested_at: Time.now.to_i))
        { state: 'queued', path: path }
      end
    rescue StandardError => e
      { state: 'unhealthy', error: e.class.name }
    end

    def self.background_request(root: File.join(Dir.home, '.pwn'))
      directory = File.join(root, 'maintenance')
      path = File.join(directory, 'background.json')
      return unless File.file?(path)
      raise IOError, 'Unsafe background request' unless File.realpath(path) == path

      File.open(File.join(directory, '.schedule.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        next unless lock.flock(File::LOCK_EX | File::LOCK_NB)

        row = JSON.parse(File.binread(path))
        next unless row['version'] == 1 && row['state'] == 'pending'

        result = yield
        next unless result

        row['state'] = result[:status] == 'success' ? 'completed' : 'interrupted'
        row['completed_at'] = Time.now.to_i
        publish(path, JSON.generate(row))
        result
      end
    end

    def self.policy
      path = File.join(Dir.home, '.pwn', 'maintenance', 'policy.json')
      return Marshal.load(Marshal.dump(POLICY)) unless File.exist?(path) || File.symlink?(path)

      raise IOError, 'Unsafe maintenance policy' if File.symlink?(path)

      value = JSON.parse(File.binread(path))
      raise ArgumentError, 'Unknown maintenance policy' unless value.is_a?(Hash) && value['version'] == 1 && (value.keys - POLICY.keys).empty?

      result = Marshal.load(Marshal.dump(POLICY)).merge(value)
      %w[retention_days budget_bytes].each do |key|
        raise ArgumentError, "Invalid #{key}" unless result[key].is_a?(Hash) && (result[key].keys - STORAGE.keys).empty? && result[key].values.all? { |n| n.nil? || (n.is_a?(Integer) && n >= 0) }

        result[key] = POLICY[key].merge(result[key])
      end
      raise ArgumentError, 'Invalid read budget' unless result['work_bytes'].is_a?(Integer) && result['work_bytes'].positive?
      raise ArgumentError, 'Invalid maintenance bounds' unless %w[batch_size scan_limit work_items work_seconds].all? { |key| result[key].is_a?(Integer) && result[key].between?(1, 100_000) }

      result
    end

    # No mkdir, locks, provider access, metadata rewrites or repair in status.
    def self.status
      config = policy
      root = File.join(Dir.home, '.pwn')
      errors = []
      remaining = config['scan_limit']
      categories = STORAGE.to_h do |category, names|
        paths = names.map { |name| name == 'sessions' ? PWN::Sessions::SESSIONS_DIR : File.join(root, name) }
        row = { paths: paths, files: 0, bytes: 0, unique_bytes: 0, symlinks: 0, retention_days: config['retention_days'][category], budget_bytes: config['budget_bytes'][category] }
        inodes = {}
        pending = paths.dup
        until pending.empty? || remaining.zero? || stopping?
          begin
            entry = pending.pop
            if entry.is_a?(Array)
              begin
                path = File.join(entry[0], entry[1].next)
                pending << entry
              rescue StopIteration
                next
              end
            else
              path = entry
            end
            next unless File.exist?(path) || File.symlink?(path)

            remaining -= 1
            stat = File.lstat(path)
            if stat.symlink?
              row[:symlinks] += 1
            elsif stat.directory?
              pending << [path, Dir.each_child(path)]
            elsif stat.file?
              row[:files] += 1
              row[:bytes] += stat.size
              key = [stat.dev, stat.ino]
              row[:unique_bytes] += stat.size unless inodes[key]
              inodes[key] = true
            end
          rescue SystemCallError => e
            errors << { path: path, error: e.class.name }
          end
        end
        row[:incomplete] = !pending.empty?
        row[:over_budget] = row[:budget_bytes] && row[:bytes] > row[:budget_bytes]
        row[:policy_mode] = %w[learning artifacts state backups].include?(category) ? 'protected_evidence_no_automatic_deletion' : 'verified_disposable_only'
        [category, row]
      end
      transactions = Dir.glob(File.join(root, 'maintenance', 'runs', '*.json')).last(config['batch_size']).map do |path|
        raise IOError, 'Unsafe transaction ledger' unless File.realpath(path) == path

        row = JSON.parse(admitted_bytes(path))
        { ledger: path, state: row['state'], recovery: %w[prepared interrupted].include?(row['state']) ? 'inspect_child_ledgers_before_retry' : nil }
      rescue StandardError => e
        { ledger: path, state: 'unknown', error: e.class.name }
      end
      { version: VERSION, operation: 'status', categories: categories, errors: errors, transactions: transactions,
        policy: config, reasons: ['Unknown files and immutable evidence are retained; budgets do not override evidence or leases.',
                                  'Historical backup expiry requires explicit retention policy and verified current recovery coverage; pinned evidence remains.'] }
    end

    # Explicit legacy expiry, not broad GC. No payload quarantine or new per-file
    # leases: old producers do not honor those. Permanent maintenance locking,
    # closed-stream markers, process descriptors and exact byte identities fence
    # adoption. References are conservatively matched even in retained transcripts.
    def self.expire_legacy(dry_run: true, manifest: nil)
      require 'zlib'
      root = File.join(Dir.home, '.pwn')
      raise IOError, 'Unsafe root' unless File.realpath(root) == root
      raise ArgumentError, 'New external metadata manifest required' if !dry_run && (manifest.nil? || File.expand_path(manifest).start_with?("#{root}/") || File.exist?(manifest))

      result = { removed: [], retained: [], candidates: [] }
      File.open(File.join(root, 'sessions', '.maintenance.lock'), File::RDWR | File::NOFOLLOW) do |lock|
        raise IOError, 'Maintenance active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

        candidates = legacy_candidates(root) + legacy_recovery_candidates(root) + legacy_cache_candidates(root)
        pins = legacy_references(root, candidates)
        opened = legacy_open_files
        candidates.each do |row|
          reason = pins[row[:path]] ? 'evidence_reference' : nil
          reason ||= 'open_descriptor' if opened.include?([row[:dev], row[:ino]])
          (reason ? result[:retained] : result[:candidates]) << row.merge(reason: reason, references: pins[row[:path]])
        end
        return result if dry_run

        # Publish metadata before irreversible expiry. An interrupted manifest is
        # an intent ledger, never a claim that every planned removal completed.
        result[:state] = 'prepared'
        legacy_manifest(manifest, result)
        raise IOError, 'Evidence references changed' unless pins == legacy_references(root, candidates)

        result[:candidates].each do |row|
          path = row[:path]
          File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
            raise IOError, 'Candidate locked' unless file.flock(File::LOCK_EX | File::LOCK_NB)

            lease = File.open("#{path}.lease", File::RDWR | File::NOFOLLOW) if File.exist?("#{path}.lease") || File.symlink?("#{path}.lease") # rubocop:disable Style/FileOpen -- closed in ensure while optional producer lease is held
            raise IOError, 'Producer lease active' if lease && !lease.flock(File::LOCK_EX | File::LOCK_NB)
            raise IOError, 'Candidate changed' unless legacy_identity(path) == row.except(:category, :reason, :references, :proofs)

            Array(row[:proofs]).each do |proof|
              raise IOError, 'Recovery proof changed' unless legacy_identity(proof[:path]) == proof
            end
            raise IOError, 'Candidate became active' if legacy_open_files(except_fd: file.fileno).include?([row[:dev], row[:ino]])

            File.unlink(path)
            result[:removed] << row
          ensure
            lease&.close
          end
        end
        result[:state] = 'completed'
        legacy_manifest(manifest, result)
      end
      result
    end

    def self.legacy_manifest(path, result)
      File.open(path, File::WRONLY | File::CREAT | File::TRUNC | File::NOFOLLOW, 0o600) do |file|
        gzip = Zlib::GzipWriter.new(file)
        gzip.write(JSON.generate(result))
        gzip.finish
        file.flush
        file.fsync
      end
    end

    def self.legacy_identity(path)
      stat = File.lstat(path)
      raise IOError, 'Unsafe legacy file' unless stat.file? && stat.uid == File.stat(File.join(Dir.home, '.pwn')).uid && stat.nlink == 1 && File.realpath(path) == path

      { path: path, dev: stat.dev, ino: stat.ino, size: stat.size, mtime: stat.mtime.to_r.to_s,
        ctime: stat.ctime.to_r.to_s, sha256: Digest::SHA256.file(path).hexdigest }
    end

    def self.legacy_candidates(root)
      days = policy['retention_days']['logs']
      return [] unless days.is_a?(Numeric) && days.positive?

      Dir.glob(File.join(root, 'logs', '*.log')).filter_map do |path|
        next unless File.basename(path).match?(/\Apwn-ai-DEBUG-[a-zA-Z0-9_-]+-R[1-9]\d*\.log\z/)

        row = legacy_identity(path)
        next unless File.lstat(path).mtime < Time.now - (days * 86_400)

        bytes = File.binread(path)
        next unless bytes.include?('debug session stop') || bytes.include?('footer iter=')

        row.merge(category: 'logs')
      end
    end

    # Historical learning/reward recovery is explicitly bounded to at least
    # three parseable copies per exact producer family, plus all reference pins.
    # A thirty-day floor excludes files an older daily producer might still use.
    def self.legacy_recovery_candidates(root)
      families = { 'learning.jsonl' => /\Alearning\.jsonl\.bak-lean-\d{8}\z/,
                   'preferences.jsonl' => /\Apreferences\.jsonl\.bak-p15-\d{14}\z/ }
      families.flat_map do |source, pattern|
        current = File.join(root, source)
        next [] unless File.file?(current)

        legacy_identity(current)
        File.foreach(current) { |line| JSON.parse(line) unless line.strip.empty? }
        copies = Dir.children(root).grep(pattern).sort.map { |name| File.join(root, name) }
        valid = copies.select do |path|
          legacy_identity(path)
          File.foreach(path) { |line| JSON.parse(line) unless line.strip.empty? }
          File.size(path).positive?
        rescue JSON::ParserError
          false
        end
        (valid - valid.last(3)).filter_map do |path|
          next unless File.mtime(path) < Time.now - (30 * 86_400)

          legacy_identity(path).merge(category: 'root_recovery', proofs: valid.last(3).map { |copy| legacy_identity(copy) })
        end
      end
    end

    # BinaryParser persists exactly these cache bytes to ArtifactRegistry. Missing
    # source binaries prevent recomputation; require a surviving byte-exact copy
    # instead, never classify arbitrary decompiler stdout as reproducible.
    def self.legacy_cache_candidates(root)
      days = policy['retention_days']['cache']
      return [] unless days.is_a?(Numeric) && days.positive?

      copies = Dir.glob(File.join(root, 'artifacts', '**', '*')).select { |path| File.file?(path) && !File.symlink?(path) }
      Dir.glob(File.join(root, 'cache', 'triage', '*.json')).filter_map do |path|
        next unless File.basename(path).match?(/\A[a-f0-9]{64}\.json\z/) && File.mtime(path) < Time.now - (days * 86_400)

        row = legacy_identity(path)
        body = JSON.parse(File.binread(path))
        next unless body['sha256'] == File.basename(path, '.json') && body['path'].is_a?(String)

        copy = copies.find { |candidate| File.size(candidate) == row[:size] && Digest::SHA256.file(candidate).hexdigest == row[:sha256] }
        next unless copy

        row.merge(category: 'cache', proofs: [legacy_identity(copy)])
      end
    end

    def self.legacy_references(root, candidates)
      names = candidates.to_h { |row| [File.basename(row[:path]), row[:path]] }
      return {} if names.empty?

      pattern = Regexp.union(names.keys)
      references = {}
      # Recovery generations are historical copies, not live evidence pins.
      # Candidate payloads cannot pin themselves. Everything else is scanned
      # without interpreting or displaying credential/transcript contents.
      Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH).sort.each do |path|
        relative = path.delete_prefix("#{root}/")
        next if %w[backup logs cache].include?(relative.split('/').first)
        next if names.value?(path) || !File.file?(path)
        raise IOError, 'Symlink in reference scope' if File.symlink?(path)

        File.binread(path).scan(pattern).uniq.each do |name|
          (references[names.fetch(name)] ||= []) << path
        end
      end
      references
    end

    def self.legacy_open_files(except_fd: nil)
      raise IOError, 'Process inventory unavailable' unless File.directory?('/proc/self/fd')

      opened = []
      Dir.glob('/proc/[0-9]*').each do |process|
        next unless Process.uid.zero? || File.stat(process).uid == Process.uid

        Dir.children("#{process}/fd").each do |fd|
          next if File.basename(process).to_i == Process.pid && fd.to_i == except_fd

          stat = File.stat("#{process}/fd/#{fd}")
          opened << [stat.dev, stat.ino] if stat.file?
        rescue Errno::ENOENT, Errno::ESRCH
          next
        end
      rescue Errno::ENOENT, Errno::ESRCH
        next
      end
      opened.uniq
    end

    # A producer registers only reproducible/disposable bytes, never evidence.
    # Writers hold the permanent .lease exclusively while changing a file;
    # consumers hold it shared for the whole read/use lifetime.
    def self.register_disposable(path:, category:, expires_at: nil)
      raise ArgumentError, 'Not a disposable category' unless %w[cache tmp logs].include?(category)

      root = File.join(Dir.home, '.pwn', category)
      path = File.expand_path(path)
      raise IOError, 'Disposable path escapes its category' unless path.start_with?("#{root}/") && File.realpath(path) == path
      raise IOError, 'Disposable must be an owned regular file' unless File.file?(path) && File.stat(path).uid == Process.uid

      days = policy['retention_days'][category]
      raise ArgumentError, 'Retention disabled for category' if days.nil?

      File.open("#{path}.lease", File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lease|
        raise IOError, 'Disposable is active' unless lease.flock(File::LOCK_EX | File::LOCK_NB)

        record_disposable(path: path, category: category, expires_at: expires_at || (Time.now.to_i + (days * 86_400)))
      end
    end

    # Caller holds the permanent exclusive producer lease through publication.
    def self.record_disposable(path:, category:, expires_at:)
      directory = private_directory(File.join(Dir.home, '.pwn', 'maintenance', 'disposable'))
      record = { version: 1, path: path, category: category, expires_at: expires_at,
                 sha256: Digest::SHA256.file(path).hexdigest, bytes: File.size(path), inode: File.stat(path).ino }
      publish(File.join(directory, "#{Digest::SHA256.hexdigest(path)}.json"), JSON.generate(record))
      record
    end

    # Cache consumers use the same permanent inode as publication and eviction.
    def self.cache(path:, bytes: nil)
      root = File.join(Dir.home, '.pwn', 'cache')
      raise IOError, 'Unsafe cache path' unless File.expand_path(path) == path && path.start_with?("#{root}/")

      private_directory(File.dirname(path)) unless File.directory?(File.dirname(path))
      raise IOError, 'Unsafe cache directory' unless File.realpath(File.dirname(path)) == File.dirname(path)

      File.open("#{path}.lease", File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lease|
        lease.flock(bytes ? File::LOCK_EX : File::LOCK_SH)
        if bytes
          publish(path, bytes)
          days = policy['retention_days']['cache']
          if days
            directory = private_directory(File.join(Dir.home, '.pwn', 'maintenance', 'disposable'))
            row = { version: 1, path: path, category: 'cache', expires_at: Time.now.to_i + (days * 86_400),
                    sha256: Digest::SHA256.file(path).hexdigest, bytes: File.size(path), inode: File.stat(path).ino }
            publish(File.join(directory, "#{Digest::SHA256.hexdigest(path)}.json"), JSON.generate(row))
          end
          bytes
        elsif File.file?(path) && !File.symlink?(path)
          File.binread(path)
        end
      end
    end

    # Known disposable input producer. The permanent lease covers publication,
    # consumption and unlink; a killed consumer leaves a registered exact file.
    def self.temporary(bytes:)
      directory = private_directory(File.join(Dir.home, '.pwn', 'tmp'))
      path = File.join(directory, "input-#{SecureRandom.hex(12)}.txt")
      File.open("#{path}.lease", File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lease|
        lease.flock(File::LOCK_EX)
        begin
          publish(path, bytes)
          days = policy['retention_days']['tmp']
          record_disposable(path: path, category: 'tmp', expires_at: Time.now.to_i + (days * 86_400)) if days
          yield path
        ensure
          File.unlink(path) if File.file?(path) && !File.symlink?(path)
        end
      end
    end

    # Rotate ordinary diagnostics under the same lease as append and eviction.
    # Request debug streams rotate at request boundaries and hold a lifetime lease.
    def self.append_log(path:, bytes:, rotate_bytes: 1_024_000)
      root = File.join(Dir.home, '.pwn', 'logs')
      raise IOError, 'Unsafe log path' unless File.expand_path(path) == path && path.start_with?("#{root}/")

      private_directory(File.dirname(path)) unless File.directory?(File.dirname(path))
      raise IOError, 'Unsafe log directory' unless File.realpath(File.dirname(path)) == File.dirname(path)

      File.open("#{path}.lease", File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lease|
        lease.flock(File::LOCK_EX)
        raise IOError, 'Symlinked log' if File.symlink?(path)

        if File.file?(path) && File.size(path) >= rotate_bytes
          rotated = "#{path}.#{SecureRandom.hex(12)}"
          File.rename(path, rotated)
          register_disposable(path: rotated, category: 'logs') unless policy['retention_days']['logs'].nil?
        end
        File.open(path, File::WRONLY | File::CREAT | File::APPEND | File::NOFOLLOW, 0o600) do |file|
          file.write(bytes)
          file.flush
          file.fsync
        end
        days = policy['retention_days']['logs']
        record_disposable(path: path, category: 'logs', expires_at: Time.now.to_i + (days * 86_400)) if days
      end
      path
    end

    def self.private_directory(path)
      ancestor = File.expand_path(path)
      loop do
        raise IOError, 'Symlinked maintenance directory' if File.symlink?(ancestor)
        break if ancestor == File.dirname(ancestor)

        ancestor = File.dirname(ancestor)
      end
      FileUtils.mkdir_p(path, mode: 0o700)
      stat = File.stat(path)
      raise IOError, 'Unsafe maintenance directory permissions' unless stat.uid == Process.uid && stat.mode.nobits?(0o077)

      path
    end

    # Exact-size reads cannot grow without bound if an uncooperative writer appends.
    def self.exact_bytes(path, size)
      bytes = File.binread(path, size + 1)
      raise IOError, 'File size changed' unless bytes.bytesize == size

      bytes
    end

    def self.admitted_bytes(path)
      size = File.size(path)
      raise IOError, 'Maintenance read budget exhausted' unless admit?(size + 1)

      exact_bytes(path, size)
    end

    def self.disposable_reason(row, pressure: false, verify: true)
      return 'unknown_schema' unless row.is_a?(Hash) && row['version'] == 1 && %w[cache tmp logs].include?(row['category']) && row['expires_at'].is_a?(Integer)

      path = row['path']
      root = File.join(Dir.home, '.pwn', row['category'])
      return 'unsafe_path' unless path.is_a?(String) && path.start_with?("#{root}/") && File.expand_path(path) == path
      return 'missing' unless File.exist?(path)
      return 'unsafe_path' unless File.realpath(path) == path && File.file?(path) && File.stat(path).uid == Process.uid
      return 'changed' unless File.stat(path).ino == row['inode'] && File.size(path) == row['bytes']
      return 'changed' if verify && Digest::SHA256.hexdigest(exact_bytes(path, row['bytes'])) != row['sha256']
      return 'retention_disabled' if policy['retention_days'][row['category']].nil?
      return 'not_expired' if !pressure && row['expires_at'] > Time.now.to_i
      return 'missing_lease' unless File.file?("#{path}.lease") && !File.symlink?("#{path}.lease")

      nil
    end

    def self.clean_disposables(dry_run: true, stop: nil)
      with_maintenance_lock(dry_run: dry_run) do
        result = { operation: 'routine', state: 'planned', dry_run: dry_run, eligible: [], deleted: [], retained: [], records: [] }
        root = File.join(Dir.home, '.pwn', 'maintenance')
        usage = status[:categories]
        # A lexical round-robin cursor is only scheduling state, never deletion
        # authority. Manifests stay put, so concurrent re-registration cannot
        # be removed or overwritten by cleanup completion.
        cursor_path = File.join(root, 'disposable.cursor')
        cursor = File.file?(cursor_path) && !File.symlink?(cursor_path) ? File.binread(cursor_path, 70) : ''
        cursor = '' unless cursor.match?(/\A[a-f0-9]{64}\.json\z/)
        files = Dir.glob(File.join(root, 'disposable', '*.json'))
        after, before = files.partition { |file| File.basename(file) > cursor }
        files = after + before
        result[:incomplete] = true if files.length > policy['scan_limit']
        files = files.first(policy['scan_limit'])
        files.each do |manifest|
          if !admit? || stop&.call || result[:deleted].length >= policy['batch_size']
            result[:incomplete] = true
            break
          end

          publish(cursor_path, File.basename(manifest)) unless dry_run
          raise IOError, 'Unsafe disposable manifest' unless File.realpath(manifest) == manifest

          manifest_size = File.size(manifest)
          break unless admit?((manifest_size + 1) * 2)

          manifest_bytes = exact_bytes(manifest, manifest_size)
          row = JSON.parse(manifest_bytes)
          category_usage = usage[row['category']] || {}
          budget = category_usage[:budget_bytes]
          pressure = budget && category_usage[:bytes] > budget
          reason = disposable_reason(row, pressure: pressure, verify: false)
          if reason
            result[:retained] << { manifest: manifest, reason: reason }
            next
          end
          path = row['path']
          File.open("#{path}.lease", File::RDWR | File::NOFOLLOW) do |lease|
            unless lease.flock(File::LOCK_EX | File::LOCK_NB)
              result[:retained] << { path: path, reason: 'active' }
              next
            end
            if exact_bytes(manifest, manifest_size) != manifest_bytes
              result[:retained] << { path: path, reason: 'registration_changed' }
              next
            end
            # Reserve all payload reads, backup write and verification before commit.
            unless admit?((row['bytes'] + 1) * (dry_run ? 1 : 5))
              result[:retained] << { path: path, reason: 'work_budget' }
              next
            end
            if (reason = disposable_reason(row, pressure: pressure))
              result[:retained] << { path: path, reason: reason }
              next
            end
            result[:eligible] << path
            category_usage[:bytes] -= row['bytes']
            next if dry_run

            unless result[:ledger]
              directory = private_directory(File.join(root, 'quarantine', SecureRandom.hex(12)))
              result[:ledger] = File.join(directory, 'ledger.json')
            end
            backup_path = File.join(File.dirname(result[:ledger]), "#{Digest::SHA256.hexdigest(path)}.bin")
            publish(backup_path, exact_bytes(path, row['bytes']))
            raise IOError, 'Disposable backup mismatch' unless Digest::SHA256.hexdigest(exact_bytes(backup_path, row['bytes'])) == row['sha256']

            record = row.merge('backup' => backup_path, 'state' => 'prepared')
            result[:records] << record
            result[:state] = 'prepared'
            publish(result[:ledger], JSON.pretty_generate(result))
            raise IOError, 'Disposable changed after backup' if disposable_reason(row, pressure: pressure)

            File.unlink(path)
            File.open(File.dirname(path), File::RDONLY, &:fsync)
            result[:deleted] << path
            record['state'] = 'committed'
            publish(result[:ledger], JSON.pretty_generate(result))
            # Keep permanent lease inode and manifest for audit/recovery.
          end
        rescue StandardError => e
          result[:retained] << { manifest: manifest, reason: e.class.name }
        end
        unless dry_run
          result[:state] = stopping? || stop&.call ? 'stopped' : 'committed'
          result[:state] = 'interrupted' if result[:records].any? { |row| row['state'] == 'prepared' }
        end
        publish(result[:ledger], JSON.pretty_generate(result)) if result[:ledger]
        result
      end
    end

    # Only disposable quarantine expires. Learning/session/retirement backups
    # are evidence, and are deliberately outside this pruning protocol.
    def self.prune_quarantine(dry_run: true)
      config = policy
      result = { eligible: [], deleted: [], retained: [] }
      days = config['retention_days']['maintenance']
      return result if days.nil?

      with_maintenance_lock(dry_run: dry_run) do
        remaining_bytes = status[:categories]['maintenance'][:unique_bytes]
        budget = config['budget_bytes']['maintenance']
        Dir.glob(File.join(Dir.home, '.pwn', 'maintenance', 'quarantine', '*', 'ledger.json')).each do |ledger|
          break if stopping? || result[:deleted].length >= config['batch_size']

          raise IOError, 'Unsafe quarantine ledger' unless File.realpath(ledger) == ledger

          data = JSON.parse(admitted_bytes(ledger))
          next if data['state'] == 'expired'
          next if data['state'] != 'expiry_prepared' && File.mtime(ledger) > Time.now - (days * 86_400) && !(budget && remaining_bytes > budget)
          raise IOError, 'Uncommitted quarantine retained' unless data['operation'] == 'routine' && %w[committed expiry_prepared].include?(data['state']) && data['records'].is_a?(Array) && data['records'].all? { |row| row['state'] == 'committed' }

          backups = data['records'].filter_map do |row|
            path = row.fetch('backup')
            raise IOError, 'Unsafe quarantine backup' unless File.dirname(path) == File.dirname(ledger) && File.expand_path(path) == path
            next if data['state'] == 'expiry_prepared' && !File.exist?(path) && !File.symlink?(path)

            raise IOError, 'Unknown quarantine bytes' unless File.dirname(path) == File.dirname(ledger) && File.realpath(path) == path && Digest::SHA256.hexdigest(admitted_bytes(path)) == row['sha256']

            path
          end
          raise IOError, 'Unknown quarantine contents' unless (Dir.children(File.dirname(ledger)) - ['ledger.json', *backups.map { |path| File.basename(path) }]).empty?

          result[:eligible].concat(backups)
          remaining_bytes -= backups.sum { |path| File.size(path) }
          next if dry_run

          data['state'] = 'expiry_prepared'
          publish(ledger, JSON.pretty_generate(data))
          backups.each do |path|
            break if !admit? || result[:deleted].length >= config['batch_size']

            File.unlink(path)
            result[:deleted] << path
          end
          File.open(File.dirname(ledger), File::RDONLY, &:fsync)
          data['state'] = backups.any? { |path| File.exist?(path) } ? 'expiry_prepared' : 'expired'
          publish(ledger, JSON.pretty_generate(data))
        rescue StandardError => e
          result[:retained] << { ledger: ledger, reason: e.class.name }
        end
      end
      result
    end

    # Prune duplicate physical bytes, not recovery names: hardlink replacement
    # preserves every store-specific rollback API and never loses the last copy.
    # Only committed writer-defined backup rows enter this inventory.
    def self.legacy_backups
      root = File.join(Dir.home, '.pwn')
      patterns = ['session_cleanup_archive/*/ledger.json', 'learning/migrations/*.json', 'maintenance/retirements/*/ledger.json']
      rows = []
      patterns.each do |pattern|
        Dir.glob(File.join(root, pattern)).first(policy['scan_limit']).each do |ledger|
          break unless admit?
          next unless File.realpath(ledger) == ledger

          data = JSON.parse(admitted_bytes(ledger))
          candidates = []
          if ledger.start_with?("#{File.join(root, 'learning', 'migrations')}/")
            hash = File.basename(ledger, '.json')
            next unless data['version'] == 1 && data['state'] == 'committed' && data['before_sha256'] == hash && hash.match?(/\A[a-f0-9]{64}\z/)

            candidates << [File.join(File.dirname(ledger), "#{hash}.backup.jsonl"), hash]
          elsif ledger.start_with?("#{File.join(root, 'maintenance', 'retirements')}/")
            next unless data['state'] == 'committed' && data['session_id'].to_s.match?(PWN::Sessions::SESSION_ID)

            candidates << [data['backup'], data['sha256']]
          elsif data['dry_run'] == false && data['records'].is_a?(Array) && data['deleted_ids'].is_a?(Array)
            data['records'].each do |row|
              next unless row['deleted'] == true && data['deleted_ids'].include?(row['id']) && row['id'].to_s.match?(PWN::Sessions::SESSION_ID)

              row.fetch('files', {}).each do |name, info|
                next unless info && ["#{row['id']}.jsonl", "#{row['id']}.meta.json"].include?(name)

                candidates << [File.join(File.dirname(ledger), name), info['sha256']]
              end
            end
            Array(data['dependency_removals']).each do |row|
              candidates << [row['backup'], row['sha256']] if row['state'] == 'committed'
            end
          end
          candidates.each do |path, hash|
            next unless path.is_a?(String) && File.dirname(path) == File.dirname(ledger)
            next unless verified_backup?(path, hash)

            rows << { path: path, sha256: hash, ledger: ledger }
          end
        rescue StandardError
          # Unknown, partial and unreadable ledgers remain untouched.
          next
        end
      end
      rows.uniq { |row| row[:path] }
    end

    def self.verified_backup?(path, hash, admitted: false, size: nil)
      hash.is_a?(String) && hash.match?(/\A[a-f0-9]{64}\z/) && File.file?(path) &&
        File.realpath(path) == path && File.stat(path).uid == Process.uid &&
        Digest::SHA256.hexdigest(admitted ? exact_bytes(path, size || File.size(path)) : admitted_bytes(path)) == hash
    end

    def self.prune_legacy_backups(dry_run: true)
      result = { operation: 'backup_compaction', state: 'planned', compacted: [], retained: [], records: [] }
      days = policy['retention_days']['maintenance']
      return result if days.nil?

      with_maintenance_lock(dry_run: dry_run) do
        # Learning and continuation producers also serialize with these locks.
        with_dependency_lock(nil, dry_run: dry_run) do
          groups = legacy_backups.group_by { |row| row[:sha256] }
          usage = status[:categories]['maintenance'][:unique_bytes]
          budget = policy['budget_bytes']['maintenance']
          groups.each_value do |rows|
            canonical = rows.first
            rows.drop(1).each do |row|
              break unless admit?
              break if result[:compacted].length >= policy['batch_size']
              next if File.identical?(canonical[:path], row[:path])
              next if File.mtime(row[:ledger]) > Time.now - (days * 86_400) && !(budget && usage > budget)

              size = File.size(row[:path])
              break unless admit?((size + 1) * 5)

              usage -= size
              record = row.merge(canonical: canonical[:path], bytes: size, state: 'prepared')
              result[:records] << record
              next if dry_run

              unless result[:ledger]
                directory = private_directory(File.join(Dir.home, '.pwn', 'maintenance', 'compactions'))
                result[:ledger] = File.join(directory, "#{SecureRandom.hex(12)}.json")
              end
              result[:state] = 'prepared'
              publish(result[:ledger], JSON.generate(result))
              compact_backup(record)
              record[:state] = 'committed'
              result[:compacted] << row[:path]
              publish(result[:ledger], JSON.generate(result))
            rescue StandardError => e
              result[:retained] << { path: row[:path], reason: e.class.name }
            end
          end
          result[:state] = stopping? || result[:records].any? { |row| row[:state] == 'prepared' } ? 'interrupted' : 'committed' unless dry_run
          publish(result[:ledger], JSON.generate(result)) if result[:ledger]
        end
      end
      result
    end

    def self.compact_backup(row)
      path, canonical, hash = row.values_at(:path, :canonical, :sha256)
      size = row[:bytes] || File.size(path)
      raise IOError, 'Changed backup' unless verified_backup?(path, hash, admitted: true, size: size) && verified_backup?(canonical, hash, admitted: true, size: size)
      return if File.identical?(path, canonical)

      temporary = "#{path}.compact-#{SecureRandom.hex(12)}"
      begin
        File.link(canonical, temporary)
        raise IOError, 'Backup readback mismatch' unless exact_bytes(temporary, size) == exact_bytes(path, size)

        File.rename(temporary, path)
        File.open(File.dirname(path), File::RDONLY, &:fsync)
        raise IOError, 'Compacted backup mismatch' unless verified_backup?(path, hash, admitted: true, size: size)
      ensure
        File.unlink(temporary) if temporary && File.exist?(temporary)
      end
    end

    # Status is not rollback: broad maintenance has independently committed
    # children. Restoring a ledger alone never undoes deletion or migration.
    def self.recovery_status(ledger:)
      root = File.join(Dir.home, '.pwn')
      prefixes = %w[maintenance session_cleanup_archive learning/migrations].map { |name| "#{File.join(root, name)}/" }
      raise IOError, 'Unsafe recovery ledger' unless prefixes.any? { |prefix| ledger.start_with?(prefix) } && File.realpath(ledger) == ledger

      data = JSON.parse(File.binread(ledger))
      operation = data['operation']
      operation = 'session_layout' if File.basename(ledger) == 'layout.json' && ledger.start_with?("#{File.join(root, 'session_cleanup_archive')}/") && data['records'].is_a?(Array)
      operation = 'learning_migration' if ledger.start_with?("#{File.join(root, 'learning', 'migrations')}/") && data['version'] == 1 && data['before_sha256'] == File.basename(ledger, '.json')
      operation = 'session_cleanup' if ledger.start_with?("#{File.join(root, 'session_cleanup_archive')}/") && data['dry_run'] == false && data['records'].is_a?(Array) && data['deleted_ids'].is_a?(Array)
      operation = 'continuation_retirement' if ledger.start_with?("#{File.join(root, 'maintenance', 'retirements')}/") && %w[prepared committed rolled_back].include?(data['state']) && data['backup'] == File.join(File.dirname(ledger), 'personas.json')
      actions = { 'session_layout' => ['resume'], 'session_cleanup' => ['restore'], 'continuation_retirement' => ['rollback'], 'backup_compaction' => ['resume'], 'maintenance' => ['resume'], 'learning_migration' => ['rollback'], 'routine' => ['restore'] }.fetch(operation, ['inspect_store_specific_recovery'])
      actions << 'rollback_dependencies' if operation == 'session_cleanup' && data['dependency_removals'].is_a?(Array)
      { ledger: ledger, state: data['state'] || 'legacy_per_record', operation: operation,
        actions: actions,
        data: data, warning: 'Ledger restoration does not undo data changes; restore source sessions before learning rollback.' }
    end

    # Recovery is explicit repair, never startup/cron behavior. Both prepared
    # and committed rows retain exact backups; an existing destination wins.
    def self.recover(ledger:, dry_run: true, action: 'restore', writers_stopped: false)
      report = recovery_status(ledger: ledger)
      raise ArgumentError, 'Unsupported recovery action; inspect recovery_status' unless report[:actions].include?(action)

      return reorganize(dry_run: dry_run, writers_stopped: writers_stopped) if report[:operation] == 'session_layout'

      return recover_dependencies(ledger: ledger, data: report[:data], dry_run: dry_run) if action == 'rollback_dependencies'
      return recover_sessions(ledger: ledger, data: report[:data], dry_run: dry_run) if report[:operation] == 'session_cleanup'
      return recover_continuation(ledger: ledger, data: report[:data], dry_run: dry_run) if report[:operation] == 'continuation_retirement'
      if report[:operation] == 'learning_migration'
        return with_maintenance_lock(dry_run: dry_run) do
          PWN::AI::Agent::Learning.rollback_evidence(migration: File.basename(ledger, '.json'), dry_run: dry_run)
        end
      end
      return dry_run ? report.merge(dry_run: true) : maintain(dry_run: false) if report[:operation] == 'maintenance'
      if report[:operation] == 'backup_compaction'
        return with_maintenance_lock(dry_run: dry_run) do
          with_dependency_lock(nil, dry_run: dry_run) do
            known = legacy_backups.to_h { |row| [row[:path], row[:sha256]] }
            data = report[:data]
            data.fetch('records').each do |row|
              raise IOError, 'Unknown compaction source' unless [row['path'], row['canonical']].all? { |path| known[path] == row['sha256'] }
              next if dry_run

              compact_backup(row.transform_keys(&:to_sym))
              row['state'] = 'committed'
              publish(ledger, JSON.generate(data))
            end
            data['state'] = 'committed' unless dry_run
            publish(ledger, JSON.generate(data)) unless dry_run
            { dry_run: dry_run, state: data['state'], operation: 'backup_compaction' }
          end
        end
      end
      root = File.join(Dir.home, '.pwn', 'maintenance', 'quarantine')
      raise IOError, 'Unsafe recovery ledger' unless ledger.start_with?("#{root}/") && File.realpath(ledger) == ledger

      data = JSON.parse(File.binread(ledger))
      raise IOError, 'Unknown recovery ledger' unless data['operation'] == 'routine' && data['records'].is_a?(Array)

      result = { operation: 'repair', dry_run: dry_run, restored: [] }
      with_maintenance_lock(dry_run: dry_run) do
        data['records'].each do |row|
          path = row.fetch('path')
          category = row.fetch('category')
          target_root = File.join(Dir.home, '.pwn', category)
          backup_path = row.fetch('backup')
          raise IOError, 'Unsafe recovery path' unless %w[cache tmp logs].include?(category) && path.start_with?("#{target_root}/") && File.expand_path(path) == path && File.realpath(File.dirname(path)) == File.dirname(path)
          raise IOError, 'Unsafe recovery backup' unless File.dirname(backup_path) == File.dirname(ledger) && File.realpath(backup_path) == backup_path && Digest::SHA256.file(backup_path).hexdigest == row['sha256']
          raise IOError, 'Refusing existing recovery destination' if File.exist?(path) || File.symlink?(path)
          next if dry_run

          File.open("#{path}.lease", File::RDWR | File::NOFOLLOW) do |lease|
            raise IOError, 'Recovery destination active' unless lease.flock(File::LOCK_EX | File::LOCK_NB)

            temporary = "#{path}.restore-#{SecureRandom.hex(12)}"
            begin
              publish(temporary, File.binread(backup_path))
              File.link(temporary, path) # atomic no-clobber; never replace a reader's new file
              File.open(File.dirname(path), File::RDONLY, &:fsync)
              result[:restored] << path
              row['recovered_at'] = Time.now.utc.iso8601
              publish(ledger, JSON.pretty_generate(data))
            ensure
              File.unlink(temporary) if temporary && File.exist?(temporary)
            end
          end
        end
      end
      result
    end

    def self.recover_dependencies(ledger:, data:, dry_run:)
      result = { dry_run: dry_run, restored: [] }
      root = File.join(Dir.home, '.pwn')
      allowed = %w[learning.jsonl memory.json memory.archive.json mistakes.json].map { |name| File.join(root, name) }
      with_maintenance_lock(dry_run: dry_run) do
        with_dependency_lock(nil, dry_run: dry_run) do
          data.fetch('dependency_removals').reverse_each do |row|
            path, backup_path, id = row.values_at('path', 'backup', 'session_id')
            raise IOError, 'Unsafe dependency recovery target' unless allowed.include?(path) && File.realpath(path) == path
            raise IOError, 'Invalid dependency recovery backup' unless File.dirname(backup_path) == File.dirname(ledger) && verified_backup?(backup_path, row['sha256'])
            raise IOError, 'Restore source session before dependency rollback' unless id.is_a?(String) && id.match?(PWN::Sessions::SESSION_ID) && File.file?(File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl"))

            current = Digest::SHA256.file(path).hexdigest
            next if current == row['sha256']
            raise IOError, 'Dependency store changed since removal' unless current == row['updated_sha256']
            next if dry_run

            publish(path, File.binread(backup_path))
            raise IOError, 'Dependency restore mismatch' unless Digest::SHA256.file(path).hexdigest == row['sha256']

            row['state'] = 'rolled_back'
            publish(ledger, JSON.generate(data))
            result[:restored] << path
          end
        end
      end
      result
    end

    def self.restore_copy(backup_path, path, hash)
      raise IOError, 'Invalid recovery backup' unless verified_backup?(backup_path, hash)
      raise IOError, 'Refusing existing recovery destination' if File.exist?(path) || File.symlink?(path)
      raise IOError, 'Unsafe recovery parent' unless File.realpath(File.dirname(path)) == File.dirname(path)

      temporary = "#{path}.restore-#{SecureRandom.hex(12)}"
      begin
        publish(temporary, File.binread(backup_path))
        raise IOError, 'Restore readback mismatch' unless Digest::SHA256.file(temporary).hexdigest == hash

        File.link(temporary, path)
        File.open(File.dirname(path), File::RDONLY, &:fsync)
      ensure
        File.unlink(temporary) if temporary && File.exist?(temporary)
      end
    end

    def self.recover_sessions(ledger:, data:, dry_run:)
      result = { dry_run: dry_run, restored: [], warning: 'Session bytes only; dependency remediations and learning migration are separate transactions.' }
      with_maintenance_lock(dry_run: dry_run) do
        data.fetch('records').each do |row|
          id = row['id']
          next unless id.is_a?(String) && id.match?(PWN::Sessions::SESSION_ID)

          # A crash can follow unlink before deleted_ids was journaled. The
          # exact prepared snapshot is also eligible, but never replaces data.
          next unless row['files'].is_a?(Hash)

          row['files'].each do |name, info|
            next unless info && ["#{id}.jsonl", "#{id}.meta.json"].include?(name)

            backup_path = File.join(File.dirname(ledger), name)
            next unless File.file?(backup_path)
            raise IOError, 'Invalid session recovery backup' unless verified_backup?(backup_path, info['sha256'])

            path = name.end_with?('.meta.json') ? PWN::Sessions.support_path(kind: :metadata, session_id: id) : File.join(PWN::Sessions.sessions_dir, name)
            next if verified_backup?(path, info['sha256'])
            raise IOError, 'Refusing existing recovery destination' if File.exist?(path) || File.symlink?(path)
            next if dry_run

            File.open(PWN::Sessions.support_path(kind: :lease, session_id: id), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
              raise IOError, 'Session recovery active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

              restore_copy(backup_path, path, info['sha256'])
              result[:restored] << path
              (data['restored_paths'] ||= []) << path
              publish(ledger, JSON.generate(data))
            end
          end
        end
      end
      result
    end

    def self.recover_continuation(ledger:, data:, dry_run:)
      root = File.join(Dir.home, '.pwn')
      path, id = data.values_at('path', 'session_id')
      raise IOError, 'Unsafe continuation recovery path' unless path.is_a?(String) && path.match?(%r{\A#{Regexp.escape(root)}/swarm/\d{8}_\d{6}_[a-f0-9]{6}/personas\.json\z}) && File.realpath(path) == path
      raise IOError, 'Invalid continuation recovery identity' unless id.is_a?(String) && id.match?(PWN::Sessions::SESSION_ID)
      raise IOError, 'Invalid continuation backup' unless verified_backup?(data['backup'], data['sha256'])

      before = File.binread(data['backup'])
      map = JSON.parse(before)
      raise IOError, 'Invalid continuation backup schema' unless map.is_a?(Hash) && map[data['name']] == id

      expected = map.reject { |name, _| name == data['name'] }
      result = { dry_run: dry_run, restored: [] }
      with_maintenance_lock(dry_run: dry_run) do
        with_dependency_lock(nil, dry_run: dry_run) do
          current = JSON.parse(File.binread(path))
          raise IOError, 'Continuation map changed after retirement' unless current == expected || current == map
          next if dry_run || current == map

          File.open(PWN::Sessions.support_path(kind: :lease, session_id: id), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lease|
            raise IOError, 'Continuation recovery active' unless lease.flock(File::LOCK_EX | File::LOCK_NB)
            raise IOError, 'Restore source session before continuation' unless File.file?(File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl"))

            publish(path, before)
            raise IOError, 'Continuation restore readback mismatch' unless File.binread(path) == before

            data['state'] = 'rolled_back'
            publish(ledger, JSON.generate(data))
            result[:restored] << path
          end
        end
      end
      result
    end

    def self.with_continuation_lock(root: File.join(Dir.home, '.pwn'))
      File.open(File.join(root, '.swarm-continuations.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        lock.flock(File::LOCK_EX)
        yield
      end
    end

    def self.retire_continuation(root:, swarm_id:, name:)
      raise ArgumentError, 'Invalid swarm identifier' unless swarm_id.match?(/\A\d{8}_\d{6}_[a-f0-9]{6}\z/)

      path = File.join(root, swarm_id, 'personas.json')
      with_maintenance_lock(dry_run: false) do
        with_continuation_lock(root: File.dirname(root)) do
          raise IOError, 'Unsafe continuation map' unless File.realpath(path) == path

          bytes = File.binread(path)
          map = JSON.parse(bytes)
          raise IOError, 'Unknown continuation map' unless map.is_a?(Hash) && map.values.all? { |id| id.is_a?(String) && id.match?(/\A\d{8}_\d{6}_[a-f0-9]{8}\z/) }

          id = map[name]
          next { state: 'absent' } unless id

          File.open(PWN::Sessions.support_path(kind: :lease, session_id: id), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lease|
            raise IOError, 'Swarm continuation active' unless lease.flock(File::LOCK_EX | File::LOCK_NB)

            directory = private_directory(File.join(Dir.home, '.pwn', 'maintenance', 'retirements', SecureRandom.hex(12)))
            backup_path = File.join(directory, 'personas.json')
            publish(backup_path, bytes)
            raise IOError, 'Continuation backup mismatch' unless File.binread(backup_path) == bytes

            result = { state: 'prepared', session_id: id, path: path, name: name, backup: backup_path, sha256: Digest::SHA256.hexdigest(bytes) }
            ledger = File.join(directory, 'ledger.json')
            publish(ledger, JSON.pretty_generate(result))
            map.delete(name)
            publish(path, JSON.pretty_generate(map))
            raise IOError, 'Continuation retirement mismatch' unless JSON.parse(File.binread(path)) == map

            result[:state] = 'committed'
            publish(ledger, JSON.pretty_generate(result))
            result
          end
        end
      end
    end

    def self.classify(path, id)
      return :unknown unless path == File.join(PWN::Sessions.sessions_dir, "#{id}.jsonl")

      PWN::Sessions.title_status(session_id: id)[:classification]
    end

    # Compatibility discovery only: upgraded launchers never block unrelated
    # sessions. Legacy in-memory IDs cannot safely be inferred from recent mtimes.
    def self.legacy_owners(proc_root)
      return [{ error: 'process_inventory_unavailable' }] unless File.directory?(proc_root)

      Dir.glob(File.join(proc_root, '[0-9]*')).filter_map do |dir|
        next if File.basename(dir).to_i == Process.pid
        next unless File.stat(dir).uid == Process.uid

        argv = File.binread(File.join(dir, 'cmdline')).split("\0")
        next unless pwn_launcher?(argv, dir)
        next if tracked_owner?(dir)

        { pid: File.basename(dir).to_i, reason: 'legacy_session_ownership_unknown' }
      rescue Errno::ENOENT, Errno::ESRCH
        nil
      rescue IOError, SystemCallError
        { pid: File.basename(dir).to_i, reason: 'ownership_unreadable' }
      end
    rescue IOError, SystemCallError
      [{ error: 'process_inventory_unreadable' }]
    end

    def self.pwn_launcher?(argv, dir)
      executable = %r{\A(?:[^\s]*/)?pwn(?:-[a-zA-Z0-9_-]+)?\z}
      return true if argv.first.to_s.match?(executable)
      return false unless argv.first.to_s.match?(%r{\A(?:[^\s]*/)?ruby[\d.]*(?:\s|\z)})
      return false unless File.basename(File.readlink(File.join(dir, 'exe'))).match?(/\Aruby[\d.]*\z/)
      return true if argv.first.to_s.match?(%r{\A\S*ruby[\d.]*\s+(?:[^\s]*/)?pwn(?:-[a-zA-Z0-9_-]+)?\z})

      args = argv.drop(1)
      while args.first&.start_with?('-')
        option = args.shift
        break if option == '--'
        break args.clear if option.start_with?('-e')

        args.shift if %w[-I -r -C -E -F].include?(option)
      end
      args.first.to_s.match?(executable)
    end

    def self.tracked_owner?(dir)
      return false unless File.file?(File.join(dir, 'stat'))

      start = File.read(File.join(dir, 'stat')).split(') ').last.split[19]
      # fdinfo proves this process holds the locked open-file description, not
      # merely an unlocked descriptor to another process's marker. Forked tool
      # workers inherit that capability and the precise session leases; they
      # must not be mistaken for untracked legacy launchers. A reused PID alone
      # has neither descriptor. Marker filenames bind the original PID/start.
      tracked = Dir.glob(File.join(dir, 'fd', '*')).any? do |fd|
        marker = File.readlink(fd)
        next false unless File.basename(marker).match?(/\A\.activity-owner-\d+-\d+\.lock\z/)

        info = File.read(File.join(dir, 'fdinfo', File.basename(fd)))
        info.match?(/^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s/)
      rescue Errno::ENOENT
        false
      end
      tracked && File.read(File.join(dir, 'stat')).split(') ').last.split[19] == start
    end

    def self.pins_known?
      referenced_session_ids
      true
    rescue StandardError
      false
    end

    # Cleanup preserves evidence referenced by all retained learning, mistake
    # and durable memory records, not just the ordinary gold/open/hot pins.
    def self.referenced_session_ids
      references = PWN::Sessions.dependency_index
      raise 'Uncertain dependency stores' unless references[:errors].empty?

      references[:dependencies].keys
    end

    # Fingerprints include inode identity and nanosecond timestamps, not bodies.
    def self.snapshot(path)
      [path, PWN::Sessions.support_path(kind: :metadata, session_id: File.basename(path, '.jsonl'))].to_h do |file|
        raise 'Refusing symlink' if File.symlink?(file)
        next [File.basename(file), nil] unless File.exist?(file)

        stat = File.stat(file)
        raise 'Not a regular file' unless stat.file?

        [File.basename(file), { sha256: Digest::SHA256.file(file).hexdigest, size: stat.size, inode: stat.ino, device: stat.dev, mtime: stat.mtime.to_r.to_s, ctime: stat.ctime.to_r.to_s }]
      end
    end

    def self.publish(path, bytes)
      temporary = "#{path}.#{SecureRandom.hex(8)}.tmp"
      root = File.join(Dir.home, '.pwn')
      category = %w[cache tmp].find { |name| path.start_with?("#{File.join(root, name)}/") }
      if category
        directory = private_directory(File.join(root, 'maintenance', 'atomic'))
        journal = File.join(directory, "#{SecureRandom.hex(12)}.json")
      end
      File.open(temporary, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
        file.flock(File::LOCK_EX)
        if journal
          row = { version: 1, operation: 'atomic_disposable', category: category, path: temporary, target: path,
                  inode: file.stat.ino, device: file.stat.dev, sha256: Digest::SHA256.hexdigest(bytes), created_at: Time.now.to_i }
          publish(journal, JSON.generate(row))
        end
        file.write(bytes)
        file.flush
        file.fsync
        File.rename(temporary, path)
        File.open(File.dirname(path), File::RDONLY, &:fsync)
      end
    ensure
      File.unlink(temporary) if temporary && File.exist?(temporary)
      File.unlink(journal) if journal && File.exist?(journal)
    end

    # Only registered disposable atomic outputs are recoverable automatically.
    # Missing journals, partial bytes, wrong inode, active writers and evidence
    # atomic outputs are preserved, regardless of filename or apparent age.
    def self.recover_atomic_temps(dry_run: true, expired_only: false)
      result = { deleted: [], retained: [] }
      root = File.join(Dir.home, '.pwn')
      with_maintenance_lock(dry_run: dry_run) do
        Dir.glob(File.join(root, 'maintenance', 'atomic', '*.json')).first(policy['scan_limit']).each do |ledger|
          break unless admit?
          break if result[:deleted].length >= policy['batch_size']
          raise IOError, 'Unsafe atomic ledger' unless File.realpath(ledger) == ledger

          row = JSON.parse(admitted_bytes(ledger))
          raise IOError, 'Unknown atomic owner' unless row['version'] == 1 && row['operation'] == 'atomic_disposable' && %w[cache tmp].include?(row['category'])

          days = policy['retention_days'][row['category']]
          next if days.nil? || (expired_only && row.fetch('created_at') > Time.now.to_i - (days * 86_400))

          path, target = row.values_at('path', 'target')
          base = "#{File.join(root, row['category'])}/"
          raise IOError, 'Unsafe atomic path' unless [path, target].all? { |name| name.is_a?(String) && name.start_with?(base) && File.expand_path(name) == name } && File.dirname(path) == File.dirname(target) && path.match?(/\A#{Regexp.escape(target)}\.[a-f0-9]{16}\.tmp\z/)
          next unless File.exist?(path) || File.symlink?(path)
          raise IOError, 'Changed atomic bytes' unless verified_backup?(path, row['sha256']) && File.stat(path).ino == row['inode'] && File.stat(path).dev == row['device']

          File.open("#{target}.lease", File::RDWR | File::NOFOLLOW) do |lease|
            raise IOError, 'Atomic producer active' unless lease.flock(File::LOCK_EX | File::LOCK_NB)

            File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
              raise IOError, 'Atomic file active or changed' unless file.flock(File::LOCK_EX | File::LOCK_NB) && File.identical?(file, path) && file.stat.ino == row['inode'] && Digest::SHA256.hexdigest(admitted_bytes(path)) == row['sha256']
              next if dry_run

              File.unlink(path)
              File.open(File.dirname(path), File::RDONLY, &:fsync)
              row['state'] = 'recovered'
              publish(ledger, JSON.generate(row))
              result[:deleted] << path
            end
          end
        rescue StandardError => e
          result[:retained] << { ledger: ledger, reason: e.class.name }
        end
      end
      result
    end

    def self.backup(path, expected, result)
      unless result[:archive_dir]
        base = File.join(Dir.home, '.pwn', 'session_cleanup_archive')
        raise 'Unsafe archive directory' if File.symlink?(base)

        FileUtils.mkdir_p(base, mode: 0o700)
        raise 'Unsafe archive permissions' unless File.stat(base).uid == Process.uid && (File.stat(base).mode & 0o777) == 0o700

        result[:archive_dir] = File.join(base, "#{Time.now.utc.strftime('%Y%m%dT%H%M%S')}-#{SecureRandom.hex(8)}")
        Dir.mkdir(result[:archive_dir], 0o700)
      end
      expected.each do |name, record|
        next unless record

        source = name.end_with?('.meta.json') ? PWN::Sessions.support_path(kind: :metadata, session_id: File.basename(name, '.meta.json')) : File.join(File.dirname(path), name)
        bytes = File.binread(source)
        raise 'Changed before backup' unless Digest::SHA256.hexdigest(bytes) == record[:sha256]

        target = File.join(result[:archive_dir], name)
        publish(target, bytes)
        raise 'Backup verification failed' unless Digest::SHA256.file(target).hexdigest == record[:sha256]
      end
      publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result))
    end

    # Only stores with a cooperating permanent writer lock are auto-remediated.
    # Other attributed errors remain explicit operator work, never broad GC.
    def self.invalid_dependencies(id, references = nil)
      (references || PWN::Sessions.dependency_index)[:invalid_records].select { |row| row[:owners].include?(id) }
    end

    def self.remediable?(id, references = nil)
      rows = invalid_dependencies(id, references)
      !rows.empty? && rows.all? do |row|
        relative = row[:path].delete_prefix("#{File.join(Dir.home, '.pwn')}/")
        supported = (relative == 'learning.jsonl' && row[:locator].is_a?(Integer)) ||
                    (%w[memory.json memory.archive.json mistakes.json].include?(relative) && row[:locator].is_a?(String))
        row[:owners] == [id] && supported
      end
    end

    def self.cleanup_state(path, id, references = nil)
      state = classify(path, id)
      return state if state == :unknown

      status = PWN::Sessions.retention_status(session_id: id, references: references)
      return :invalid_dependency unless status[:dependency_errors].empty?

      state
    end

    def self.with_dependency_lock(id, dry_run: false)
      return yield if dry_run

      rows = invalid_dependencies(id)
      raise 'Unresolved dependency remediation' unless rows.empty? || remediable?(id)

      # Lock even absent stores: a concurrent writer can introduce the first
      # reference between the final index and unlink. These inodes are permanent.
      root = File.join(Dir.home, '.pwn')
      paths = %w[.learning-write.lock .swarm-continuations.lock memory.json.write.lock mistakes.json.write.lock].map { |name| File.join(root, name) }.sort
      locks = []
      begin
        paths.each do |path|
          lock = File.open(path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) # rubocop:disable Style/FileOpen -- closed together in ensure
          locks << lock
          raise 'Dependency writer active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)
        end
        yield
      ensure
        locks.reverse_each(&:close)
      end
    end

    def self.remove_invalid_dependencies(id, result)
      rows = invalid_dependencies(id)
      return if rows.empty?

      raise 'Dependency remediation changed' unless remediable?(id)

      rows.group_by { |row| row[:path] }.each do |path, entries|
        bytes = File.binread(path)
        hash = Digest::SHA256.hexdigest(bytes)
        raise 'Dependency changed' unless entries.all? { |row| row[:sha256] == hash }

        backup_path = File.join(result[:archive_dir], "dependency-#{SecureRandom.hex(8)}.jsonl")
        publish(backup_path, bytes)
        raise 'Dependency backup failed' unless Digest::SHA256.file(backup_path).hexdigest == hash

        locators = entries.map { |row| row[:locator] }
        updated = if path.end_with?('.jsonl')
                    bytes.lines.each_with_index.reject { |_, index| locators.include?(index) }.map(&:first).join
                  else
                    map = JSON.parse(bytes)
                    raise 'Dependency map changed' unless map.is_a?(Hash) && locators.all? { |key| map.key?(key) }

                    locators.each { |key| map.delete(key) }
                    JSON.pretty_generate(map)
                  end
        removal = { session_id: id, path: path, backup: backup_path, sha256: hash,
                    updated_sha256: Digest::SHA256.hexdigest(updated), locators: locators, state: 'prepared' }
        (result[:dependency_removals] ||= []) << removal
        publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result))
        raise 'Dependency changed after backup' unless File.binread(path) == bytes

        publish(path, updated)
        # Compare exact bytes even when JSON emits non-ASCII UTF-8 text.
        raise 'Dependency write verification failed' unless File.binread(path) == updated.b

        removal[:state] = 'committed'
        publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result))
      end
    end

    # The command and bundled cron use this exact maintenance transaction.
    # Legacy writers block all mutations, including evidence migration.
    # One permanent inode serializes CLI, curses and cron maintenance writers.
    # Read-only previews never acquire a writer lock or create lock files.
    def self.with_maintenance_lock(dry_run:)
      return yield if dry_run

      root = PWN::Sessions.sessions_dir
      raise IOError, 'Unsafe session maintenance directory' unless File.realpath(root) == File.expand_path(root)

      path = File.join(root, '.maintenance.lock')
      owner = Thread.current[:pwn_session_maintenance_lock]
      return yield if owner && owner[:pid] == Process.pid && owner[:thread] == Thread.current && owner[:path] == path && !owner[:file].closed?

      File.open(path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |file|
        raise IOError, 'Session maintenance already running; wait for its result before retrying' unless file.flock(File::LOCK_EX | File::LOCK_NB)

        begin
          Thread.current[:pwn_session_maintenance_lock] = { pid: Process.pid, thread: Thread.current, path: path, file: file }
          yield
        ensure
          Thread.current[:pwn_session_maintenance_lock] = owner
        end
      end
    end

    def self.stopping?
      control = Thread.current[:pwn_steering_input]
      budget = Thread.current[:pwn_maintenance_budget]
      (control.respond_to?(:stopping?) && control.stopping?) || (budget && (budget[:remaining] <= 0 || budget[:bytes] <= 0 || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= budget[:deadline]))
    end

    # Fresh schedules use one coordinator. Existing split jobs keep maintain
    # until an operator explicitly replaces their schedules after deployment.
    # Preserve evidence before retention can remove its last source edge.
    def self.coordinate(dry_run: false, current_session_id: nil, proc_root: '/proc')
      with_maintenance_lock(dry_run: dry_run) do
        result = { state: 'prepared', dry_run: dry_run, phases: {} }
        unless dry_run
          directory = private_directory(File.join(Dir.home, '.pwn', 'maintenance', 'runs'))
          ledger = File.join(directory, "coordinator-#{SecureRandom.hex(12)}.json")
          publish(ledger, JSON.generate(result))
        end
        begin
          maintenance = maintain(dry_run: dry_run, current_session_id: current_session_id, proc_root: proc_root)
          result[:phases][:maintenance] = maintenance
          if maintenance[:apply_blocked] || maintenance[:incomplete] || stopping?
            result[:state] = maintenance[:apply_blocked] ? 'blocked' : 'interrupted'
          else
            result[:phases][:memory_consolidation] = dry_run ? { planned: true } : PWN::AI::Agent::Learning.consolidate
            result[:phases][:learning_retention] = PWN::AI::Agent::Learning.prune_outcomes!(dry_run: dry_run)
            result[:phases][:mistakes_retention] = PWN::AI::Agent::Mistakes.lean!(dry_run: dry_run)
            result[:phases][:policy_retention] = PWN::AI::Agent::Policy.lean!(dry_run: dry_run)
            result[:state] = dry_run ? 'planned' : 'committed'
          end
          result[:transaction_ledger] = ledger if ledger
          publish(ledger, JSON.generate(result)) if ledger
          result
        rescue StandardError, Interrupt, SystemExit => e
          result[:state] = 'interrupted'
          publish(ledger, JSON.generate(result.merge(error: e.class.name))) if ledger
          raise
        end
      end
    end

    def self.maintain(dry_run: false, current_session_id: nil, proc_root: '/proc')
      config = policy # validate policy before any mutation or migration
      prior_budget = Thread.current[:pwn_maintenance_budget]
      prior_admission = Thread.current[:pwn_maintenance_admission]
      Thread.current[:pwn_maintenance_budget] = { remaining: config['work_items'], bytes: config['work_bytes'], deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + config['work_seconds'] }
      Thread.current[:pwn_maintenance_admission] = method(:admit?)
      with_maintenance_lock(dry_run: dry_run) do
        unless dry_run
          directory = private_directory(File.join(Dir.home, '.pwn', 'maintenance', 'runs'))
          ledger = File.join(directory, "#{Time.now.utc.strftime('%Y%m%dT%H%M%S')}-#{SecureRandom.hex(8)}.json")
          publish(ledger, JSON.generate(version: 1, state: 'prepared', operation: 'maintenance'))
        end
        begin
          result = maintenance_transaction(dry_run: dry_run, current_session_id: current_session_id, proc_root: proc_root)
          result[:storage] = clean_disposables(dry_run: dry_run || result[:apply_blocked] == true)
          result[:quarantine] = prune_quarantine(dry_run: dry_run || result[:apply_blocked] == true)
          unless stopping?
            result[:atomic_temps] = recover_atomic_temps(dry_run: dry_run || result[:apply_blocked] == true, expired_only: true)
            result[:legacy_backups] = prune_legacy_backups(dry_run: dry_run || result[:apply_blocked] == true)
          end
          result[:migration_backups] = PWN::Migrate.prune_backups(dry_run: dry_run || result[:apply_blocked] == true, admission: method(:admit?)) unless stopping?
          result[:usage] = status unless stopping?
          result[:incomplete] = true if stopping? || result[:storage][:incomplete]
          result[:state] = if dry_run
                             'planned'
                           elsif result[:incomplete] || result[:storage][:state] == 'interrupted'
                             'interrupted'
                           elsif result[:apply_blocked]
                             'blocked'
                           else
                             'committed'
                           end
          result[:transaction_ledger] = ledger if ledger
          publish(ledger, JSON.generate(version: 1, state: result[:state], operation: 'maintenance', result: result)) if ledger
          result
        rescue StandardError, Interrupt, SystemExit => e
          publish(ledger, JSON.generate(version: 1, state: 'interrupted', operation: 'maintenance', error: e.class.name, result: result)) if ledger
          raise
        end
      end
    ensure
      Thread.current[:pwn_maintenance_budget] = prior_budget
      Thread.current[:pwn_maintenance_admission] = prior_admission
    end

    # Admission is cooperative: an admitted atomic write is never interrupted.
    def self.admit?(bytes = 0)
      return false if stopping?

      budget = Thread.current[:pwn_maintenance_budget]
      if budget
        budget[:remaining] -= 1
        if bytes > budget[:bytes]
          budget[:bytes] = 0
          return false
        end
        budget[:bytes] -= bytes
      end
      true
    end

    def self.maintenance_transaction(dry_run:, current_session_id:, proc_root:)
      preflight = sweep(dry_run: true, current_session_id: current_session_id, proc_root: proc_root)
      blocked = stopping? || !preflight[:legacy_owners].empty? || Array(preflight[:unresolved_store_remediation]).any?
      unless dry_run || blocked
        # Private metadata-only preflight survives an interrupted migration.
        backup(File.join(PWN::Sessions.sessions_dir, 'inventory.jsonl'), {}, preflight)
        ledger = File.join(preflight[:archive_dir], 'maintenance.json')
        publish(ledger, JSON.pretty_generate(state: 'prepared', inventory: preflight))
        blocked = !legacy_owners(proc_root).empty?
      end
      return preflight.merge(incomplete: true, apply_blocked: true) if stopping?

      migration = PWN::AI::Agent::Learning.migrate_evidence(dry_run: dry_run || blocked, max_sessions: policy['batch_size'], stop: method(:stopping?), nonblocking: true)
      blocked = true if migration[:deferred]
      result = if dry_run || blocked
                 preflight
               else
                 sweep(dry_run: false, current_session_id: current_session_id, proc_root: proc_root)
               end
      result[:dry_run] = dry_run
      result[:apply_blocked] = true if blocked
      result[:evidence_migration] = migration
      result[:remaining_sessions] = Dir.glob(File.join(PWN::Sessions.sessions_dir, '*.jsonl')).length
      result[:visible_sessions] = PWN::Sessions.list.length
      if ledger
        result[:maintenance_ledger] = ledger
        publish(ledger, JSON.pretty_generate(state: blocked ? 'blocked' : 'committed', inventory: preflight, result: result))
      end
      result
    end

    # Explicit offline layout migration: never a cron side effect. Stop schedulers
    # and all writers first; old binaries cannot understand the new layout.
    # Transcript files never move. Temporary writer remnants are recoverable.
    def self.reorganize(dry_run: true, writers_stopped: false, proc_root: '/proc')
      raise ArgumentError, 'All writers and schedulers must be stopped' unless dry_run || writers_stopped

      with_maintenance_lock(dry_run: dry_run) do
        root = PWN::Sessions.sessions_dir
        plan = Dir.children(root).sort.filter_map do |name|
          target = case name
                   when /\A\d{8}_\d{6}_[a-f0-9]{8}\.meta\.json\z/ then File.join('support', 'metadata', name)
                   when /\A\..+\.cleanup\.lock\z/ then File.join('support', 'leases', name)
                   when /\A\.activity-owner-\d+-\d+\.lock\z/ then File.join('support', 'owners', name)
                   when /\A\d{8}_\d{6}_[a-f0-9]{8}\.jsonl\.\d+\.tmp\z/ then nil
                   else next
                   end
          source = File.join(root, name)
          raise IOError, 'Unsafe layout source' unless File.file?(source) && !File.symlink?(source)

          { source: source, target: target && File.join(root, target), sha256: Digest::SHA256.file(source).hexdigest,
            inode: File.stat(source).ino, temporary: target.nil? }
        end
        # Existing trace paths may be immutable finding/artifact anchors. Keep
        # those exact paths; new traces use compact storage after the marker.
        retained_support = Dir.glob(File.join(root, '*', 'trace.jsonl'))
        references = PWN::Sessions.dependency_index
        raise IOError, 'Uncertain evidence anchors prevent layout migration' unless references[:errors].empty?

        plan.reject! do |row|
          next false unless row[:source].end_with?('.meta.json')

          id = File.basename(row[:source], '.meta.json')
          anchored = !references[:dependencies].fetch(id, []).empty? || !references[:session_errors].fetch(id, []).empty?
          retained_support << row[:source] if anchored
          anchored
        end
        result = { state: 'planned', records: plan, retained_support: retained_support, transcripts: Dir.glob(File.join(root, '*.jsonl')).length }
        next result if dry_run

        raise IOError, 'Legacy writers remain active' unless legacy_owners(proc_root).empty?

        handles = []
        begin
          locks = Dir.glob(File.join(root, 'support', '{leases,owners}', '.*.lock'))
          locks.each do |path|
            file = File.open(path, File::RDWR | File::NOFOLLOW) # rubocop:disable Style/FileOpen -- transaction owns all handles
            handles << file
            locked = file.flock(File::LOCK_EX | File::LOCK_NB)
            own_marker = File.basename(path).start_with?(".activity-owner-#{Process.pid}-")
            raise IOError, 'Session writers are active' unless locked || own_marker
          end
          plan.reject! do |row|
            next false unless row[:source].end_with?('.lock')

            # The migration caller can own its capability marker; leave it in
            # place, not a replacement inode. Other held markers block migration.
            file = File.open(row[:source], File::RDWR | File::NOFOLLOW) # rubocop:disable Style/FileOpen -- transaction holds every lock through commit
            handles << file
            locked = file.flock(File::LOCK_EX | File::LOCK_NB)
            own_marker = File.basename(row[:source]).start_with?(".activity-owner-#{Process.pid}-")
            raise IOError, 'Session writers are active' unless locked || own_marker

            !locked
          end
          backup(File.join(root, 'layout.jsonl'), {}, result)
          ledger = File.join(result[:archive_dir], 'layout.json')
          result[:state] = 'prepared'
          publish(ledger, JSON.pretty_generate(result))
          # Back up every byte before the first move, including abandoned temp
          # output. Do not infer that a temp is safe merely from its age/PID.
          plan.each_with_index do |row, index|
            raise IOError, 'Layout source changed' unless File.stat(row[:source]).ino == row[:inode] && Digest::SHA256.file(row[:source]).hexdigest == row[:sha256]
            raise IOError, 'Layout destination exists' if row[:target] && (File.exist?(row[:target]) || File.symlink?(row[:target]))

            row[:backup] = File.join(result[:archive_dir], "layout-#{index}.bin")
            publish(row[:backup], File.binread(row[:source]))
            raise IOError, 'Layout backup mismatch' unless Digest::SHA256.file(row[:backup]).hexdigest == row[:sha256]
          end
          publish(ledger, JSON.pretty_generate(result))
          plan.each do |row|
            raise IOError, 'Layout source changed' unless Digest::SHA256.file(row[:source]).hexdigest == row[:sha256]

            if row[:temporary]
              File.unlink(row[:source])
            else
              FileUtils.mkdir_p(File.dirname(row[:target]), mode: 0o700)
              raise IOError, 'Unsafe layout destination' unless File.realpath(File.dirname(row[:target])) == File.expand_path(File.dirname(row[:target]))

              File.rename(row[:source], row[:target])
              raise IOError, 'Layout move mismatch' unless File.stat(row[:target]).ino == row[:inode] && Digest::SHA256.file(row[:target]).hexdigest == row[:sha256]
            end
            row[:moved] = true
            publish(ledger, JSON.pretty_generate(result))
          end
          publish(File.join(root, '.layout-v2'), "2\n")
          result[:state] = 'committed'
          publish(ledger, JSON.pretty_generate(result))
          result
        ensure
          handles.each(&:close)
        end
      end
    end

    def self.summary(result)
      { version: VERSION, dry_run: result[:dry_run], apply_blocked: result[:apply_blocked] == true,
        scanned: result[:scanned], candidates: result[:candidate_ids].length, deleted: result[:deleted_ids].length,
        remaining: result[:remaining_sessions], visible: result[:visible_sessions], skipped: result[:skipped],
        evidence_migration: result[:evidence_migration], archive_dir: result[:archive_dir], storage: result[:storage], usage: result[:usage], quarantine: result[:quarantine],
        unresolved_dependency_stores: result[:dependency_errors] || [], legacy_owners: result[:legacy_owners] }
    end

    def self.run(dry_run: true, current_session_id: nil, proc_root: '/proc', approved_candidates: nil)
      return sweep(dry_run: dry_run, current_session_id: current_session_id, proc_root: proc_root, approved_candidates: approved_candidates) if approved_candidates

      maintain(dry_run: dry_run, current_session_id: current_session_id, proc_root: proc_root)
    end

    def self.sweep(dry_run: true, current_session_id: nil, proc_root: '/proc', approved_candidates: nil)
      with_maintenance_lock(dry_run: dry_run) do
        sweep_transaction(dry_run: dry_run, current_session_id: current_session_id, proc_root: proc_root, approved_candidates: approved_candidates)
      end
    end

    def self.sweep_transaction(dry_run:, current_session_id:, proc_root:, approved_candidates:)
      raise 'Session cleanup requires the updated Sessions activity API; load the updated source or deploy it before running this helper' unless PWN::Sessions.respond_to?(:activate)

      root = PWN::Sessions.sessions_dir
      raise 'Refusing symlinked session directory' if File.symlink?(root)

      current = current_session_id || (PWN::Env.dig(:ai, :session_id) if defined?(PWN::Env))
      legacy = legacy_owners(proc_root)
      result = { version: VERSION, dry_run: dry_run, scanned: 0, unnamed: 0, candidate_ids: [], deleted_ids: [], records: [], skipped: Hash.new(0), legacy_owners: legacy }
      references = PWN::Sessions.dependency_index
      result[:incomplete] = true if references[:errors].include?('incomplete_dependency_index')
      unless references[:errors].empty?
        result[:skipped][:unknown_pins] = 1
        result[:dependency_errors] = references[:errors]
        result[:unresolved_store_remediation] = references[:errors]
      end
      result[:diagnostics] = references.fetch(:diagnostics, [])
      dependencies = references[:dependencies]
      pins = dependencies.keys
      Dir.glob(File.join(root, '*.jsonl')).each do |path|
        unless admit?
          result[:incomplete] = true
          break
        end
        id = File.basename(path, '.jsonl')
        result[:scanned] += 1
        state = cleanup_state(path, id, references)
        record = PWN::Sessions.retention_status(session_id: id, references: references).merge(id: id, classification: state, dependencies: dependencies.fetch(id, []))
        result[:records] << record
        unless references[:errors].empty?
          record[:skip] = :unknown_pins
          next
        end
        unless %i[unnamed invalid_dependency].include?(state)
          result[:skipped][state] += 1
          next
        end
        if state == :invalid_dependency && (!remediable?(id, references) || pins.include?(id))
          record[:skip] = :unresolved_dependency_remediation
          result[:skipped][:unresolved_dependency_remediation] += 1
          next
        end
        days = policy['retention_days']['sessions']
        if days.nil? || File.mtime(path) > Time.now - (days * 86_400)
          record[:skip] = :retention
          result[:skipped][:retention] += 1
          next
        end
        expected = snapshot(path)
        expected_dependencies = invalid_dependencies(id, references)
        record[:dependency_records] = expected_dependencies
        record[:files] = expected
        approval = approved_candidates && approved_candidates[id]
        approved = approval.is_a?(Hash) && approval.key?(:files) ? approval[:files] == expected && approval[:dependency_records] == expected_dependencies : approval == expected && expected_dependencies.empty?
        if approved_candidates && !approved
          record[:skip] = :not_approved_or_changed
          result[:skipped][:not_approved_or_changed] += 1
          next
        end
        result[:unnamed] += 1
        if PWN::Sessions.active?(session_id: id)
          record[:skip] = :active
          result[:skipped][:active] += 1
          next
        end
        if id == current || pins.include?(id)
          reason = id == current ? :current : :referenced
          record[:skip] = reason
          result[:skipped][reason] += 1
          next
        end
        result[:candidate_ids] << id
        record[:apply_blocked_by] = :unknown_legacy_ownership unless legacy.empty?
        next if dry_run

        if stopping?
          record[:skip] = :stopped
          result[:skipped][:stopped] += 1
          next
        end
        if result[:deleted_ids].length >= policy['batch_size']
          record[:skip] = :batch_limit
          result[:skipped][:batch_limit] += 1
          next
        end

        unless legacy.empty? && legacy_owners(proc_root).empty?
          record[:skip] = :unknown_legacy_ownership
          result[:skipped][:unknown_legacy_ownership] += 1
          next
        end
        # Never unlink lock files: waiters must keep sharing the same inode.
        lock_path = PWN::Sessions.support_path(kind: :lease, session_id: id)
        raise 'Refusing symlinked cleanup lock' if File.symlink?(lock_path)

        File.open(lock_path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
          unless lock.flock(File::LOCK_EX | File::LOCK_NB)
            result[:skipped][:locked] += 1
            record[:skip] = :locked
            next
          end
          with_dependency_lock(id) do
            File.open(path, File::RDONLY | File::NOFOLLOW) do |transcript|
              unless transcript.flock(File::LOCK_EX | File::LOCK_NB)
                result[:skipped][:locked] += 1
                record[:skip] = :locked
                next
              end
              # Activation and deletion serialize on the same per-session inode.
              # Legacy ownership uncertainty still requires operator migration.
              unless File.identical?(transcript, path) && cleanup_state(path, id) == state && invalid_dependencies(id) == expected_dependencies && snapshot(path) == expected && legacy_owners(proc_root).empty? && pins_known? && !referenced_session_ids.include?(id)
                result[:skipped][:changed] += 1
                record[:skip] = :changed
                next
              end
              backup(path, expected, result)
              unless snapshot(path) == expected && cleanup_state(path, id) == state && invalid_dependencies(id) == expected_dependencies && legacy_owners(proc_root).empty? && pins_known? && !referenced_session_ids.include?(id)
                result[:skipped][:changed] += 1
                record[:skip] = :changed
                next
              end
              # Only verified, archived, unreferenced unsummarized sessions;
              # current and all known reference pins checked above.
              # The normal delete API's age pin is deliberately bypassed here.
              remove_invalid_dependencies(id, result)
              raise 'Dependencies changed after remediation' unless pins_known? && !referenced_session_ids.include?(id) && invalid_dependencies(id).empty? && snapshot(path) == expected

              PWN::Sessions.delete(session_id: id, current_session_id: current, force: true, cleanup_lock: lock)
              raise 'Deletion did not remove both session records' if File.exist?(path) || File.exist?(PWN::Sessions.support_path(kind: :metadata, session_id: id))

              result[:deleted_ids] << id
              record[:deleted] = true
              publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result))
            end
          end
        end
      rescue StandardError => e
        result[:skipped][:error] += 1
        record[:error] = e.class.name if record
      end
      publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result)) if result[:archive_dir]
      result
    end

    private_class_method :with_maintenance_lock, :maintenance_transaction, :sweep_transaction
  end
end

if $PROGRAM_NAME == __FILE__
  raise 'Use --dry-run or --apply' unless ARGV.length == 1 && %w[--dry-run --apply].include?(ARGV.first)

  puts JSON.generate(PWN::SessionCleanup.summary(PWN::SessionCleanup.maintain(dry_run: ARGV.first == '--dry-run')))
end
