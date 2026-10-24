# frozen_string_literal: true

# PWN managed default: session_cleanup v9
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
    VERSION = 9

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
      File.open(temporary, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
        file.write(bytes)
        file.flush
        file.fsync
      end
      File.rename(temporary, path)
      File.open(File.dirname(path), File::RDONLY, &:fsync)
    ensure
      File.unlink(temporary) if temporary && File.exist?(temporary)
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

    def self.with_dependency_lock(id)
      rows = invalid_dependencies(id)
      raise 'Unresolved dependency remediation' unless rows.empty? || remediable?(id)

      # Lock even absent stores: a concurrent writer can introduce the first
      # reference between the final index and unlink. These inodes are permanent.
      root = File.join(Dir.home, '.pwn')
      paths = %w[.learning-write.lock memory.json.write.lock mistakes.json.write.lock].map { |name| File.join(root, name) }.sort
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

    def self.maintain(dry_run: false, current_session_id: nil, proc_root: '/proc')
      with_maintenance_lock(dry_run: dry_run) do
        maintenance_transaction(dry_run: dry_run, current_session_id: current_session_id, proc_root: proc_root)
      end
    end

    def self.maintenance_transaction(dry_run:, current_session_id:, proc_root:)
      preflight = sweep(dry_run: true, current_session_id: current_session_id, proc_root: proc_root)
      blocked = !preflight[:legacy_owners].empty? || Array(preflight[:unresolved_store_remediation]).any?
      unless dry_run || blocked
        # Private metadata-only preflight survives an interrupted migration.
        backup(File.join(PWN::Sessions.sessions_dir, 'inventory.jsonl'), {}, preflight)
        ledger = File.join(preflight[:archive_dir], 'maintenance.json')
        publish(ledger, JSON.pretty_generate(state: 'prepared', inventory: preflight))
        blocked = !legacy_owners(proc_root).empty?
      end
      migration = PWN::AI::Agent::Learning.migrate_evidence(dry_run: dry_run || blocked)
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
        evidence_migration: result[:evidence_migration], archive_dir: result[:archive_dir],
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
      unless references[:errors].empty?
        result[:skipped][:unknown_pins] = 1
        result[:dependency_errors] = references[:errors]
        result[:unresolved_store_remediation] = references[:errors]
      end
      result[:diagnostics] = references.fetch(:diagnostics, [])
      dependencies = references[:dependencies]
      pins = dependencies.keys
      Dir.glob(File.join(root, '*.jsonl')).each do |path|
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
