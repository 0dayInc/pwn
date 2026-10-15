# frozen_string_literal: true

# PWN managed default: session_cleanup v6
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
    VERSION = 6

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
      [path, path.sub(/\.jsonl\z/, '.meta.json')].to_h do |file|
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

        source = File.join(File.dirname(path), name)
        bytes = File.binread(source)
        raise 'Changed before backup' unless Digest::SHA256.hexdigest(bytes) == record[:sha256]

        target = File.join(result[:archive_dir], name)
        publish(target, bytes)
        raise 'Backup verification failed' unless Digest::SHA256.file(target).hexdigest == record[:sha256]
      end
      publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result))
    end

    def self.run(dry_run: true, current_session_id: nil, proc_root: '/proc', approved_candidates: nil)
      raise 'Session cleanup requires the updated Sessions activity API; load the updated source or deploy it before running this helper' unless PWN::Sessions.respond_to?(:activate)

      root = PWN::Sessions.sessions_dir
      raise 'Refusing symlinked session directory' if File.symlink?(root)

      current = current_session_id || (PWN::Env.dig(:ai, :session_id) if defined?(PWN::Env))
      legacy = legacy_owners(proc_root)
      result = { version: VERSION, dry_run: dry_run, scanned: 0, unnamed: 0, candidate_ids: [], deleted_ids: [], records: [], skipped: Hash.new(0), legacy_owners: legacy }
      unless pins_known?
        result[:skipped][:unknown_pins] = 1
        result[:dependency_errors] = PWN::Sessions.dependency_index[:errors]
        return result
      end
      dependencies = PWN::Sessions.dependency_index[:dependencies]
      pins = referenced_session_ids
      Dir.glob(File.join(root, '*.jsonl')).each do |path|
        id = File.basename(path, '.jsonl')
        result[:scanned] += 1
        state = classify(path, id)
        record = PWN::Sessions.title_status(session_id: id).merge(id: id, classification: state, dependencies: dependencies.fetch(id, []))
        result[:records] << record
        unless state == :unnamed
          result[:skipped][state] += 1
          next
        end
        expected = snapshot(path)
        record[:files] = expected
        if approved_candidates && approved_candidates[id] != expected
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
        lock_path = File.join(root, ".#{id}.cleanup.lock")
        raise 'Refusing symlinked cleanup lock' if File.symlink?(lock_path)

        File.open(lock_path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
          unless lock.flock(File::LOCK_EX | File::LOCK_NB)
            result[:skipped][:locked] += 1
            record[:skip] = :locked
            next
          end
          File.open(path, File::RDONLY | File::NOFOLLOW) do |transcript|
            unless transcript.flock(File::LOCK_EX | File::LOCK_NB)
              result[:skipped][:locked] += 1
              record[:skip] = :locked
              next
            end
            # Activation and deletion serialize on the same per-session inode.
            # Legacy ownership uncertainty still requires operator migration.
            unless File.identical?(transcript, path) && classify(path, id) == :unnamed && snapshot(path) == expected && legacy_owners(proc_root).empty? && pins_known? && !referenced_session_ids.include?(id)
              result[:skipped][:changed] += 1
              record[:skip] = :changed
              next
            end
            backup(path, expected, result)
            unless snapshot(path) == expected && classify(path, id) == :unnamed && legacy_owners(proc_root).empty? && pins_known? && !referenced_session_ids.include?(id)
              result[:skipped][:changed] += 1
              record[:skip] = :changed
              next
            end
            # Only verified, archived, unreferenced unsummarized sessions;
            # current and all known reference pins checked above.
            # The normal delete API's age pin is deliberately bypassed here.
            PWN::Sessions.delete(session_id: id, current_session_id: current, force: true, cleanup_lock: lock)
            raise 'Deletion did not remove both session records' if File.exist?(path) || File.exist?(path.sub(/\.jsonl\z/, '.meta.json'))

            result[:deleted_ids] << id
            record[:deleted] = true
            publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result))
          end
        end
      rescue StandardError => e
        result[:skipped][:error] += 1
        record[:error] = e.class.name if record
      end
      publish(File.join(result[:archive_dir], 'ledger.json'), JSON.pretty_generate(result)) if result[:archive_dir]
      result
    end
  end
end

if $PROGRAM_NAME == __FILE__
  raise 'Use --dry-run or --apply' unless ARGV.length == 1 && %w[--dry-run --apply].include?(ARGV.first)

  puts JSON.generate(PWN::SessionCleanup.run(dry_run: ARGV.first == '--dry-run'))
end
