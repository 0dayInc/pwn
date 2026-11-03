# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'digest'
require 'securerandom'
require 'find'

module PWN
  # All first-party recovery copies share one serialized seven-generation store.
  # Evidence artifacts are not recovery copies and must not enter this store.
  module Backups
    LIMIT = 7
    GENERATION = /\A\d{8}_\d{6}_[a-f0-9]{8}\z/
    # Published Migrate.backup! names from before .generation.json. Not an unknown folder.
    LEGACY_SNAPSHOT = /\A\d{8}_\d{6}\z/
    # Unpublished housekeeping-era copy. Rename was the publish step, so this is not a restore name.
    PARTIAL_SNAPSHOT = /\A\.partial-\d{8}_\d{6}(?:_[a-f0-9]{8})?\z/

    # Supported Method Parameters::
    # PWN::Backups.active?
    public_class_method def self.active?
      owner = Thread.current[:pwn_backup_transaction]
      !owner.nil? && owner[:pid] == Process.pid && owner[:thread] == Thread.current
    end

    # Supported Method Parameters::
    # PWN::Backups.transaction(root: nil) { ... }
    public_class_method def self.transaction(opts = {})
      owner = Thread.current[:pwn_backup_transaction]
      override = Thread.current[:pwn_backup_root]
      real_home = Thread.current[:pwn_backup_real_home]
      override = nil if real_home && Dir.home != real_home
      root = File.expand_path(opts[:root] || (owner[:root] if active?) || override || File.join(Dir.home, '.pwn', 'backup'))
      return yield if owner && owner[:pid] == Process.pid && owner[:thread] == Thread.current && owner[:root] == root
      raise IOError, 'Nested backup roots are not supported' if active?

      learning = PWN::AI::Agent::Learning.send(:learning_lock)
      safe_directory(path: root)
      File.open(File.join(root, '.retention.lock'), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        raise IOError, 'Unsafe backup lock' unless lock.stat.uid == Process.uid && lock.stat.nlink == 1

        lock.flock(File::LOCK_EX)
        context = { pid: Process.pid, thread: Thread.current, root: root }
        Thread.current[:pwn_backup_transaction] = context
        begin
          result = yield
          failed = result.is_a?(Hash) && (result[:error] || result[:ok] == false || result[:promoted] == false || result[:incomplete] || %w[prepared interrupted blocked].include?(result[:state].to_s))
          write_state(context: context, state: 'complete') if context[:directory] && !failed
          result
        ensure
          # Exceptions leave a prepared recovery generation, never silently expire it.
          Thread.current[:pwn_backup_transaction] = owner
        end
      end
    ensure
      PWN::AI::Agent::Learning.send(:learning_unlock, lock: learning) if learning
    end

    # Supported Method Parameters::
    # PWN::Backups.directory(label: 'maintenance')
    # Caller must hold transaction through the final source mutation and ledger.
    public_class_method def self.directory(opts = {})
      label = opts[:label].to_s
      raise ArgumentError, 'Invalid backup label' unless label.match?(/\A[a-zA-Z0-9_-]+\z/)

      context = Thread.current[:pwn_backup_transaction]
      raise IOError, 'Backup transaction required' unless context && context[:pid] == Process.pid && context[:thread] == Thread.current

      unless context[:directory]
        root = context[:root]
        names = Dir.children(root).select { |name| File.directory?(File.join(root, name)) || File.symlink?(File.join(root, name)) }.sort
        pins = names.length >= LIMIT ? reference_pins(root: root) : []
        raise IOError, 'Pinned backup missing' unless (pins - names).empty?

        candidates = names.select { |name| expirable_name?(name: name, root: root, pins: pins) }
        count = [names.length - LIMIT + 1, 0].max
        raise IOError, 'Backup capacity occupied by legacy, pinned or interrupted generations' if candidates.length < count

        candidates.sort_by { |name| [File.mtime(File.join(root, name)).to_r, name] }.first(count).each do |name|
          FileUtils.remove_entry_secure(File.join(root, name))
        end
        context[:directory] = File.join(root, "#{Time.now.utc.strftime('%Y%m%d_%H%M%S')}_#{SecureRandom.hex(4)}")
        Dir.mkdir(context[:directory], 0o700)
        write_state(context: context, state: 'prepared')
      end
      path = File.join(context[:directory], "#{label}-#{SecureRandom.hex(8)}")
      Dir.mkdir(path, 0o700)
      path
    end

    # Supported Method Parameters::
    # PWN::Backups.capture(path: '/path/to/source', label: 'learning')
    public_class_method def self.capture(opts = {})
      source = File.expand_path(opts[:path])
      label = opts[:label] || 'snapshot'
      transaction do
        Thread.current[:pwn_backup_transaction][:pinned] = true if opts[:pin]
        raise IOError, 'Unsafe backup source' unless File.file?(source) && File.realpath(source) == source && File.stat(source).uid == Process.uid

        directory = self.directory(label: label)
        target = File.join(directory, File.basename(source))
        before = Digest::SHA256.file(source).hexdigest
        File.open(source, File::RDONLY | File::NOFOLLOW) do |input|
          File.open(target, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |output|
            IO.copy_stream(input, output)
            output.flush
            output.fsync
          end
        end
        raise IOError, 'Backup source changed or copy failed' unless Digest::SHA256.file(source).hexdigest == before && Digest::SHA256.file(target).hexdigest == before

        File.open(directory, File::RDONLY, &:fsync)
        target
      end
    end

    # Supported Method Parameters::
    # PWN::Backups.configure(root: nil)
    public_class_method def self.configure(opts = {})
      root = opts[:root] || File.join(Dir.home, '.pwn', 'backup')
      transaction(root: root) do
        path = File.join(root, '.retention-policy.json')
        raise IOError, 'Unsafe retention policy' if File.symlink?(path)

        policy = File.file?(path) ? JSON.parse(File.binread(path)) : { 'version' => 1, 'pins' => [] }
        raise IOError, 'Invalid retention policy' unless policy['version'] == 1 && policy['pins'].is_a?(Array)

        updated = policy.merge('keep' => LIMIT, 'expire_history' => true, 'scope' => 'global')
        next updated if updated == policy

        temporary = "#{path}.#{SecureRandom.hex(8)}"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
          file.write(JSON.generate(updated))
          file.flush
          file.fsync
        end
        File.rename(temporary, path)
        File.open(root, File::RDONLY, &:fsync)
        updated
      end
    end

    # Supported Method Parameters::
    # PWN::Backups.reconcile(generation: 'name', expected_sha256: 'digest', confirmed: true)
    public_class_method def self.reconcile(opts = {})
      generation = opts[:generation].to_s
      raise ArgumentError, 'Exact generation and explicit recovery confirmation required' unless generation.match?(GENERATION) && opts[:confirmed] == true

      transaction do
        root = Thread.current[:pwn_backup_transaction][:root]
        directory = File.join(root, generation)
        raise IOError, 'Recovery generation missing' unless File.directory?(directory)

        safe_directory(path: directory)
        path = File.join(directory, '.generation.json')
        raise IOError, 'Recovery manifest changed' unless !File.symlink?(path) && Digest::SHA256.file(path).hexdigest == opts[:expected_sha256]

        record = JSON.parse(File.read(path))
        raise IOError, 'Unknown recovery manifest' unless record['version'] == 1 && %w[prepared complete].include?(record['state'])

        write_state(context: { root: root, directory: directory, pinned: opts.fetch(:pinned, true) }, state: 'complete')
        { generation: generation, state: 'complete', pinned: opts.fetch(:pinned, true) }
      end
    end

    # Supported Method Parameters::
    # PWN::Backups.relocate_legacy(paths: [], dry_run: true, writers_stopped: false)
    public_class_method def self.relocate_legacy(opts = {})
      paths = Array(opts[:paths]).map { |path| File.expand_path(path) }.uniq
      dry_run = opts.fetch(:dry_run, true)
      raise ArgumentError, 'Stop all legacy writers before relocation' unless dry_run || opts[:writers_stopped] == true

      home = Dir.home
      root = File.join(home, '.pwn')
      paths.each do |path|
        relative = path.delete_prefix("#{root}/")
        recognized = relative.match?(%r{\A(?:learning\.jsonl\.bak[^/]*|preferences\.jsonl\.bak[^/]*|skills/.+/SKILL\.md\.[a-f0-9]{64}\.bak|policy\.json\.rollback-[a-f0-9]{64}\.json|learning/migrations/[a-f0-9]{64}\.backup\.jsonl|session_cleanup_archive/[^/]+|maintenance/(?:retirements|quarantine)/[^/]+)\z})
        recognized ||= path == File.join(home, '.config', 'terminator', 'config.pwnbak')
        raise ArgumentError, 'Unrecognized legacy recovery path' unless recognized
        raise IOError, 'Unsafe legacy recovery path' unless File.realpath(path) == path && File.stat(path).uid == Process.uid
      end
      raise ArgumentError, 'Overlapping legacy sources' if paths.any? { |path| paths.any? { |other| path != other && path.start_with?("#{other}/") } }

      return { planned: paths, moved: [] } if dry_run

      transaction do
        legacy_unreferenced(paths: paths, root: root)
        mappings = paths.to_h do |path|
          target = File.join(directory(label: 'legacy'), File.basename(path))
          before = legacy_inventory(path: path)
          FileUtils.cp_r(path, target, preserve: true)
          raise IOError, 'Legacy recovery changed during copy' unless before == legacy_inventory(path: path) && before == legacy_inventory(path: target)

          [path, { target: target, inventory: before }]
        end
        legacy_unreferenced(paths: paths, root: root)
        mappings.each do |path, row|
          raise IOError, 'Legacy recovery changed before relocation' unless row[:inventory] == legacy_inventory(path: path)
        end
        ledger = File.join(Thread.current[:pwn_backup_transaction][:directory], '.relocation.json')
        File.open(ledger, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
          file.write(JSON.generate(version: 1, mappings: mappings))
          file.flush
          file.fsync
        end
        mappings.each_key { |path| FileUtils.remove_entry_secure(path) }
        { moved: mappings.transform_values { |row| row[:target] }, ledger: ledger }
      end
    end

    private_class_method def self.legacy_inventory(opts = {})
      path = opts[:path]
      rows = {}
      Find.find(path) do |file|
        stat = File.lstat(file)
        raise IOError, 'Unsafe legacy recovery entry' unless (stat.file? || stat.directory?) && stat.uid == Process.uid

        rows[file.delete_prefix(path)] = [stat.ftype, stat.mode, stat.file? ? Digest::SHA256.file(file).hexdigest : nil]
        File.open(file, File::RDONLY, &:fsync)
      end
      rows
    end

    private_class_method def self.legacy_unreferenced(opts = {})
      paths = opts[:paths]
      root = opts[:root]
      return unless File.directory?(root)

      Find.find(root) do |file|
        Find.prune if file == File.join(root, 'backup') || paths.include?(file)
        raise IOError, 'Unsafe legacy reference scope' if File.symlink?(file)
        next unless File.file?(file) && file.match?(/\.jsonl?\z/)

        body = File.binread(file)
        raise IOError, 'Legacy recovery is referenced; preserve original paths' if paths.any? { |path| body.include?(path) || body.include?(path.delete_prefix("#{root}/")) }
      end
    end

    private_class_method def self.reference_pins(opts = {})
      root = opts[:root]
      policy = File.join(root, '.retention-policy.json')
      raise IOError, 'Unsafe retention policy' if File.symlink?(policy)

      pins = File.file?(policy) ? JSON.parse(File.binread(policy)).fetch('pins') : []
      raise IOError, 'Invalid backup pins' unless pins.is_a?(Array) && pins.all? { |name| name.is_a?(String) && name.match?(/\A\d{8}_\d{6}(?:_[a-f0-9]{8})?\z/) }

      pins = pins.dup
      state_root = File.dirname(root)
      names = %w[learning learning.jsonl memory.json mistakes.json policy.json policy_traj.jsonl preferences.jsonl engagements artifacts sessions swarm jobs runs missions open_goals open_goal.json curriculum finetune extrospection skill_review.jsonl maintenance]
      names.each do |name|
        path = File.join(state_root, name)
        next unless File.exist?(path) || File.symlink?(path)

        Find.find(path) do |file|
          stat = File.lstat(file)
          raise IOError, 'Unsafe backup reference entry' unless (stat.file? || stat.directory?) && stat.uid == Process.uid
          next unless stat.file? && file.match?(/\.jsonl?\z/)

          admission = Thread.current[:pwn_maintenance_admission]
          raise IOError, 'Backup reference budget exhausted' if admission && !admission.call(stat.size + 1)

          values = file.end_with?('.jsonl') ? File.foreach(file).reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) } : [JSON.parse(File.binread(file))]
          values.select! { |value| value.is_a?(Hash) && (%w[prepared interrupted].include?(value['state']) || value['pinned'] == true) } if name == 'maintenance'
          until values.empty?
            value = values.pop
            case value
            when Hash then values.concat(value.values)
            when Array then values.concat(value)
            when String
              match = value.match(%r{\A(?:#{Regexp.escape(root)}/|backup/)(\d{8}_\d{6}(?:_[a-f0-9]{8})?)(?:/|\z)})
              pins << match[1] if match
            end
          end
        end
      end
      pins.uniq
    rescue JSON::ParserError, KeyError => e
      raise IOError, "Unreadable backup references: #{e.class}"
    end

    # Unreferenced complete generations, published pre-generation snapshots, and
    # unpublished partials may be expired. Policy pins, evidence references,
    # interrupted generations, and unknown folder names may not.
    private_class_method def self.expirable_name?(opts = {})
      name = opts[:name].to_s
      root = opts[:root]
      return false if opts[:pins].include?(name)

      path = File.join(root, name)
      return false unless owned_directory?(path: path)
      return true if name.match?(PARTIAL_SNAPSHOT)
      return false unless name.match?(GENERATION) || name.match?(LEGACY_SNAPSHOT)

      state = File.join(path, '.generation.json')
      return true unless File.exist?(state) || File.symlink?(state)
      return false unless File.file?(state) && !File.symlink?(state)

      record = JSON.parse(File.binread(state))
      record.is_a?(Hash) && record['version'] == 1 && record['state'] == 'complete'
    rescue JSON::ParserError
      false
    end

    private_class_method def self.owned_directory?(opts = {})
      path = opts[:path]
      ancestor = path
      loop do
        return false if File.symlink?(ancestor)
        break if File.dirname(ancestor) == ancestor

        ancestor = File.dirname(ancestor)
      end
      stat = File.stat(path)
      stat.directory? && stat.uid == Process.uid
    rescue SystemCallError
      false
    end

    private_class_method def self.safe_directory(opts = {})
      path = opts[:path]
      ancestor = path
      loop do
        raise IOError, 'Symlinked backup ancestor' if File.symlink?(ancestor)
        break if File.dirname(ancestor) == ancestor

        ancestor = File.dirname(ancestor)
      end
      FileUtils.mkdir_p(path, mode: 0o700)
      stat = File.stat(path)
      if stat.uid == Process.uid && !stat.mode.nobits?(0o077)
        File.chmod(0o700, path)
        stat = File.stat(path)
      end
      raise IOError, 'Unsafe backup directory' unless stat.uid == Process.uid && stat.mode.nobits?(0o077)

      path
    end

    private_class_method def self.write_state(opts = {})
      context = opts[:context]
      path = File.join(context[:directory], '.generation.json')
      temporary = "#{path}.tmp"
      File.open(temporary, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |file|
        file.write(JSON.generate(version: 1, state: opts[:state], pinned: context[:pinned] == true))
        file.flush
        file.fsync
      end
      File.rename(temporary, path)
      File.open(context[:directory], File::RDONLY, &:fsync)
      File.open(context[:root], File::RDONLY, &:fsync)
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>
    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module
    public_class_method def self.help
      puts "
        # Hold the shared lock through backup and source mutation.
        #{self}.transaction(root: 'optional - backup root; defaults to Thread.current[:pwn_backup_root] or ~/.pwn/backup') { ... }
        # Allocate a producer directory inside the current generation.
        #{self}.directory(label: 'required - producer label')
        # Copy and hash-verify an owned regular file.
        #{self}.capture(path: 'required - source path', label: 'optional - producer label', pin: 'optional - retain until explicitly reconciled')
        # Install the global seven-folder policy without expiring existing data.
        #{self}.configure(root: 'optional - backup root; defaults ~/.pwn/backup')
        # Acknowledge completed store-specific recovery; this does not restore data.
        #{self}.reconcile(generation: 'required - exact generation name', expected_sha256: 'required - inspected generation manifest digest', confirmed: 'required - explicit true after store recovery', pinned: 'optional - retain by default; false permits ordinary retention')
        # Explicitly relocate recognized unreferenced legacy recovery copies.
        #{self}.relocate_legacy(paths: 'required - exact legacy paths', dry_run: 'optional - preview only by default', writers_stopped: 'optional - must be true to apply')
        # Check whether this thread owns the backup transaction.
        #{self}.active?
        # Show module authors.
        #{self}.authors
      "
    end
  end
end
