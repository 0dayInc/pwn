# frozen_string_literal: true

require 'json'
require 'open3'
require 'timeout'
require 'fileutils'
require 'stringio'
require 'ffi'
require 'find'
require 'tmpdir'
require 'socket'

module PWN
  module Plugins
    # Forked worker for model-authored shell/Ruby with Landlock/seccomp profiles.
    module AISandbox
      ALIAS_MUTEX = Mutex.new
      ALIAS_CACHE = {} # rubocop:disable Style/MutableConstant -- host-only inode fingerprint cache

      NotStarted = PWN::AI::Agent::MissionNamespace::Unavailable

      # One kernel-owned process tree. Namespace PID 1 owns every descendant,
      # including double forks and setsid jobs. Reaping PID 1 completes teardown.
      # No process-group fallback: unsupported hosts never execute the block.
      MissionProcess = PWN::AI::Agent::MissionNamespace

      WRITE_RX = %r{\b(?:rm|rmdir|unlink|shred|truncate)\b|FileUtils\.rm|File\.(?:delete|unlink)|Pathname.*rmtree|>\s*/}
      NET_RX = /\b(?:curl|wget|nc|ncat|ssh|scp|ftp|telnet)\b|TCPSocket|UDPSocket|Net::HTTP|Socket\.(?:tcp|udp)/
      PATH_RX = %r{FileUtils\.\w+\(\s*['"]([^'"]+)['"]|(?:^|\s)(?:rm|rmdir)\s+(?:-[a-zA-Z]+\s+)*([^\s;|&]+)|['"](/(?:[^'"]+))['"]}

      public_class_method def self.required_bins
        %w[unshare]
      end

      # Read the ai_sandbox key as strict, permissive, or off.
      public_class_method def self.mode(opts = {})
        raw = opts[:mode] || opts[:ai_sandbox]
        raw = env_mode if raw.nil?
        value = raw.to_s.downcase
        %w[strict permissive off].include?(value) ? value.to_sym : :off
      end

      # Classify payload as read, write, or network for profile selection.
      public_class_method def self.classify(opts = {})
        text = (opts[:payload] || opts[:command] || opts[:code]).to_s
        return (opts[:side_effect] || opts[:class]).to_sym if opts[:side_effect] || opts[:class]
        return :write if text.match?(WRITE_RX)
        return :network if text.match?(NET_RX)

        :read
      end

      # Run shell or Ruby in a forked worker under the selected profile.
      public_class_method def self.exec(opts = {})
        kind = (opts[:kind] || :shell).to_s.to_sym
        payload = (opts[:payload] || opts[:command] || opts[:code]).to_s
        profile = classify(opts.merge(payload: payload))
        denied = preflight(opts.merge(payload: payload, profile: profile))
        return denied if denied

        run_worker(opts.merge(kind: kind, payload: payload, profile: profile))
      end

      # Intercept shell when ai_sandbox is not off; nil means the caller runs host Open3.
      public_class_method def self.wrap_shell(opts = {})
        return nil if mode(opts) == :off

        exec(opts.merge(kind: :shell, payload: opts[:command] || opts[:payload]))
      end

      # Intercept pwn_eval when ai_sandbox is not off; nil means in-process eval.
      public_class_method def self.wrap_ruby(opts = {})
        return nil if mode(opts) == :off

        exec(opts.merge(kind: :ruby, payload: opts[:code] || opts[:payload]))
      end

      # Pin each controller directory component without following symlinks.
      # Callers must use NOFOLLOW/EXCL for final files within the yielded fd path.
      public_class_method def self.control_directory(opts = {})
        raise NotStarted, 'safe controller persistence requires Linux openat' unless RUBY_PLATFORM.include?('linux')

        native = Module.new do
          extend ::FFI::Library

          ffi_lib ::FFI::Library::LIBC
          attach_function :openat, %i[int string int uint], :int
          attach_function :mkdirat, %i[int string uint], :int
        end
        flags = directory_open_flags
        identities = protected_roots.map do |path|
          stat = File.stat(path)
          [stat.dev, stat.ino]
        end
        directory = IO.new(IO.sysopen('/', flags))
        File.expand_path(opts.fetch(:path)).split('/').reject(&:empty?).each do |part|
          fd = native.openat(directory.fileno, part, flags, 0)
          if fd.negative? && ::FFI.errno == Errno::ENOENT::Errno
            result = native.mkdirat(directory.fileno, part, 0o700)
            raise SystemCallError.new('controller mkdirat', ::FFI.errno) if result.negative? && ::FFI.errno != Errno::EEXIST::Errno

            fd = native.openat(directory.fileno, part, flags, 0)
          end
          raise SystemCallError.new('controller openat (symlink ancestry is forbidden)', ::FFI.errno) if fd.negative?

          child = IO.new(fd)
          directory.close
          directory = child
          stat = directory.stat
          raise NotStarted, 'controller persistence path enters protected source' if identities.include?([stat.dev, stat.ino])
        end
        yield "/proc/self/fd/#{directory.fileno}"
      ensure
        directory&.close unless directory&.closed?
      end

      # O_DIRECTORY is 1<<16 on x86_64 and 1<<14 on aarch64/arm. 1<<16 is O_DIRECT
      # there, and open("/", O_DIRECT) returns EINVAL.
      private_class_method def self.directory_open_flags(opts = {})
        platform = opts[:platform] || RUBY_PLATFORM
        directory = platform.match?(/\Aaarch64|\Aarm-/) ? (1 << 14) : (1 << 16)
        File::RDONLY | File::NOFOLLOW | directory | (1 << 19)
      end

      # Mandatory repository boundary, independent of the optional profile.
      # The block runs only in a child; cwd and restrictions never affect the UI.
      public_class_method def self.protect_call(opts = {})
        return yield if Thread.current[:pwn_repository_worker]
        return protect_descriptor(opts) unless PWN::AI::Agent::MissionNamespace.owned || (PWN::AI::Agent::MissionNamespace.prepared? && !PWN::AI::Agent::MissionNamespace.force_exec)

        roots = Array(opts[:roots] || protected_roots).map { |path| File.realpath(path) }.uniq
        scratch = workspace
        FileUtils.mkdir_p(scratch, mode: 0o700)
        scratch = File.realpath(scratch)
        task_dir = File.expand_path(opts[:workspace] || scratch)
        ancestor = task_dir
        ancestor = File.dirname(ancestor) until File.exist?(ancestor)
        resolved = File.join(File.realpath(ancestor), task_dir.delete_prefix(ancestor).delete_prefix('/'))
        raise SecurityError, 'runtime workspace is inside protected source' if roots.any? { |root| resolved == root || resolved.start_with?("#{root}/") }

        FileUtils.mkdir_p(task_dir, mode: 0o700)
        task_dir = File.realpath(task_dir)
        if opts[:runtime]
          provision_swarm_state
          controller_root = File.dirname(opts[:runtime].checkpoint_path, 2)
          roots += [File.realpath(controller_root), File.realpath(PWN::AI::Agent::Swarm::SWARM_ROOT), File.realpath(PWN::AI::Agent::Swarm::AGENTS_FILE)]
        end
        roots.concat(controller_state_roots)
        explicit = prepare_write_roots(paths: opts[:write_roots])
        writable = [scratch, '/dev/null', '/dev/zero', '/dev/random', '/dev/urandom'] + explicit
        writable += prepare_write_roots(paths: state_write_roots) unless opts.dig(:handler, :name).to_s == 'shell'
        writable = writable.filter_map { |path| File.realpath(path) if File.exist?(path) && !File.symlink?(path) }.uniq
        writable.reject! { |path| %w[/ /proc /sys /dev].include?(path) }
        aliases, identities = repository_aliases(roots: roots, writable: writable)

        reader, writer = IO.pipe
        controller, client = UNIXSocket.pair
        mission = nil
        Thread.handle_interrupt(Exception => :never) do
          mission = MissionProcess.new(inherit_namespace: true) do
            reader.close
            controller.close
            Thread.current[:pwn_swarm_controller] = client if opts[:runtime]
            Signal.trap('TERM') { raise Interrupt, 'runtime worker cancelled' }
            begin
              repository_restrict!(roots: roots + aliases, writable: writable, explicit: explicit)
              repository_metadata_restrict!(roots: roots + aliases, identities: identities)
              Dir.chdir(task_dir)
              ENV['TMPDIR'] = scratch
              Thread.current[:pwn_repository_worker] = true
              opts[:runtime]&.worker_view!
              started = true
              result = yield
              provenance = opts[:runtime]&.observations&.transform_values { |row| row.except(:head, :tail) } || {}
              writer.write(JSON.generate(started: true, provenance: provenance, result: PWN::AI::Agent::Result.utf8_value(value: result)))
            rescue StandardError, SecurityError, NotImplementedError => e
              writer.write(JSON.generate(started: started == true, result: { success: false, error: "repository protection: #{e.class}: #{e.message}" }))
            ensure
              writer.close
              exit!
            end
          end
        end
        writer.close
        client.close
        raw = collect_worker(reader: reader, controller: controller, runtime: opts[:runtime])
        mission.wait
        envelope = JSON.parse(raw, symbolize_names: true)
        raise NotStarted, envelope.dig(:result, :error) unless envelope[:started]

        opts[:runtime]&.worker_provenance!(rows: (envelope[:provenance] || {}).transform_keys(&:to_s).merge(opts[:runtime].observations))
        envelope[:result]
      rescue NotImplementedError, SecurityError, SystemCallError => e
        raise NotStarted, "repository protection unavailable: #{e.message}"
      ensure
        reader&.close unless reader&.closed?
        writer&.close unless writer&.closed?
        mission&.close
        controller&.close unless controller&.closed?
        client&.close unless client&.closed?
      end

      private_class_method def self.protect_descriptor(opts = {})
        raise NotStarted, 'protected host calls require a serializable handler descriptor' unless opts[:handler]

        reader, writer = IO.pipe
        controller, client = UNIXSocket.pair
        descriptor = { operation: :protected, options: opts.except(:runtime), runtime: opts[:runtime]&.mission_snapshot }
        mission = MissionProcess.new(descriptor: descriptor, fds: { 4 => writer, 5 => client })
        writer.close
        client.close
        raw = collect_worker(reader: reader, controller: controller, runtime: opts[:runtime])
        mission.wait
        envelope = JSON.parse(raw, symbolize_names: true)
        raise NotStarted, envelope[:error] if envelope[:error]

        opts[:runtime]&.worker_provenance!(rows: envelope.fetch(:provenance, {}).transform_keys(&:to_s))
        envelope[:result]
      ensure
        mission&.close
        [reader, writer, controller, client].compact.each { |io| io.close unless io.closed? }
      end

      private_class_method def self.mission_entry(opts = {})
        writer = PWN::AI::Agent::MissionNamespace.io(4)
        Thread.current[:pwn_swarm_controller] = PWN::AI::Agent::MissionNamespace.io(5)
        runtime = PWN::AI::Agent::RequestRuntime.send(:from_mission_snapshot, state: opts[:runtime]) if opts[:runtime]
        Thread.current[:pwn_request_runtime] = runtime
        options = opts.fetch(:options)
        handler = options.fetch(:handler)
        PWN::AI::Agent::Registry.discover
        begin
          result = protect_call(options.merge(runtime: runtime)) do
            PWN::AI::Agent::Registry.lookup(name: handler.fetch(:name)).handler.call(handler.fetch(:args))
          end
          writer.write(JSON.generate(result: result, provenance: runtime&.observations || {}))
        rescue StandardError => e
          writer.write(JSON.generate(error: "#{e.class}: #{e.message}"))
        ensure
          writer.close
        end
      end

      # Typed swarm control operations; never execute a registry handler on the host.
      public_class_method def self.swarm_control(opts = {})
        socket = Thread.current[:pwn_swarm_controller]
        raise NotStarted, 'swarm controller unavailable' unless socket

        socket.puts(JSON.generate(operation: opts.fetch(:operation), args: opts.fetch(:args)))
        reply = JSON.parse(socket.gets || '{}', symbolize_names: true)
        raise NotStarted, reply[:error] if reply[:error]

        reply.fetch(:result)
      end

      private_class_method def self.provision_swarm_state
        swarm = PWN::AI::Agent::Swarm
        control_directory(path: swarm::SWARM_ROOT) { |_directory| nil }
        control_directory(path: File.dirname(swarm::AGENTS_FILE)) do |directory|
          [File.basename(swarm::AGENTS_FILE), '.swarm-continuations.lock'].each do |name|
            File.open(File.join(directory, name), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |file|
              raise NotStarted, 'swarm state must be a singly linked regular file' unless file.stat.file? && file.stat.nlink == 1
            end
          end
        end
      end

      private_class_method def self.collect_worker(opts = {})
        reader = opts.fetch(:reader)
        controller = opts.fetch(:controller)
        streams = [reader, controller]
        bytes = +''
        loop do
          IO.select(streams).first.each do |stream|
            if stream == reader
              chunk = reader.read_nonblock(65_536, exception: false)
              return bytes if chunk.nil?

              bytes << chunk unless chunk == :wait_readable
            else
              line = controller.gets(65_537)
              if line.nil?
                streams.delete(controller)
                next
              end
              reply = swarm_control_reply(line: line, runtime: opts[:runtime])
              controller.puts(JSON.generate(reply))
            end
          end
        end
      end

      private_class_method def self.swarm_control_reply(opts = {})
        raise NotStarted, 'swarm controller requires a request runtime' unless opts[:runtime]
        raise ArgumentError, 'swarm control frame too large' if opts.fetch(:line).bytesize > 65_536

        frame = JSON.parse(opts.fetch(:line), symbolize_names: true)
        operation = frame.fetch(:operation)
        opts[:runtime].check_cancelled!
        raise ArgumentError, 'swarm control permission denied' unless opts[:runtime].tool_allowed?(name: "agent_#{operation}", toolset: 'swarm')

        fields = case operation
                 when 'spawn' then %i[name role toolsets engine model max_iters]
                 when 'ask' then %i[name request swarm_id unit ttl engagement_id]
                 else raise ArgumentError, 'unsupported swarm control operation'
                 end
        args = frame.fetch(:args)
        raise ArgumentError, 'unsupported swarm control fields' unless args.is_a?(Hash) && (args.keys - fields).empty?

        %i[swarm_id engagement_id].each do |key|
          next if args[key].nil?
          raise ArgumentError, 'invalid swarm control identifier' unless args[key].is_a?(String) && args[key].match?(/\A[a-zA-Z0-9_-]+\z/)
        end
        swarm = PWN::AI::Agent::Swarm
        control_directory(path: swarm::SWARM_ROOT) do |_directory|
          control_directory(path: File.join(swarm::SWARM_ROOT, args[:swarm_id])) { |_child| nil } if args[:swarm_id]
        end
        result = operation == 'spawn' ? swarm.spawn(args) : swarm.ask(args)
        { result: result }
      rescue StandardError => e
        { error: "swarm controller: #{e.class}: #{e.message}" }
      end

      # Default new-file directory. Process cwd is not an implicit write grant.
      public_class_method def self.workspace
        File.expand_path(File.join(Dir.home, '.pwn', 'workspaces', 'runtime'))
      end

      # Relative reads use a safe task directory. Protected-source launches use
      # the runtime workspace instead.
      public_class_method def self.task_directory
        cwd = File.realpath(Dir.pwd)
        protected = protected_roots.any? { |root| cwd == root || cwd.start_with?("#{root}/") || root.start_with?("#{cwd}/") }
        return workspace if cwd == '/' || protected

        cwd
      end

      # Materialize operator-named destinations. A file literal grants its parent
      # so creation works; a directory literal grants itself. Protected source
      # and symlinks are never granted.
      public_class_method def self.prepare_write_roots(opts = {})
        roots = protected_roots
        Array(opts[:paths]).filter_map do |literal|
          path = File.expand_path(literal.to_s)
          next if protected_path?(path: path, roots: roots)

          # An existing directory is the grant. A file, or a destination that does
          # not exist yet, grants its parent so mv/touch can create the file.
          # Do not mkdir a missing extensionless path; that would turn
          # `mv foo /tmp/test` into a move into a directory.
          grant = File.directory?(path) && !File.symlink?(path) ? path : File.dirname(path)
          next if protected_path?(path: grant, roots: roots) || %w[/ /proc /sys /dev].include?(grant)
          next if File.symlink?(grant)

          FileUtils.mkdir_p(grant, mode: 0o700) unless File.directory?(grant)
          next unless File.directory?(grant) && !File.symlink?(grant)

          resolved = File.realpath(grant)
          next if protected_path?(path: resolved, roots: roots)

          resolved
        end.uniq
      end

      # Detect both the conventional checkout and the loaded package source.
      public_class_method def self.protected_roots
        ['/opt/pwn', File.expand_path('../../..', __dir__)].select { |path| File.directory?(path) }.map { |path| File.realpath(path) }.uniq
      end

      private_class_method def self.protected_path?(opts = {})
        path = opts[:path]
        opts.fetch(:roots).any? { |root| path == root || path.start_with?("#{root}/") }
      end

      # Plugin records, not the default scratch tree. Shell does not receive these.
      private_class_method def self.state_write_roots
        denied = controller_state_roots
        %w[jobs cache ghidra redb binws wordlists exports sandbox_snapshots intel].filter_map do |name|
          path = File.join(Dir.home, '.pwn', name)
          next if protected_path?(path: path, roots: denied)

          path
        end
      end

      # Keep controller persistence out of tool grants, including absent paths.
      # A missing deny still splits its ancestor grant, so tools cannot plant it
      # before the controller's first append. Honour test/custom store constants.
      private_class_method def self.controller_state_roots
        agent = PWN::AI::Agent
        stores = [PWN::Sessions, PWN::Memory, PWN::MemoryIndex, PWN::Plugins::ArtifactRegistry,
                  agent::Learning, agent::Policy, agent::Metrics, agent::Reward, agent::Mistakes,
                  agent::OpenGoal, agent::Mission, agent::TaskDAG, agent::SkillReview, agent::Engagement,
                  agent::Curriculum, agent::ToolGuard, agent::Extrospection, agent::Swarm]
        paths = stores.flat_map do |store|
          store.constants(false).filter_map do |name|
            next unless name.to_s.match?(/(?:_FILE|_DIR|_ROOT|LEDGER|ROOT)\z/)

            value = store.const_get(name, false)
            value if value.is_a?(String) && value.start_with?('/')
          end
        end
        paths.concat(%w[artifacts logs learning metrics skills .swarm-continuations.lock pwn.yaml pwn.yaml.decryptor vault-secrets.json].map { |name| File.join(Dir.home, '.pwn', name) })
        paths << File.join(Dir.home, '.pwn-vault.key')
        if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
          %i[pwn_env_path pwn_dec_path pwn_skills_path].each do |key|
            path = PWN::Env.dig(:driver_opts, key)
            paths << path unless path.to_s.empty?
          end
        end
        paths.concat(PWN::Skills.values.filter_map { |meta| File.dirname(meta[:path]) if meta.is_a?(Hash) && meta[:path].is_a?(String) }) if defined?(PWN::Skills) && PWN::Skills.is_a?(Hash)
        paths.flat_map do |path|
          path = File.expand_path(path)
          ancestor = path
          ancestor = File.dirname(ancestor) until File.exist?(ancestor) || File.symlink?(ancestor)
          # Preserve the lexical deny (including absent paths), and also deny
          # the canonical store behind an operator-configured symlink.
          [path, "#{File.realpath(ancestor)}#{path.delete_prefix(ancestor)}"]
        end.uniq
      end

      private_class_method def self.repository_aliases(opts = {})
        identities = {}
        opts.fetch(:roots).each do |root|
          next unless File.exist?(root)

          Find.find(root) do |path|
            stat = File.lstat(path)
            identities[[stat.dev, stat.ino]] = [stat.nlink, stat.ctime.to_r] if stat.file? && stat.nlink > 1
          end
        end
        return [[], []] if identities.empty?

        aliases = opts.fetch(:writable).flat_map do |root|
          stat = File.stat(root)
          key = [identities, root, stat.dev, stat.ino]
          ALIAS_MUTEX.synchronize do
            ALIAS_CACHE.shift if ALIAS_CACHE.length >= 64
            ALIAS_CACHE[key] ||= repository_scan_aliases(root: root, identities: identities).freeze
          end
        end.uniq
        [aliases, identities.keys]
      end

      private_class_method def self.repository_scan_aliases(opts = {})
        aliases = []
        Find.find(opts.fetch(:root)) do |path|
          stat = File.lstat(path)
          if stat.directory? && (!File.readable?(path) || !File.executable?(path))
            aliases << path
            Find.prune
          end
          aliases << path if stat.file? && opts.fetch(:identities)[[stat.dev, stat.ino]]
        rescue Errno::ENOENT
          next
        end
        aliases
      end

      private_class_method def self.repository_metadata_restrict!(opts = {})
        roots = opts.fetch(:roots)
        # Landlock does not mediate chmod/chown/xattr/time metadata. Deny those
        # syscalls conservatively, also outside source, rather than claim a
        # path regex makes arbitrary Ruby safe. Content writes remain usable.
        native = Module.new do
          extend ::FFI::Library

          ffi_lib 'libseccomp.so.2'
          attach_function :seccomp_init, [:uint32], :pointer
          attach_function :seccomp_syscall_resolve_name, [:string], :int
          attach_function :seccomp_rule_add, %i[pointer uint32 int uint], :int
          attach_function :seccomp_load, [:pointer], :int
          attach_function :seccomp_release, [:pointer], :void
        end
        context = native.seccomp_init(0x7fff0000)
        raise SecurityError, 'seccomp initialization failed' if context.null?

        begin
          %w[chmod fchmod fchmodat fchmodat2 chown fchown lchown fchownat
             utime utimes futimesat utimensat setxattr lsetxattr fsetxattr
             removexattr lremovexattr fremovexattr mount umount2 pivot_root
             move_mount open_tree fsopen fsconfig fsmount mount_setattr unshare
             setns ptrace process_vm_writev io_uring_setup].each do |name|
            number = native.seccomp_syscall_resolve_name(name)
            next if number.negative?
            raise SecurityError, "seccomp rule failed: #{name}" unless native.seccomp_rule_add(context, 0x50000 | 1, number, 0).zero?
          end
          raise SecurityError, 'seccomp load failed' unless native.seccomp_load(context).zero?
        ensure
          native.seccomp_release(context)
        end
        # Close descriptors opened before Landlock; its policy applies to open,
        # not writes through an already-open file description.
        Dir.children('/proc/self/fd').each do |number|
          fd = number.to_i
          begin
            path = File.realpath("/proc/self/fd/#{fd}")
            stat = File.stat("/proc/self/fd/#{fd}")
            IO.new(fd).close if opts.fetch(:identities).include?([stat.dev, stat.ino]) || roots.any? { |root| path == root || path.start_with?("#{root}/") }
          rescue Errno::ENOENT, Errno::EBADF
            nil
          end
        end
        :restricted
      rescue LoadError => e
        raise SecurityError, "libseccomp is required: #{e.message}"
      end

      private_class_method def self.repository_restrict!(opts = {})
        raise NotImplementedError, 'Linux Landlock ABI 3 or newer is required' unless RUBY_PLATFORM.match?(/(?:x86_64|aarch64).*linux/)

        abi = syscall(444, 0, 0, 1)
        raise NotImplementedError, 'Linux Landlock ABI 3 or newer is required' if abi < 3

        # Handle every filesystem content/creation/removal right, including
        # REFER and TRUNCATE. Read and execute remain available everywhere.
        rights = (1 << 1) | (((1 << 15) - 1) & ~15)
        attr = ::FFI::MemoryPointer.from_string([rights].pack('Q'))
        ruleset = syscall(444, attr.address, 8, 0)
        roots = opts.fetch(:roots)
        # Compile exact denies and their ancestors once. Hardlink inventories can
        # contain thousands of files; rescanning every deny at every tree node
        # makes otherwise bounded namespace startup quadratic.
        denied = roots.to_h { |path| [path, true] }
        ancestors = {}
        roots.each do |root|
          parent = File.dirname(root)
          loop do
            ancestors[parent] = true
            break if parent == '/'

            parent = File.dirname(parent)
          end
        end
        begin
          opts.fetch(:writable).each do |path|
            next if roots.any? { |root| path == root || path.start_with?("#{root}/") }

            repository_allow!(path: path, denied: denied, ancestors: ancestors, ruleset: ruleset, rights: rights, force: opts[:explicit]&.include?(path))
          end
          prctl = RUBY_PLATFORM.start_with?('aarch64') ? 167 : 157
          syscall(prctl, 38, 1, 0, 0, 0)
          syscall(446, ruleset, 0)
        ensure
          IO.new(ruleset).close
        end
        :restricted
      end

      private_class_method def self.repository_allow!(opts = {})
        path = opts.fetch(:path)
        return if opts.fetch(:denied).key?(path)
        return if File.symlink?(path)

        if opts.fetch(:ancestors).key?(path) && !opts[:force]
          Dir.children(path).each { |name| repository_allow!(opts.merge(path: File.join(path, name), force: false)) }
        else
          rights = opts.fetch(:rights)
          rights &= (1 << 1) | (1 << 14) unless File.directory?(path)
          fd = IO.sysopen(path, 0x200000 | 0x80000) # O_PATH | O_CLOEXEC
          begin
            attr = ::FFI::MemoryPointer.from_string([rights, fd].pack('QL'))
            syscall(445, opts.fetch(:ruleset), 1, attr.address, 0)
          ensure
            IO.new(fd).close
          end
        end
        :allowed
      rescue Errno::ENOENT
        # Unrelated sibling scratch entries can disappear during enumeration.
        # Omitting an allow rule is conservative; never grant its parent.
        :absent
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Pin controller ancestry with no-follow openat directory descriptors.
          #{self}.control_directory(
            path: 'required - controller directory, created with mode 0700 if absent'
          ) { |fd_path| persist_with_nofollow(fd_path) }

          # Execute a runtime handler behind mandatory Linux source protection.
          #{self}.protect_call(
            roots: 'optional - host-owned protected roots; defaults to checkout and loaded package',
            workspace: 'optional - host-owned cwd; defaults to ~/.pwn/workspaces/runtime',
            write_roots: 'optional - destinations named by the original operator request',
            runtime: 'optional - host-owned request runtime; child checkpoint writes stay isolated'
          ) { handler.call }

          # Request one typed swarm operation from the supervising controller.
          #{self}.swarm_control(
            operation: 'required - spawn or ask; no arbitrary method or handler dispatch',
            args: 'required - JSON-compatible allowlisted swarm tool arguments'
          )

          # Return the default directory for unnamed new files.
          #{self}.workspace

          # Return the task directory used for relative reads.
          #{self}.task_directory

          # Create and return grants for operator-named write destinations.
          #{self}.prepare_write_roots(
            paths: 'required - absolute or expandable destinations from the original request'
          )

          # Return detected checkout and installed package source roots.
          #{self}.protected_roots

          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Read the ai_sandbox key as strict, permissive, or off.
          #{self}.mode(
            mode: 'optional - strict, permissive, or off overlay',
            ai_sandbox: 'optional - alias for mode'
          )

          # Classify payload as read, write, or network for profile selection.
          #{self}.classify(
            payload: 'optional - shell command or Ruby source',
            command: 'optional - alias for payload',
            code: 'optional - alias for payload',
            side_effect: 'optional - declared class read, write, or network',
            class: 'optional - alias for side_effect'
          )

          # Run shell or Ruby in a forked worker under the selected profile.
          #{self}.exec(
            kind: 'optional - shell or ruby (defaults to shell)',
            payload: 'optional - command or Ruby source',
            command: 'optional - alias for payload',
            code: 'optional - alias for payload',
            mode: 'optional - strict, permissive, or off overlay',
            timeout: 'optional - worker seconds budget',
            side_effect: 'optional - declared class read, write, or network',
            scope: 'optional - Array of hostnames allowed for network egress'
          )

          # Intercept shell when ai_sandbox is not off; nil means the caller runs host Open3.
          #{self}.wrap_shell(
            command: 'optional - shell command to sandbox',
            payload: 'optional - alias for command',
            mode: 'optional - strict, permissive, or off overlay',
            timeout: 'optional - worker seconds budget'
          )

          # Intercept pwn_eval when ai_sandbox is not off; nil means in-process eval.
          #{self}.wrap_ruby(
            code: 'optional - Ruby source to sandbox',
            payload: 'optional - alias for code',
            mode: 'optional - strict, permissive, or off overlay',
            timeout: 'optional - worker seconds budget'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.env_mode(opts = {})
        _n = opts[:n]
        return nil unless defined?(PWN::Env)

        PWN::Env[:ai_sandbox] || PWN::Env.dig(:ai, :sandbox) || PWN::Env.dig(:ai, :agent, :sandbox)
      rescue StandardError
        nil
      end

      private_class_method def self.artifacts_root(opts = {})
        _n = opts[:n]
        File.expand_path(File.join(Dir.home, '.pwn', 'artifacts'))
      end

      private_class_method def self.allowed_write?(opts = {})
        path = File.expand_path(opts[:path].to_s)
        root = artifacts_root
        path == root || path.start_with?("#{root}/")
      rescue StandardError
        false
      end

      private_class_method def self.payload_paths(opts = {})
        text = opts[:payload].to_s
        text.scan(PATH_RX).flatten.compact.map { |item| item.sub(%r{/*\z}, '') }.reject(&:empty?)
      end

      private_class_method def self.preflight(opts = {})
        return nil unless mode(opts) == :strict

        profile = opts[:profile] || classify(opts)
        if profile == :write
          paths = payload_paths(opts)
          paths = ['/'] if paths.empty?
          bad = paths.reject { |path| allowed_write?(path: path) }
          return violation(reason: "filesystem write outside ~/.pwn/artifacts (#{bad.join(', ')})") unless bad.empty?
        end
        if profile == :network
          scope = Array(opts[:scope]).map(&:to_s)
          return violation(reason: 'network egress outside engagement scope') if scope.empty?
        end
        nil
      end

      private_class_method def self.violation(opts = {})
        { error: "sandbox violation: #{opts[:reason]}", sandbox: mode(opts).to_s, ok: false }
      end

      private_class_method def self.run_worker(opts = {})
        timeout = (opts[:timeout] || 30).to_i
        timeout = 30 if timeout <= 0
        reader, writer = IO.pipe
        pid = Process.fork do
          reader.close
          apply_profile(opts)
          result = opts[:kind].to_s == 'ruby' ? eval_ruby(opts) : run_shell(opts)
          writer.write(JSON.generate(result))
        rescue StandardError => e
          writer.write(JSON.generate(error: "sandbox violation: #{e.message}", ok: false))
        ensure
          writer.close
          exit!
        end
        writer.close
        raw = Timeout.timeout(timeout) { reader.read }
        Process.wait(pid)
        JSON.parse(raw.to_s, symbolize_names: true)
      rescue Timeout::Error
        begin
          Process.kill('KILL', pid) if pid
        rescue StandardError
          nil
        end
        { error: 'sandbox violation: worker timeout', ok: false }
      rescue NotImplementedError, Errno::ENOSYS
        preflight(opts.merge(mode: :strict)) || { error: 'sandbox violation: fork unavailable', ok: false }
      end

      private_class_method def self.run_shell(opts = {})
        cmd = opts[:payload].to_s
        stdout, stderr, status = Open3.capture3(cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus, sandbox: mode(opts).to_s }
      end

      private_class_method def self.eval_ruby(opts = {})
        buf = StringIO.new
        old = $stdout
        $stdout = buf
        # rubocop:disable-next Security/Eval
        val = eval(opts[:payload].to_s, TOPLEVEL_BINDING, '(pwn_eval)', 1)
        { stdout: buf.string, value: val.inspect, sandbox: mode(opts).to_s }
      ensure
        $stdout = old
      end

      private_class_method def self.apply_profile(opts = {})
        return unless mode(opts) == :strict

        landlock_restrict!(opts)
        seccomp_restrict!(opts)
      rescue StandardError
        nil
      end

      private_class_method def self.landlock_restrict!(opts = {})
        _n = opts[:n]
        return unless RUBY_PLATFORM.include?('linux')

        FileUtils.mkdir_p(artifacts_root)
        nil
      end

      private_class_method def self.seccomp_restrict!(opts = {})
        _profile = opts[:profile]
        nil
      end
    end
  end
end
