# frozen_string_literal: true

require 'socket'
require 'fiddle'
require 'json'
require 'date'
require 'rbconfig'
require 'timeout'

# Load root autoloads before opening nested namespaces on direct require.
require 'pwn'

module PWN
  module AI
    module Agent
      # Exec-based user namespace bootstrap; the terminal never enters a namespace.
      # Only typed descriptors cross the private socket. Ruby closures are permitted
      # below an existing owner, where fork does not need a new user namespace.
      class MissionNamespace # rubocop:disable Metrics/ClassLength -- one exec handshake and process ownership protocol
        class Unavailable < StandardError; end
        CONTEXT_KEYS = %i[pwn_swarm_engine pwn_swarm_model pwn_swarm_id pwn_swarm_depth pwn_solve_workspace pwn_solve_tools
                          pwn_session_id pwn_artifact_contract pwn_active_steering_request pwn_turn_finalizer_depth
                          pwn_reflect_depth pwn_request_intent pwn_loop_budget_s pwn_loop_mutations pwn_loop_tokens].freeze
        attr_reader :status

        @fork_lock = Mutex.new
        @control_writers = ObjectSpace::WeakMap.new

        class << self
          attr_accessor :owned, :bootstrap_requires, :force_exec

          # Register the parent endpoint atomically with respect to all mission
          # forks, including sibling missions started by another console thread.
          def control_socket_pair
            @fork_lock.synchronize do
              UNIXSocket.pair.tap { |_reader, writer| @control_writers[writer] = true }
            end
          end

          def fork_mission
            @fork_lock.synchronize do
              writers = @control_writers.keys # Pin live endpoints across fork, not for the console's lifetime.
              fork do
                @fork_lock = Mutex.new # Nested missions must not use the parent's held lock.
                writers.each(&:close) # Close the copies, never shutdown the shared socket.
                yield
              end
            end
          end

          def prepared?
            rows = File.readlines('/proc/self/uid_map').map { |line| line.split.map(&:to_i) }
            count = rows.length == 1 ? rows.first.last : nil
            # The initial host map is the full 32-bit range. Any smaller single
            # line is a user namespace, including a root test bootstrap that must
            # still include a non-root account.
            count.is_a?(Integer) && count.positive? && count < 4_294_967_295
          rescue SystemCallError
            false
          end

          def io(number)
            stream = Thread.current[:pwn_mission_fds]&.fetch(number, nil) || IO.for_fd(number)
            stream.close_on_exec = true if number > 2
            stream
          end

          def native(name, arguments)
            Fiddle::Function.new(Fiddle::Handle::DEFAULT[name], arguments, Fiddle::TYPE_INT)
          end

          def checked(result, operation)
            raise Unavailable, "#{operation}: #{SystemCallError.new(operation, Fiddle.last_error).message}; install util-linux unshare and enable Linux user/PID namespaces and pidfds" if result.negative?

            result
          end

          # Tagged JSON preserves Symbol hash keys and values without deserializing
          # executable Ruby objects or placing credentials in argv or temporary files.
          def encode(value, depth = 0)
            raise ArgumentError, 'mission snapshot is too deep or cyclic' if depth > 30

            case value
            when Hash then ['hash', value.map { |key, item| [encode(key, depth + 1), encode(item, depth + 1)] }]
            when Array then ['array', value.map { |item| encode(item, depth + 1) }]
            when Time then ['time', value.to_i, value.nsec, value.utc_offset, value.utc?]
            when DateTime then ['datetime', value.iso8601(9)]
            when Date then ['date', value.iso8601]
            when Symbol then ['symbol', value.to_s]
            when String then ['string', [value.b].pack('m0'), value.encoding.name]
            when NilClass, TrueClass, FalseClass, Numeric then ['scalar', value]
            else raise ArgumentError, "mission snapshot cannot transfer #{value.class}; use a serializable descriptor"
            end
          end

          def decode(value)
            type, body, encoding = value
            case type
            when 'hash' then body.to_h { |key, item| [decode(key), decode(item)] }
            when 'array' then body.map { |item| decode(item) }
            when 'time' then value[4] ? Time.at(body, encoding, :nanosecond).utc : Time.at(body, encoding, :nanosecond).getlocal(value[3])
            when 'datetime' then DateTime.iso8601(body)
            when 'date' then Date.iso8601(body)
            when 'symbol' then body.to_sym
            when 'string' then body.unpack1('m0').force_encoding(encoding)
            when 'scalar' then body
            else raise ArgumentError, 'invalid mission snapshot'
            end
          end

          def supervise(pid_namespace: true)
            channel = UNIXSocket.for_fd(3)
            snapshot = decode(JSON.parse(channel.gets))
            checked(native('unshare', [Fiddle::TYPE_INT]).call(0x20000000), 'unshare PID namespace') if pid_namespace
            reader, writer = IO.pipe
            armed, arm = IO.pipe
            init = fork_mission do
              armed.close
              checked(native('prctl', [Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG]).call(1, Signal.list.fetch('KILL'), 0, 0, 0), 'PR_SET_PDEATHSIG')
              arm.write('1')
              arm.close
              channel.close
              writer.close
              exit! unless reader.read(1) == '1'

              reader.close
              self.owned = true
              self.bootstrap_requires = snapshot.fetch(:requires, [])
              PWN::Env.replace(decode(encode(snapshot.fetch(:env))))
              bootstrap_requires.each { |path| require path }
              PWN::Env.replace(snapshot.fetch(:env))
              PWN.const_set(:Skills, snapshot[:skills]) if snapshot[:skills] && !PWN.const_defined?(:Skills)
              snapshot.fetch(:locals).each { |key, value| Thread.current[key] = value }
              begin
                Thread.handle_interrupt(Exception => :immediate) { execute(snapshot.fetch(:descriptor)) }
                completed = true
              ensure
                exit!(completed ? 0 : 1)
              end
            end
            arm.close
            raise Unavailable, 'namespace init exited before arming parent-death protection' unless armed.read(1) == '1'

            armed.close
            reader.close
            fd = IO.new(checked(native('pidfd_open', [Fiddle::TYPE_INT, Fiddle::TYPE_INT]).call(init, 0), 'pidfd_open'))
            channel.send_io(fd)
            exit! unless channel.read(1) == '1'

            writer.write('1')
            writer.close
            readable = IO.select([channel, fd]).first
            native('pidfd_send_signal', [Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]).call(fd.fileno, Signal.list.fetch('KILL'), 0, 0) if readable.include?(channel)
            _pid, status = Process.wait2(init)
            init = nil
            fd.close
            status.exitstatus || (128 + status.termsig)
          rescue Exception => e # rubocop:disable Lint/RescueException -- startup must fail closed
            warn "Mission namespace unavailable: #{e.class}: #{e.message}"
          ensure
            if init
              begin
                Process.kill('KILL', init)
              rescue Errno::ESRCH
                nil
              end
              begin
                Process.wait(init)
              rescue Errno::ECHILD
                nil
              end
            end
            channel&.close unless channel&.closed?
          end

          # Same handshake without util-linux unshare or a user/PID namespace.
          # The supervisor is a process-group leader so cancellation still reaches
          # children that have not called setsid.
          def supervise_host
            supervise(pid_namespace: false)
          end

          def execute(descriptor)
            case descriptor.fetch(:operation).to_sym
            when :command
              _pid, status = Process.wait2(Process.spawn(*descriptor.fetch(:argv)))
              exit!(status.exitstatus || (128 + status.termsig))
            when :loop
              require 'pwn/ai/cli'
              PWN::AI::CLI.send(:mission_entry, descriptor)
            when :protected
              PWN::Plugins::AISandbox.send(:mission_entry, descriptor)
            when :console, :slash
              PWN::Plugins::REPL::AIConsole::Console.send(:mission_entry, descriptor: descriptor)
            when :legacy, :steerable
              PWN::Plugins::REPL.pwn_ai_mission_entry(descriptor)
            when :swarm
              PWN::Plugins::REPL::AISwarm::Controller.send(:mission_entry, descriptor: descriptor)
            else
              raise ArgumentError, 'unknown mission operation'
            end
          end
        end

        def initialize(opts = {}, &operation)
          @mutex = Mutex.new
          raise Unavailable, 'mission containment requires Linux' unless RUBY_PLATFORM.include?('linux')

          if self.class.prepared? && !self.class.force_exec && !(opts[:inherit_namespace] && self.class.owned)
            start_prepared(opts, &operation)
            return
          end

          if operation
            raise Unavailable, 'host closures cannot cross an exec boundary; use a mission descriptor or explicitly bootstrap under unshare --user --map-current-user --keep-caps' unless self.class.owned

            @pid = self.class.fork_mission do
              Thread.handle_interrupt(Exception => :immediate) { operation.call }
            ensure
              exit!
            end
            @pidfd = IO.new(self.class.checked(self.class.native('pidfd_open', [Fiddle::TYPE_INT, Fiddle::TYPE_INT]).call(@pid, 0), 'pidfd_open'))
            return
          end
          snapshot = { requires: Array(self.class.bootstrap_requires), descriptor: opts.fetch(:descriptor), env: PWN::Env, locals: CONTEXT_KEYS.to_h { |key| [key, Thread.current[key]] } }
          if PWN.const_defined?(:Skills)
            snapshot[:skills] = PWN::Skills
            ruby_skills = PWN::Skills.values.select { |skill| skill[:loaded] && skill[:type] == :ruby }
            snapshot[:requires] += ruby_skills.flat_map do |skill|
              skill[:format] == :legacy ? [skill.fetch(:path)] : Dir.glob(File.join(skill.fetch(:dir), 'scripts', '*.rb'))
            end
            snapshot[:requires].uniq!
          end
          mode = opts[:containment] == :host ? :host : :namespace
          payload = JSON.generate(self.class.encode(snapshot))
          start_supervisor(payload, opts, mode)
        rescue Exception => e # rubocop:disable Lint/RescueException -- failed startup cannot leak a child
          close
          detail = startup_detail(e)
          raise Unavailable, detail unless mode != :host && !@host_attempted && namespace_denied?(detail)

          @host_attempted = true
          @child_error = nil
          begin
            start_supervisor(payload, opts, :host)
          rescue Exception => host_error # rubocop:disable Lint/RescueException -- second attempt must not leak a child
            close
            raise Unavailable, "#{detail}; host supervisor: #{startup_detail(host_error)}"
          end
        end

        def wait
          @pidfd.wait_readable if @pidfd && !@pidfd.closed?
          @mutex.synchronize { reap }
        rescue IOError, Errno::EBADF
          @mutex.synchronize { reap }
        end

        def close
          return :reaped unless @mutex

          @mutex.synchronize do
            if @group && @pid
              begin
                Process.kill('KILL', -@group)
              rescue Errno::ESRCH, Errno::EPERM
                nil
              end
            end
            if @pidfd && !@pidfd.closed?
              result = self.class.native('pidfd_send_signal', [Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT]).call(@pidfd.fileno, Signal.list.fetch('KILL'), 0, 0)
              self.class.checked(result, 'pidfd_send_signal') unless result.negative? && Fiddle.last_error == Errno::ESRCH::Errno
            elsif @pid
              begin
                Process.kill('KILL', @pid)
              rescue Errno::ESRCH
                nil
              end
            end
            reap
          end
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~HELP
            # Identify module authors.
            #{self}.authors

            # Launch a private Linux mission and retain its cancellation owner.
            #{self}.new(
              descriptor: 'required - serializable operation and request parameters',
              fds: 'optional - explicitly inherited descriptor map'
            )
          HELP
        end

        private

        def start_supervisor(payload, opts, mode)
          @channel, child = UNIXSocket.pair
          err_read, err_write = IO.pipe
          mapping = opts.fetch(:fds, {}).merge(3 => child, err: err_write)
          entry = mode == :host ? 'supervise_host' : 'supervise'
          command = [RbConfig.ruby, '-I', $LOAD_PATH.join(File::PATH_SEPARATOR), '-rpwn', '-e', "exit!(PWN::AI::Agent::MissionNamespace.#{entry} || 1)"]
          command = ['unshare', '--user', '--map-current-user', '--keep-caps', *command] if mode == :namespace
          spawn_opts = mapping.merge(close_others: true)
          spawn_opts[:pgroup] = true if mode == :host
          @pid = Process.spawn(*command, spawn_opts)
          @group = @pid if mode == :host
          child.close
          err_write.close
          drain = Thread.new { @child_error = err_read.read }
          drain.report_on_exception = false
          @stderr_thread = drain
          @stderr_read = err_read
          Timeout.timeout(15) do
            @channel.puts(payload)
            @pidfd = @channel.recv_io
            @channel.write('1')
          end
        ensure
          child&.close unless child&.closed?
          err_write&.close unless err_write&.closed?
        end

        def startup_detail(error)
          [@child_error.to_s.strip, error.message].reject(&:empty?).uniq.join('; ')
        end

        def namespace_denied?(detail)
          text = detail.to_s
          return false if text.match?(/snapshot|unknown mission operation|ArgumentError/)

          text.match?(/Broken pipe|unshare|namespace|Operation not permitted|Invalid argument|No such file or directory/i)
        end

        def start_prepared(opts, &operation)
          ready, announce = IO.pipe
          release, gate = IO.pipe
          owner = Process.pid
          @pid = self.class.fork_mission do
            ready.close
            gate.close
            begin
              self.class.checked(self.class.native('prctl', [Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG]).call(1, Signal.list.fetch('KILL'), 0, 0, 0), 'PR_SET_PDEATHSIG')
              exit! unless Process.ppid == owner
              self.class.checked(self.class.native('unshare', [Fiddle::TYPE_INT]).call(0x20000000), 'unshare PID namespace')
              armed, arm = IO.pipe
              init = self.class.fork_mission do
                armed.close
                announce.close
                self.class.checked(self.class.native('prctl', [Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG]).call(1, Signal.list.fetch('KILL'), 0, 0, 0), 'PR_SET_PDEATHSIG')
                arm.write('1')
                arm.close
                exit! unless release.read(1) == '1'
                release.close
                self.class.owned = true
                Thread.current[:pwn_mission_fds] = opts.fetch(:fds, {})
                begin
                  Thread.handle_interrupt(Exception => :immediate) { operation ? operation.call : self.class.execute(opts.fetch(:descriptor)) }
                  completed = true
                ensure
                  exit!(completed ? 0 : 1)
                end
              end
              arm.close
              raise Unavailable, 'namespace init exited before arming parent-death protection' unless armed.read(1) == '1'

              armed.close
              announce.puts(JSON.generate(pid: init))
              announce.close
              release.close
              _pid, status = Process.wait2(init)
              exit!(status.exitstatus || (128 + status.termsig))
            rescue Exception => e # rubocop:disable Lint/RescueException -- report child startup errors
              announce.puts(JSON.generate(error: e.message)) unless announce.closed?
            ensure
              exit!
            end
          end
          announce.close
          release.close
          message = JSON.parse(ready.gets || '{}')
          raise Unavailable, message.fetch('error', 'namespace supervisor exited') unless message['pid']

          @pidfd = IO.new(self.class.checked(self.class.native('pidfd_open', [Fiddle::TYPE_INT, Fiddle::TYPE_INT]).call(message.fetch('pid'), 0), 'pidfd_open'))
          gate.write('1')
        ensure
          [ready, announce, release, gate].compact.each { |io| io.close unless io.closed? }
        end

        def reap
          _pid, @status = Process.wait2(@pid) if @pid
          @pid = nil
          @group = nil
          @stderr_thread&.join(1)
          @stderr_read&.close unless @stderr_read&.closed?
          @channel&.close unless @channel&.closed?
          @pidfd&.close unless @pidfd&.closed?
          :reaped
        end
      end
    end
  end
end
