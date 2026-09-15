# frozen_string_literal: true

require 'json'
require 'digest'

module PWN
  module AI
    module Agent
      # Hermes-style post-reply learning. Loop.run returns the user-visible
      # answer first; Reward / Policy / Curriculum keep running off that path.
      #
      # User-visible turn (Loop.run)
      #   tools, streaming, TaskSummarizer, final text
      # After the reply is already decided
      #   TurnFinalizer.defer -> daemon thread
      #     re-attaches the R5 episode snapshot
      #     Learning.auto_introspect (critic, Reward.judge, PRM, HER, reflect)
      #
      # Default ON during Loop.run (PWN::Env[:ai][:agent][:defer_introspect]).
      # Direct Learning.auto_introspect calls (specs, cron, tools) stay inline
      # so existing ORM contracts still get a synchronous return value.
      module TurnFinalizer
        MUTEX = Mutex.new
        THREADS = [] # rubocop:disable Style/MutableConstant
        MAX_TRACKED = 16
        DEPTH_KEY = :pwn_turn_finalizer_depth
        INLINE_KEY = :pwn_turn_finalizer_inline
        SYNC_KEY = :pwn_turn_finalizer_sync

        # Supported Method Parameters::
        # PWN::AI::Agent::TurnFinalizer.enter_user_path!

        public_class_method def self.enter_user_path!
          Thread.current[DEPTH_KEY] = Thread.current[DEPTH_KEY].to_i + 1
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::TurnFinalizer.leave_user_path!

        public_class_method def self.leave_user_path!
          depth = Thread.current[DEPTH_KEY].to_i - 1
          Thread.current[DEPTH_KEY] = depth.positive? ? depth : 0
        end

        public_class_method def self.user_path?
          Thread.current[DEPTH_KEY].to_i.positive?
        end

        # Supported Method Parameters::
        # ok = PWN::AI::Agent::TurnFinalizer.should_defer?

        public_class_method def self.should_defer?
          return false if Thread.current[INLINE_KEY]
          return false if Thread.current[SYNC_KEY]
          return false unless user_path?

          flag = agent_flag(key: :defer_introspect, default: true)
          return false if flag == false || flag.to_s.match?(/\A(0|false|no|off)\z/i)

          true
        rescue StandardError
          false
        end

        # Supported Method Parameters::
        # result = PWN::AI::Agent::TurnFinalizer.defer(
        #   session_id: 'required - PWN::Sessions id',
        #   request: 'optional - original user request',
        #   final: 'optional - user-visible final answer',
        #   predicted: 'optional - W3 predicted score',
        #   plan: 'optional - tangible-task plan',
        #   ts_state: 'optional - TaskSummarizer state'
        # )
        #
        # Snapshots the live Policy episode onto this thread, clears it so
        # Loop.maybe_finish_policy is a no-op, and runs Learning.auto_introspect
        # on a daemon thread with the episode re-attached.

        public_class_method def self.defer(opts = {})
          session_id = opts[:session_id]
          return { skipped: :no_session } if session_id.to_s.strip.empty?
          return { skipped: :no_learning } unless defined?(Learning)

          episode = nil
          episode = Policy.detach_episode! if defined?(Policy) && Policy.respond_to?(:detach_episode!)

          payload = {
            session_id: session_id,
            request: opts[:request],
            final: opts[:final],
            predicted: opts[:predicted],
            ts_state: opts[:ts_state],
            inline: true
          }

          worker = Thread.new do
            Thread.current[INLINE_KEY] = true
            begin
              Policy.attach_episode!(episode: episode) if defined?(Policy) && Policy.respond_to?(:attach_episode!)
              Learning.auto_introspect(payload)
            rescue StandardError => e
              warn "[pwn-ai/turn_finalizer] background review swallowed: #{e.class}: #{e.message}"
              nil
            ensure
              leftover = defined?(Policy) && Policy.respond_to?(:current_episode) && Policy.current_episode
              if leftover && Policy.respond_to?(:finish)
                Policy.finish(
                  session_id: session_id,
                  proxy_ok: false,
                  final: payload[:final],
                  ts_state: payload[:ts_state]
                )
              elsif defined?(Policy) && Policy.respond_to?(:attach_episode!)
                Policy.attach_episode!(episode: nil)
              end
            end
          end
          worker.report_on_exception = false
          begin
            worker.name = 'pwn-turn-finalizer'
          rescue StandardError
            nil
          end
          track(thr: worker)
          { deferred: true, session_id: session_id, thread_id: worker.object_id }
        rescue StandardError => e
          warn "[pwn-ai/turn_finalizer] defer swallowed: #{e.class}: #{e.message}"
          # Never drop the learner — fall back to inline review.
          opts_inline = opts.merge(inline: true)
          defined?(Learning) ? Learning.auto_introspect(opts_inline) : { error: e.message }
        end

        # Supported Method Parameters::
        # result = PWN::AI::Agent::TurnFinalizer.finalize(
        #   session_id:, request:, final:, predicted:, plan:, ts_state:,
        #   should: true|false
        # )
        #
        # Single entry used when a caller wants the Hermes split without
        # going through Learning.auto_introspect's gate.

        public_class_method def self.finalize(opts = {})
          return { skipped: :gated } unless opts.fetch(:should, true)
          return { skipped: :no_learning } unless defined?(Learning)

          if should_defer?
            defer(opts)
          else
            Learning.auto_introspect(opts.merge(inline: true))
          end
        rescue StandardError => e
          warn "[pwn-ai/turn_finalizer] finalize swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # n = PWN::AI::Agent::TurnFinalizer.join_all!(timeout: 15)

        public_class_method def self.join_all!(opts = {})
          timeout = (opts[:timeout] || 15).to_f
          list = MUTEX.synchronize do
            pending = THREADS.dup
            THREADS.clear
            pending
          end
          list.each do |thr|
            thr.join(timeout) if thr.alive?
          rescue StandardError
            nil
          end
          list.length
        end

        # Supported Method Parameters::
        # n = PWN::AI::Agent::TurnFinalizer.pending

        public_class_method def self.pending
          MUTEX.synchronize { THREADS.count(&:alive?) }
        end

        # Literal destinations only; source paths are never delivery obligations.
        public_class_method def self.output_paths(opts = {})
          request = opts[:request].to_s
          paths = []
          intent = nil
          previous_end = 0
          request.to_enum(:scan, %r{["'`]((?:~/|/|\./|\.\./)[^"'`\n]+|[^"'`\n]+\.[A-Za-z0-9]+)["'`]|(?<![\w:/])((?:~/|/|\./|\.\./)[\w.+/-]+|[\w+-]+\.[A-Za-z0-9]+)}).each do
            match = Regexp.last_match
            literal = match[1] || match[2].sub(/[.,;:]+\z/, '')
            prefix = request[previous_end...match.begin(0)]
            previous_end = match.end(0)
            intent = prefix.scan(/\b(write|save|store|output|export|create|update|modify|edit|generate|put|produce|deliver|read|inspect|review|analy[sz]e|summari[sz]e|from|using)\b/i).flatten.last&.downcase || intent
            next unless %w[write save store output export create update modify edit generate put produce deliver].include?(intent)

            paths << File.expand_path(literal, opts[:cwd] || Dir.pwd)
          end
          paths.uniq
        end

        # Host-only snapshot; never parse an artifact claim from tool stdout.
        public_class_method def self.artifact_snapshot(opts = {})
          Array(opts[:paths]).to_h do |literal|
            path = File.expand_path(literal.to_s)
            [path, artifact_readback(path: path)]
          end
        end

        # Invoke immediately after a successful tool dispatch. The host reads
        # stat plus bounded head/tail itself, before exposing the result.
        public_class_method def self.observe_artifacts(opts = {})
          return {} unless opts[:success] == true && opts[:effect].to_s == 'write'

          before = opts[:before] || {}
          artifact_snapshot(paths: opts[:paths]).select do |path, row|
            row && before.key?(path) && before[path] != row
          end
        end

        private_class_method def self.artifact_readback(opts = {})
          File.open(opts[:path], File::RDONLY | File::NONBLOCK) do |file|
            stat = file.stat
            return nil unless stat.file? && stat.size.positive?

            head = file.read(4096).to_s
            file.seek([stat.size - 4096, 0].max)
            tail = file.read(4096).to_s
            file.rewind
            digest = Digest::SHA256.new
            while (chunk = file.read(65_536))
              digest.update(chunk)
            end
            current = file.stat
            return nil unless [current.ino, current.size, current.mtime, current.ctime] == [stat.ino, stat.size, stat.mtime, stat.ctime]

            { stat: { size: stat.size, ino: stat.ino, dev: stat.dev, mtime: stat.mtime.to_r.to_s, ctime: stat.ctime.to_r.to_s },
              head: head, tail: tail, sha256: digest.hexdigest }
          end
        rescue StandardError
          nil
        end

        public_class_method def self.arbitrate(opts = {})
          request = opts[:request].to_s
          messages = Array(opts[:messages])
          t0 = opts[:session_t0] || Thread.current[:pwn_loop_t0]
          paths = Array(opts[:paths]).map { |path| File.expand_path(path.to_s) }
          paths += output_paths(request: request)
          paths.uniq!
          ledger = evidence_ledger(messages: messages)
          unmet = []
          paths.each do |path|
            row = ledger[path]
            unless File.file?(path)
              unmet << { criterion: 'artifact_missing', detail: path }
              next
            end
            unmet << { criterion: 'empty_artifact', detail: path } if File.size(path) < 2
            unmet << { criterion: 'write_missing', detail: path } unless row && row[:write]
            unmet << { criterion: 'readback_missing', detail: path } unless row && row[:read]
            unmet << { criterion: 'artifact_mtime_before_session', detail: path } if t0 && File.mtime(path) < t0
          end
          {
            complete: unmet.empty? && (!paths.empty? || ledger.any?),
            unmet: unmet,
            ledger: ledger
          }
        end

        public_class_method def self.evidence_ledger(opts = {})
          ledger = {}
          Array(opts[:messages]).each do |msg|
            next unless msg.is_a?(Hash) && msg[:role].to_s == 'tool'

            next unless msg[:artifact_observations].is_a?(Hash)

            msg[:artifact_observations].each do |path, observed|
              current = artifact_readback(path: path)
              next unless current && current == observed

              ledger[path] = { write: true, read: true, evidence: observed }
            end
          end
          ledger
        end

        public_class_method def self.evidence_satisfied?(opts = {})
          row = arbitrate(
            request: opts[:request],
            messages: opts[:messages] || opts[:trace],
            paths: opts[:paths],
            session_t0: opts[:session_t0]
          )
          row[:complete] == true && Array(row[:unmet]).empty?
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Run enter user path and return its result
            #{self}.enter_user_path!

            # Run leave user path and return its result
            #{self}.leave_user_path!

            # Run user path and return its result
            #{self}.user_path?

            # Run should defer and return its result
            #{self}.should_defer?

            # Run defer and return its result
            #{self}.defer(
              session_id: 'required - PWN::Sessions id',
              request: 'optional - original user request',
              final: 'optional - user-visible final answer',
              predicted: 'optional - W3 predicted score',
              plan: 'optional - tangible-task plan',
              ts_state: 'optional - TaskSummarizer state'
            )

            # Run finalize and return its result
            #{self}.finalize(
              session_id: 'optional - request:, final:, predicted:, plan:, ts_state:',
              should: 'optional - should value consumed by #finalize'
            )

            # Run join all and return its result
            #{self}.join_all!(
              timeout: 'optional - seconds to wait before giving up'
            )

            # Run pending and return its result
            #{self}.pending

            # Extract explicit output literals, excluding source/read paths.
            #{self}.output_paths(request: 'required - original user request', cwd: 'optional - relative path base')

            # Snapshot named destinations immediately before a tool runs.
            #{self}.artifact_snapshot(paths: 'required - destination paths')

            # Host-only post-dispatch write delta and stat/head-tail readback.
            # Keep this result in internal tool-message artifact_observations.
            #{self}.observe_artifacts(
              paths: 'required - destination paths', before: 'required - artifact_snapshot result',
              effect: 'required - actual Dispatch effect', success: 'required - semantic tool success boolean'
            )

            # Arbitrate a completion claim against the turn evidence ledger.
            #{self}.arbitrate(
              request: 'optional - original operator request',
              messages: 'optional - Array of role/content hashes for this turn',
              paths: 'optional - absolute paths that must exist',
              session_t0: 'optional - session start Time (mtime-before-session is named, not silent)'
            )

            # Build path → {write,read} from host-owned artifact_observations only.
            #{self}.evidence_ledger(
              messages: 'optional - Array of role/content hashes'
            )

            # True when write-then-readback evidence satisfies the original request.
            #{self}.evidence_satisfied?(
              request: 'optional - original request text',
              messages: 'optional - Array of role/content hashes',
              trace: 'optional - alias for messages (Array of role/content hashes)',
              paths: 'optional - Array of declared deliverable paths',
              session_t0: 'optional - session start Time'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.track(opts = {})
          thr = opts[:thr]
          MUTEX.synchronize do
            THREADS.select!(&:alive?)
            THREADS << thr
            THREADS.shift&.kill if THREADS.length > MAX_TRACKED
          end
        rescue StandardError
          nil
        end

        private_class_method def self.agent_flag(opts = {})
          key = opts[:key]
          default = opts[:default]
          return default unless defined?(PWN::Env)

          val = PWN::Env.dig(:ai, :agent, key)
          val.nil? ? default : val
        rescue StandardError
          opts[:default]
        end
      end
    end
  end
end
