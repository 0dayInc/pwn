# frozen_string_literal: true

require 'json'
require 'digest'
require 'securerandom'

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
        PATH_LITERAL = %r{["'`]((?:~/|/|\./|\.\./)[^"'`\n]+|[^"'`\n]+\.[A-Za-z0-9]+)["'`]|(?<![\w:/])((?:~/|/|\./|\.\./)[\w.+/-]+|[\w+-]+\.[A-Za-z0-9]+)}
        WRITE_VERBS = %w[write save store output export create update modify edit generate put produce deliver mv move copy cp rename].freeze
        TO_DESTINATION = %w[summarize summarise translate convert extract append redirect].freeze
        FILE_CONTEXT = /\b(?:#{Regexp.union(WRITE_VERBS + TO_DESTINATION).source}|read|compare|inspect|review|analy[sz]e|from|using|into|to)\b/i

        # A directory is not a file artifact. Only the operator's frozen skill
        # destination can use this witness. Inventory metadata, never catalog
        # bodies; a final check opens only the documents in the host receipt.
        class SkillDirectory
          MAX_ENTRIES = 8192
          MAX_DEPTH = 12
          MAX_DOCUMENTS = 16
          MAX_BYTES = 1 << 20
          FLAGS = File::RDONLY | File::NOFOLLOW | File::NONBLOCK
          EXCLUDED = %w[assets scripts templates].freeze

          # Read-only fd-relative traversal. Never mkdir, follow a symlink, or
          # cross a mount below HOME (including a same-device bind mount).
          class PinnedTree
            def at(path, missing: false, &block)
              raise IOError if path.count('/') > 128

              if path == '/'
                @mount = nil
                return yield('/')
              end

              at(File.dirname(path), missing: missing) do |parent|
                child = File.join(parent, File.basename(path))
                begin
                  stat = File.lstat(child)
                rescue Errno::ENOENT
                  raise unless missing

                  next
                end
                descend(child, stat) do |pinned, file|
                  @mount = mount_id(file) if path == Dir.home
                  block.call(pinned)
                end
              end
            end

            def descend(path, stat)
              raise IOError unless stat.directory?

              File.open(path, FLAGS) do |file|
                actual = file.stat
                raise IOError unless actual.directory? && actual.dev == stat.dev && actual.ino == stat.ino
                raise IOError if @mount && !same_mount?(file)

                result = yield "/proc/self/fd/#{file.fileno}", file
                named = File.lstat(path)
                raise IOError unless named.directory? && named.dev == actual.dev && named.ino == actual.ino

                result
              end
            end

            def same_mount?(file)
              mount_id(file) == @mount
            end

            private

            def mount_id(file)
              File.read("/proc/self/fdinfo/#{file.fileno}", 4096)[/^mnt_id:\s*(\d+)$/, 1] || raise(IOError)
            end
          end
          private_constant :PinnedTree

          def initialize(path, library, contract)
            @path = path
            @library = library
            @contract = contract
            @tree = PinnedTree.new
            @entries = {}
            @remaining = MAX_ENTRIES
          end

          attr_reader :path, :contract, :entries, :action, :identity

          def snapshot
            # Only the inner dispatcher brackets a single action. Do not use
            # the wider Loop watch window or a baseline from another action.
            @action = Thread.current[:pwn_request_runtime].events.last
            return unless @action && @action[:phase] == 'start' && !@action[:action_id].to_s.empty?
            return unless %w[shell pwn_eval].include?(@action[:tool]) && direct_turn?

            @tree.at(@path, missing: true) do |pinned|
              @identity = directory_id(pinned)
              inventory(pinned, '', 0)
            end
            @entries.freeze
            self
          rescue SystemCallError, IOError, ArgumentError, EncodingError
            nil # An incomplete inventory is NOT an empty pre-write directory.
          end

          def changes(before, action_id, tool)
            return unless before.is_a?(SkillDirectory) && before.contract.equal?(@contract) && before.path == @path
            return unless before.action == @action && @action.values_at(:action_id, :tool) == [action_id, tool]
            # Moving a tree of existing documents is not a document write.
            return if before.identity && before.identity != @identity
            return unless before.entries.each_key.all? { |name| @entries.key?(name) }

            changed = @entries.reject { |name, stat| before.entries[name] == stat }
            # No pre-write digest for an entire catalog: a same-inode, same-size
            # edit cannot be distinguished from touch. Name the file for that case.
            return if changed.any? { |name, stat| before.entries[name]&.first(3) == stat.first(3) }

            readback(changed)
          end

          def matches?(observed)
            docs = observed[:skill_documents]
            return false unless direct_turn? && docs.is_a?(Array) && docs.size.between?(1, MAX_DOCUMENTS) && docs.all?(Hash)

            events = Thread.current[:pwn_request_runtime].events.select { |event| event[:action_id] == observed[:action_id] }
            return false unless events.map { |e| e[:phase] } == %w[start end] && events.last[:state] == 'completed' && events.all? { |e| e[:tool] == observed[:tool] }

            current = readback(docs.to_h { |doc| [doc[:path], doc[:stat]] })
            current && current == observed.slice(*current.keys)
          end

          private

          def direct_turn?
            !Thread.current[:pwn_loop_nested] && !Thread.current[:pwn_solve_tools] && !Thread.current[:pwn_swarm_depth].to_i.positive?
          end

          def signature(stat)
            [stat.dev, stat.ino, stat.size, stat.mtime.to_r.to_s, stat.ctime.to_r.to_s]
          end

          def directory_id(pinned)
            stat = File.stat(pinned)
            [stat.dev, stat.ino]
          end

          def inventory(pinned, prefix, depth)
            raise IOError if depth > MAX_DEPTH

            stamp = signature(File.stat(pinned))
            Dir.each_child(pinned) do |name|
              raise IOError if (@remaining -= 1).negative?
              next if name.start_with?('.') || EXCLUDED.include?(name)

              child = File.join(pinned, name)
              relative = prefix + name
              stat = File.lstat(child)
              if stat.directory?
                @tree.descend(child, stat) { |dir| inventory(dir, "#{relative}/", depth + 1) }
              else
                raise IOError unless stat.file? && stat.nlink == 1

                @entries[relative] = signature(stat) if owner(relative)
              end
            end
            raise IOError unless signature(File.stat(pinned)) == stamp
          end

          # A canonical entry or a text reference, never an arbitrary script,
          # attachment, hidden path or directory named by tool stdout.
          def owner(name)
            return unless name.is_a?(String) && name.valid_encoding? && !name.match?(/[[:cntrl:]]/)

            parts = File.join(@path, name).delete_prefix("#{@library}/").split('/', -1)
            return if name.start_with?('/') || parts.any? { |part| part.empty? || part.start_with?('.') || EXCLUDED.include?(part) }

            refs = parts.index('references')
            return parts[0...refs] if refs&.positive? && %w[.md .txt].include?(File.extname(parts.last).downcase)

            parts[0...-1] if !refs && parts.size > 1 && parts.last == 'SKILL.md'
          end

          def readback(changed)
            return unless changed.size.between?(1, MAX_DOCUMENTS)

            owners = changed.keys.map { |name| owner(name) }.uniq
            return unless owners.size == 1 && owners.first

            identity = @tree.at(@path) { |pinned| directory_id(pinned) }
            return if @identity && @identity != identity

            docs = changed.sort.map { |name, stat| document(name, stat) }
            # The runtime persists head/tail for file receipts. Never attach
            # samples from a directory or publish an inventory of unrelated docs.
            { skill_directory_id: identity, skill_documents: docs, sha256: Digest::SHA256.hexdigest(JSON.generate(docs)),
              skill_request: Digest::SHA256.hexdigest(@contract.fetch(:request)), head: '', tail: '' }
          rescue SystemCallError, IOError, ArgumentError, EncodingError
            nil
          end

          def document(name, expected)
            path = File.join(@path, name)
            @tree.at(File.dirname(path)) do |dir|
              child = File.join(dir, File.basename(path))
              stat = File.lstat(child)
              raise IOError unless matching_file?(stat, expected) && stat.size.between?(1, MAX_BYTES)

              File.open(child, FLAGS) do |file|
                raise IOError unless @tree.same_mount?(file) && matching_file?(file.stat, expected)

                bytes = file.binmode.read(stat.size + 1).to_s.force_encoding(Encoding::UTF_8)
                raise IOError unless bytes.bytesize == stat.size && bytes.valid_encoding? && !bytes.include?("\0") && bytes.match?(/\S/)
                raise IOError unless matching_file?(file.stat, expected) && matching_file?(File.lstat(child), expected)

                { path: name, stat: expected, sha256: Digest::SHA256.hexdigest(bytes) }
              end
            end
          end

          def matching_file?(stat, expected)
            stat.file? && stat.nlink == 1 && signature(stat) == expected
          end
        end
        private_constant :SkillDirectory

        # Bounded, local document work. Only a verb and its file operands qualify;
        # an additional action or an ambiguous target stays on the ordinary path.
        # Keep coverage in the controller for this turn, never in the model prompt.
        class InputPages
          LIST = /\A\s*(?:please\s+)?(?:read|compare|inspect|review|summari[sz]e|analy[sz]e)\s+
                  (?:(?:the|these|both)\s+)?(?<files>files?\s*:?\s*)?\x00
                  (?:\s*(?:,\s*(?:and\s+)?|and|to|with|against|versus|vs\.?)\s*\x00)*
                  (?:\s*[,;]?\s*(?:and\s+)?(?:reply|answer|respond)\s+in\s+(?:(?:the|this)\s+)?chat)?\s*[.!?]?\s*\z/ix

          public_class_method def self.for_turn(opts = {})
            runtime = opts[:runtime]
            return if opts[:nested] || opts[:unattended] || opts[:solve_handoff]
            return unless runtime && runtime.request == opts[:request] && runtime.contract[:required_artifacts].empty?

            for_request(request: opts[:request], cwd: runtime.contract.fetch(:cwd))
          end

          public_class_method def self.for_request(opts = {})
            paths = operands(request: opts.fetch(:request))
            new(paths, opts.fetch(:cwd)) if paths
          end

          public_class_method def self.operands(opts = {})
            request = opts.fetch(:request)
            return if request.include?("\0") || request.match?(%r{\b[a-z][a-z\d+.-]*://}i)

            paths = []
            bare_name = false
            shape = request.gsub(PATH_LITERAL) do
              quoted, bare = Regexp.last_match.captures
              bare_name ||= !quoted && !bare.start_with?('/', './', '../', '~/')
              paths << (quoted || bare.sub(/[.,;:]+\z/, ''))
              "\0"
            end
            list = LIST.match(shape)
            # A bare dotted name is ambiguous unless the operator called it a file.
            paths if list && (!bare_name || list[:files])
          end

          def initialize(paths, cwd)
            @cwd = cwd
            @pages = paths.to_h { |path| [File.expand_path(path, cwd), nil] }
          end

          # Only the registered reader's successful result counts. A proposed
          # call, a grep preview, or an unrelated tool printing JSON is not a page.
          def observe(name, raw)
            return unless name == 'artifact_read'

            result = JSON.parse(raw, symbolize_names: true)
            return unless result.is_a?(Hash) && result[:success] == true && result[:effect] == 'read'

            page = result[:result]
            return unless page.is_a?(Hash) && page[:path].is_a?(String) && page[:body].is_a?(String)

            path = File.expand_path(page[:path], @cwd)
            first, last, size = page.values_at(:offset, :next_offset, :total_bytes)
            return unless @pages.key?(path) && [first, last, size].all?(Integer) && first.between?(0, last) && last <= size && page[:bytes] == last - first

            state = @pages[path]
            state = @pages[path] = { size: size, ranges: {} } unless state && state[:size] == size
            state[:ranges][first] = [last, state[:ranges].fetch(first, first)].max
          rescue JSON::ParserError, ArgumentError
            nil
          end

          def unmet
            @pages.filter_map do |path, state|
              offset = next_missing(state)
              "input_unread:#{path} (next byte #{offset})" if offset
            end
          end

          private

          def next_missing(state)
            return 0 unless state

            offset = 0
            state[:ranges].sort.each do |first, last|
              break if first > offset

              offset = [offset, last].max
            end
            offset unless offset == state[:size]
          end
        end

        # A visible reply that does not certify the requested work. A partial
        # chat draft is presentation only, never an action or a learning label.
        class TurnNotice < String
          CHAT_DESTINATION = /\b(?:in (?:this |the )?chat|in (?:your|the) (?:reply|response)|here in (?:your|the) reply)\b/i

          # Another prose answer isn't a changed observation of a missing file.
          class Gap
            def initialize(opts, nested)
              @public_draft = !nested && !opts[:solve_handoff] && !opts[:force_tools] && !opts[:verification_contract]
            end

            def stop_reason(unmet, no_tools, runtime)
              return 'no_available_tools' if no_tools

              paths = runtime.contract[:required_artifacts]
              return unless unmet.any? { |row| row.start_with?('input_unread:') || paths.include?(row.to_s.partition(':').last) }

              observed = runtime.observations.slice(*paths).transform_values { |row| row[:sha256] }
              state = [unmet.uniq.sort, observed]
              return 'unchanged_evidence' if @last == state

              @last = state
              nil
            end

            def notice(runtime, unmet, reason, msg)
              draft = msg[:content].to_s if @public_draft && !msg[:_thinking_promoted]
              TurnNotice.new.unfinished(runtime: runtime, unmet: unmet, reason: reason, candidate: draft)
            end
          end

          def unfinished(runtime:, unmet:, reason:, candidate: nil)
            summary = case reason
                      when 'no_available_tools' then 'No tools are available in this request.'
                      when 'unchanged_evidence' then 'The outstanding requirement is unchanged; there is no new evidence to check.'
                      else 'No specific unmet requirement was identified to retry.'
                      end
            outstanding = Array(runtime.contract[:required_artifacts]).select do |path|
              unmet.any? { |row| row.to_s.partition(':').last == path }
            end
            self << "[pwn-ai] blocked: #{summary}"
            unread = unmet.grep(/\Ainput_unread:/).map { |row| row.delete_prefix('input_unread:') }
            self << if unread.any?
                      " Input not fully read: #{unread.join(', ')}."
                    elsif outstanding.empty?
                      ' The requested work was not verified.'
                    else
                      " File delivery was not verified: #{outstanding.join(', ')}."
                    end
            partial = outstanding.any? && candidate && runtime.request.match?(CHAT_DESTINATION)
            if partial
              self << "\n\nChat draft (not evidence of file delivery):\n"
              self << candidate.lines.map { |line| "> #{line}" }.join
            end
            runtime.finish!(status: 'blocked', goal_status: partial ? 'partial' : 'blocked', stage: 'finalization', unmet: unmet + [reason])
            self
          end
        end

        # An operator-facing reply is a deliverable, not an observation of an
        # external effect. The same object governs the main hop and its final.
        class Conversation
          TEXT = /\A(?:compose|draft|translate|paraphrase|rephrase|convert|write (?:me|us)|how many|what is the number of)\b/i
          # A stated writing format specifies the medium, not the topic. A
          # bare 'write a report' remains ambiguous about the destination.
          WRITING_FORMAT = /\Awrite\b[^;\n]*?\b(?:words?|sentences?|paragraphs?|notes?|poems?|letters?|captions?)\b/i
          QUESTION = /\A(?:what|which|when|where|why|who|how|is|are|will|does|do|can (?:we|I)|should (?:we|I))\b/i
          EXTERNAL = %r{https?://|[/\\]|\b(?:files?|folder|directory|repo(?:sitory)?|on\s+disk|hostname|machine|subnet|shell|server|processes|devices|installed|running|logs?|backups?|database|configuration|settings|calendar)\b|
            \b(?:save|store|export|publish|send|upload|download|email|execute|install|schedule|scan|wait|monitor)\b}ix
          INSTRUCTIONS = <<~TEXT
            The operator's request is the goal; a proposed plan is not an additional deliverable.
            Return your public reply as JSON: {"pwn_turn":"answer", "text":"the answer"}.
            If an essential input is missing, use "needs_input"; if only part is ready, use "partial".
            For either, give the useful portion and a precise question or next requirement in text, and name it in "remaining".
            Use the supplied conversation. Do not ask twice, invent a current source, or claim an external action from prose.
          TEXT

          def select(opts)
            return if %i[nested force_tools verification_contract runtime unattended mission_id solve_handoff min_seconds steering_history require_resumable request_id].any? { |key| opts[key] }
            return if opts[:trusted_context] || opts[:core_only] == false
            return if Thread.current[:pwn_request_runtime] || Thread.current[:pwn_swarm_depth].to_i.positive? || TurnFinalizer.user_path?

            text = opts[:request].to_s.strip
            return if text.empty? || text.match?(OpenGoal::CONTINUE_RX) || text.match?(EXTERNAL) || text.match?(Loop::BROWSER_REQUEST_RX)
            return if InputPages.operands(request: text)
            return unless Loop.request_intent(request: text) == :act && !Loop.catalog_lookup?(request: text)
            return unless TurnFinalizer.output_paths(request: text).empty?

            clause = text.sub(/\A(?:(?:could|can|would) you )?(?:please )?/i, '')
            @no_sources = opts[:enabled_toolsets] == []
            question = QUESTION.match?(clause)
            # A chat destination says where to answer, not where a fact comes from.
            @text_only = TEXT.match?(clause) || WRITING_FORMAT.match?(clause) || (!question && clause.match?(TurnNotice::CHAT_DESTINATION))
            effects = @text_only ? clause.sub(/\A(?:write|create)\b/i, '') : clause
            return if effects.match?(Loop::ACT_REQUEST_RX) || effects.sub(/\Ahow many\b/i, '').match?(Loop::LOOKUP_REQUEST_RX)
            return if Mission.active_id

            sid = opts[:session_id]
            current = OpenGoal.for_session(session_id: sid) unless sid.to_s.empty?
            return if current && !current[:reply_question]

            if current && follows_question?(current, sid)
              @pending = current
              @text_only ||= current[:reply_medium] == 'text'
            end
            self if @pending || @text_only || question
          end

          def text_only?
            @text_only
          end

          def permits_reply?(runtime)
            runtime && !runtime.verification_contract && runtime.contract[:required_artifacts].empty? && runtime.blocker.nil?
          end

          def unprocessed?(msg)
            msg[:_thinking_promoted] || Array(msg[:tool_calls]).any?
          end

          # Only already-configured provider retrieval, never local functions
          # or a code interpreter. A source is optional, not a plan obligation.
          def sources(engine, config, model)
            return [] if text_only? || @no_sources
            return [] unless engine == :grok || PWN::AI::ServerTools.mixable?(engine: engine, model: model)

            Array(config[:server_tools]).map(&:to_s) & PWN::AI::ServerTools::WIRE.fetch(engine, {}).keys & %w[web_search web_fetch google_search x_search]
          end

          def with_instructions(messages, sources:)
            medium = if text_only?
                       'The requested result is text. No external actions are available.'
                     elsif sources.empty?
                       'No online source is enabled for this turn. If current information is needed and missing, return partial and ask for the relevant source text.'
                     else
                       "Provider-hosted sources available now: #{sources.join(', ')}. Use them when the answer needs a lookup and cite the source used. No local functions are available."
                     end
            follow_up = ' If this message supplies the requested input and your reply answers or advances that earlier goal, also set "continues":true.' if @pending
            first_turn = messages.take_while { |row| %w[system developer].include?((row[:role] || row['role']).to_s) }.length
            messages.dup.insert(first_turn, { role: 'system', content: "#{INSTRUCTIONS}#{medium}#{follow_up}" })
          end

          def unprocessed(runtime, msg)
            text = msg[:content].to_s unless msg[:_thinking_promoted]
            visible = text.to_s.match?(Loop::DisplayReply::BLANK) ? 'No public answer was available.' : decode(text).fetch(:text)
            notice = TurnNotice.new(visible)
            pending = Array(msg[:tool_calls]).any?
            notice << "\n\nAn action from this reply was not processed." if pending
            save(runtime, 'notice', notice)
            runtime.finish!(status: 'incomplete', stage: 'provider', unmet: [pending ? 'unprocessed_action' : 'public_reply_missing'])
            notice
          end

          # Preview contains public text and a pending bit, never a runnable provider message.
          def present_preview(runtime, preview, on_notice)
            return finish(runtime, preview.text) if preview.answer?

            runtime.check_cancelled!
            visible = decode(preview.text).fetch(:text)
            save(runtime, 'notice', preview.present(nil, public_text: visible))
            runtime.finish!(status: 'incomplete', stage: 'provider', unmet: [preview.pending ? 'unprocessed_action' : 'public_reply_missing'])
            preview.present(on_notice, public_text: visible)
          end

          def finish(runtime, content)
            runtime.check_cancelled!
            disposition = decode(content)
            reply = disposition.fetch(:text)
            state = disposition.fetch(:pwn_turn)
            sid = runtime.session_id
            continues = @pending && disposition[:continues] == true
            row = save(runtime, 'assistant', reply)
            if state == 'answer'
              runtime.observe_evidence!(kind: 'answer', requirement: runtime.original_request, locator: 'chat:reply', sha256: Digest::SHA256.hexdigest(row.fetch(:content))) if row && text_only?
              runtime.finish!(status: 'complete')
              OpenGoal.clear!(answered_id: @pending[:request_id]) if continues
            else
              awaiting = state == 'needs_input'
              runtime.finish!(status: 'incomplete', goal_status: awaiting ? 'awaiting_input' : 'partial', stage: awaiting ? 'clarification' : 'finalization', unmet: [disposition[:remaining]])
              unless sid.empty?
                OpenGoal.begin!(request: runtime.original_request, session_id: sid, answered_id: (@pending[:request_id] if continues),
                                reply_question: (Digest::SHA256.hexdigest(row.fetch(:content)) if awaiting && row), reply_medium: text_only? ? 'text' : 'information')
              end
            end
            reply
          end

          private

          # Direct callers need not have a transcript. A returned string and a
          # persisted row are different observations; never invent the latter.
          def save(runtime, role, text)
            PWN::Sessions.append(session_id: runtime.session_id, role: role, content: text) unless runtime.session_id.empty?
          rescue IOError, SystemCallError
            nil
          end

          def follows_question?(goal, sid)
            rows = PWN::Sessions.load(session_id: sid).last(2)
            return false unless rows in [{ role: 'user', content: String }, { role: 'assistant', content: String }]

            previous = goal[:reply_after] || Digest::SHA256.hexdigest(goal.fetch(:request))
            Digest::SHA256.hexdigest(rows.first[:content].strip) == previous && Digest::SHA256.hexdigest(rows.last[:content]) == goal[:reply_question]
          end

          def decode(text)
            if text.lstrip.start_with?('{')
              row = begin
                JSON.parse(text, symbolize_names: true)
              rescue JSON::ParserError
                nil # Unframed JSON can itself be the requested answer.
              end
              return row if framed?(row)
            end
            # Older models can return ordinary prose. Display it verbatim, but
            # don't certify an unlabelled question as the answer it asks for.
            return { pwn_turn: 'needs_input', text: text, remaining: text.strip } if text.rstrip.end_with?('?')

            { pwn_turn: 'answer', text: text }
          end

          def framed?(row)
            return false unless row.is_a?(Hash) && row[:text].is_a?(String) && !row[:text].match?(Loop::DisplayReply::BLANK)

            row[:pwn_turn] == 'answer' || (%w[needs_input partial].include?(row[:pwn_turn]) && row[:remaining].is_a?(String) && !row[:remaining].strip.empty?)
          end
        end

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

          snapshot = Reward.prm_snapshot(session_id: session_id, request: opts[:request]) if defined?(Reward)
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
            Thread.current[:pwn_prm_snapshot] = snapshot
            begin
              Policy.attach_episode!(episode: episode) if defined?(Policy) && Policy.respond_to?(:attach_episode!)
              Learning.auto_introspect(payload)
            rescue StandardError => e
              warn "[pwn-ai/turn_finalizer] background review swallowed: #{e.class}: #{e.message}"
              nil
            ensure
              Thread.current[:pwn_prm_snapshot] = nil
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

        # Freeze operator-owned destinations once, before tools can change cwd.
        public_class_method def self.commit_artifacts!(opts = {})
          return Thread.current[:pwn_artifact_contract] if opts[:inherit] && Thread.current[:pwn_artifact_contract]

          request = opts[:request].to_s.dup.freeze
          paths = output_paths(request: request, cwd: opts[:cwd]).map(&:freeze).freeze
          Thread.current[:pwn_artifact_contract] = {
            id: SecureRandom.hex(16).freeze,
            request: request,
            required_artifacts: paths,
            started_at: Time.now.freeze
          }.freeze
        end

        public_class_method def self.required_artifacts(opts = {})
          contract = Thread.current[:pwn_artifact_contract]
          return contract[:required_artifacts] if contract && (contract[:request] == opts[:request].to_s || Thread.current[:pwn_loop_nested])

          output_paths(request: opts[:request], cwd: opts[:cwd])
        end

        # Literal destinations only; source paths are never delivery obligations.
        public_class_method def self.output_paths(opts = {})
          request = opts[:request].to_s
          paths = []
          intent = nil
          operation = nil
          previous_end = 0
          request.to_enum(:scan, PATH_LITERAL).each do
            match = Regexp.last_match
            literal = match[1] || match[2].sub(/[.,;:]+\z/, '')
            # Unquoted dotted initials followed by a period are prose (i.e.,
            # e.g., U.S.), not a filename. Quoted literals remain authoritative.
            next if !match[1] && literal.match?(/\A(?:[A-Za-z]\.)+[A-Za-z]\z/) && request[match.end(0)] == '.'

            prefix = request[previous_end...match.begin(0)]
            previous_end = match.end(0)
            prefix.downcase.scan(FILE_CONTEXT).each do |word|
              case word
              when 'from', 'using' then intent = :input
              when 'into', 'to' then intent = operation
              when *TO_DESTINATION
                operation = :output
                intent = :input
              else intent = operation = WRITE_VERBS.include?(word) ? :output : :input
              end
            end
            next unless intent == :output

            paths << File.expand_path(literal, opts[:cwd] || Dir.pwd)
          end
          paths.uniq
        end

        # Only committed destinations may be sampled during a turn. A known
        # missing file has a nil baseline; an unobservable file has NO baseline.
        public_class_method def self.artifact_snapshot(opts = {})
          contract = Thread.current[:pwn_artifact_contract]
          Array(opts[:paths]).each_with_object({}) do |literal, rows|
            path = File.expand_path(literal.to_s)
            next if contract && !contract[:required_artifacts].include?(path)

            directory = skill_directory_for(path: path)
            row = directory ? directory.snapshot : artifact_readback(path: path)
            rows[path] = row unless row == :unavailable
          end
        end

        # Invoke immediately after a successful tool dispatch. The host reads
        # stat plus bounded head/tail itself, before exposing the result.
        public_class_method def self.observe_artifacts(opts = {})
          return {} unless opts[:success] == true && opts[:effect].to_s == 'write'

          before = opts[:before] || {}
          observed = artifact_snapshot(paths: opts[:paths]).filter_map do |path, row|
            next unless row && before.key?(path) && before[path] != row

            row = row.changes(before[path], opts[:action_id], opts[:tool]) if row.is_a?(SkillDirectory)
            [path, row] if row
          end.to_h
          observed = observed.transform_values do |row|
            contract = Thread.current[:pwn_artifact_contract]
            row = row.merge(action_id: opts[:action_id], tool: opts[:tool]) if opts[:action_id]
            contract ? row.merge(artifact_turn_id: contract[:id]) : row
          end
          runtime = Thread.current[:pwn_request_runtime]
          runtime.observe!(observations: observed) if runtime && runtime.contract[:id] == Thread.current[:pwn_artifact_contract]&.dig(:id)
          observed
        end

        private_class_method def self.skill_directory_for(opts = {})
          path = opts.fetch(:path)
          contract = Thread.current[:pwn_artifact_contract]
          return unless contract && contract.dig(:skill_destinations, path) == :directory
          return unless Thread.current[:pwn_request_runtime]&.contract.equal?(contract) && contract[:required_artifacts].include?(path)

          library = File.join(Dir.home, '.pwn', 'skills')
          SkillDirectory.new(path, library, contract) if path == library || path.start_with?("#{library}/")
        end

        private_class_method def self.artifact_readback(opts = {})
          path = opts.fetch(:path)
          begin
            stat = File.lstat(path)
          rescue Errno::ENOENT, Errno::ENOTDIR
            return nil
          end
          return :unavailable unless stat.file?
          return nil unless stat.size.positive?

          with_artifact_file(path: path, stat: stat) do |file|
            file.binmode
            head = file.read(4096).to_s
            file.seek([stat.size - 4096, 0].max)
            tail = file.read(4096).to_s
            file.rewind
            digest = Digest::SHA256.new
            remaining = stat.size
            while remaining.positive?
              chunk = file.read([remaining, 65_536].min)
              return :unavailable unless chunk && !chunk.empty?

              digest.update(chunk)
              remaining -= chunk.bytesize
            end
            next :unavailable unless same_artifact?(expected: stat, actual: file.stat) && same_artifact?(expected: stat, actual: File.lstat(path))

            { stat: { size: stat.size, ino: stat.ino, dev: stat.dev, mtime: stat.mtime.to_r.to_s, ctime: stat.ctime.to_r.to_s },
              head: head, tail: tail, sha256: digest.hexdigest }
          end
        rescue SystemCallError, IOError
          :unavailable # No receipt for this path; independent outputs still count.
        end

        private_class_method def self.same_artifact?(opts = {})
          expected = opts.fetch(:expected)
          actual = opts.fetch(:actual)
          actual.file? && expected.dev == actual.dev && expected.ino == actual.ino && expected.size == actual.size &&
            expected.mtime == actual.mtime && expected.ctime == actual.ctime
        end

        private_class_method def self.with_artifact_file(opts = {})
          path = opts.fetch(:path)
          stat = opts.fetch(:stat)
          flags = File::RDONLY | File::NONBLOCK
          read_regular = lambda do |file|
            next :unavailable unless same_artifact?(expected: stat, actual: file.stat)

            yield file
          end
          return File.open(path, flags | File::NOFOLLOW, &read_regular) unless RUBY_PLATFORM.include?('linux')

          # O_PATH pins the inode without opening a device driver. Reopen
          # that descriptor for bytes, never a potentially replaced pathname.
          File.open(path, 0x200000 | File::NOFOLLOW) do |pin|
            next :unavailable unless same_artifact?(expected: stat, actual: pin.stat)

            File.open("/proc/self/fd/#{pin.fileno}", flags, &read_regular)
          end
        end

        public_class_method def self.arbitrate(opts = {})
          request = opts[:request].to_s
          messages = Array(opts[:messages])
          t0 = opts[:session_t0] || Thread.current[:pwn_artifact_contract]&.dig(:started_at) || Thread.current[:pwn_loop_t0]
          paths = Array(opts[:paths]).map { |path| File.expand_path(path.to_s) }
          paths += required_artifacts(request: request)
          paths.uniq!
          ledger = evidence_ledger(messages: messages, request: request, paths: paths)
          unmet = []
          paths.each do |path|
            row = ledger[path]
            if skill_directory_for(path: path)
              unmet << { criterion: 'skill_document_unverified', detail: path } unless row&.dig(:evidence, :skill_documents)
              next
            end
            unless File.file?(path)
              unmet << { criterion: 'artifact_missing', detail: path }
              next
            end
            unmet << { criterion: 'empty_artifact', detail: path } if File.empty?(path)
            unmet << { criterion: 'write_missing', detail: path } unless row && row[:write]
            unmet << { criterion: 'readback_missing', detail: path } unless row && row[:read]
            # Filesystem timestamps can lag Time.now by a clock tick. A bound
            # current-turn write delta plus matching readback is stronger proof.
            current_turn = row && row.dig(:evidence, :artifact_turn_id) == Thread.current[:pwn_artifact_contract]&.dig(:id) && Thread.current[:pwn_artifact_contract]
            unmet << { criterion: 'artifact_mtime_before_session', detail: path } if t0 && File.mtime(path) < t0 && !current_turn
          end
          unmet.concat(literal_content_unmet(request: request, ledger: ledger, paths: paths))
          complete = unmet.empty? && (!paths.empty? || ledger.any?)
          {
            status: complete ? 'complete' : 'incomplete',
            complete: complete,
            unmet: unmet,
            ledger: ledger
          }
        rescue StandardError => e
          { status: 'verification_error', complete: false, unmet: [{ criterion: 'verification_error', detail: "#{e.class}: #{e.message}" }], ledger: {} }
        end

        # Deliberately narrow, deterministic literal grammar, not a semantic
        # judge. The expected digest comes from the request, never tool prose.
        private_class_method def self.literal_content_unmet(opts = {})
          request = opts[:request].to_s
          paths = opts[:paths]
          ledger = opts[:ledger]
          request.scan(/(?:"([^"\n]+)"|`([^`\n]+)`|([^\s]+))\s+containing exactly\s+([^\n]+?)\s+followed by (?:a )?newline/i).filter_map do |quoted, ticked, bare, literal|
            path = File.expand_path(quoted || ticked || bare, Thread.current[:pwn_artifact_contract]&.dig(:cwd) || Dir.pwd)
            next unless paths.include?(path)

            expected = Digest::SHA256.hexdigest("#{literal}\n")
            next if ledger.dig(path, :evidence, :sha256) == expected

            { criterion: 'artifact_content_mismatch', detail: path }
          end
        end

        public_class_method def self.evidence_ledger(opts = {})
          ledger = {}
          contract = Thread.current[:pwn_artifact_contract]
          paths = Array(opts[:paths] || contract&.dig(:required_artifacts) || required_artifacts(request: opts[:request]))
          paths &= contract[:required_artifacts] if contract
          runtime = Thread.current[:pwn_request_runtime]
          messages = Array(opts[:messages])
          host = { role: 'tool', artifact_observations: runtime.observations } if runtime
          messages += [host] if host
          messages.each do |msg|
            next unless msg.is_a?(Hash) && msg[:role].to_s == 'tool'

            next unless msg[:artifact_observations].is_a?(Hash)

            msg[:artifact_observations].each do |path, observed|
              next unless paths.include?(path) && observed.is_a?(Hash)
              next if contract && observed[:artifact_turn_id] != contract[:id]

              directory = skill_directory_for(path: path)
              if directory
                next unless msg.equal?(host) && opts.fetch(:request, contract[:request]) == contract[:request] && directory.matches?(observed)
              else
                next if observed.key?(:skill_documents)

                current = artifact_readback(path: path)
                readback = observed.except(:artifact_turn_id, :action_id, :tool, :child_request_id, :child_turn_id, :child_provenance)
                next unless current && current == readback
              end

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

            # Track input pages for an interactive turn with no file delivery.
            #{self}::InputPages.for_turn(
              request: 'required - original operator request', runtime: 'required - runtime that owns the request',
              nested: 'optional - true for a nested turn', unattended: 'optional - true for an unattended turn',
              solve_handoff: 'optional - true when handing work to the solver'
            )

            # Build a page tracker for an explicit local file read.
            #{self}::InputPages.for_request(request: 'required - original operator request', cwd: 'required - directory for resolving input paths')

            # Return the literal input filenames in an unambiguous read request.
            #{self}::InputPages.operands(request: 'required - original operator request')

            # Precommit immutable required_artifacts for this turn before tools run.
            #{self}.commit_artifacts!(request: 'required - original user request', cwd: 'optional - initial relative path base', inherit: 'optional - reuse the owning turn contract for a nested call')

            # Return precommitted paths, or parse literals outside an active turn.
            #{self}.required_artifacts(request: 'required - original user request', cwd: 'optional - relative path base outside a turn')

            # Snapshot named destinations immediately before a tool runs.
            # Operator-named default skill directories inventory bounded metadata only.
            #{self}.artifact_snapshot(paths: 'required - destination paths')

            # Host-only post-dispatch write delta and stat/head-tail readback.
            # Skill directory receipts contain only changed document paths, metadata and digests.
            # Keep this result in internal tool-message artifact_observations.
            #{self}.observe_artifacts(
              paths: 'required - destination paths', before: 'required - artifact_snapshot result',
              effect: 'required - actual Dispatch effect', success: 'required - semantic tool success boolean',
              action_id: 'optional - dispatcher tool call identifier for revision provenance',
              tool: 'optional - dispatcher tool name for revision provenance'
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
              messages: 'optional - Array of role/content hashes',
              request: 'optional - original request defining output paths outside a turn',
              paths: 'optional - absolute output paths to recheck, limited by the active turn'
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
