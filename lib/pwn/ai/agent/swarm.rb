# frozen_string_literal: true

require 'json'
require 'yaml'
require 'time'
require 'fileutils'
require 'securerandom'

module PWN
  module AI
    module Agent
      # Native multi-agent orchestration for pwn-ai.
      #
      # Swarm replaces the legacy `pwn-irc` mechanism (inspircd + weechat +
      # PRIVMSG-flattened .chat calls) with first-class sub-agents built on
      # top of PWN::AI::Agent::Loop.run. Each persona is a full tool-calling
      # agent — Memory, Skills, Learning, Metrics and Extrospection all
      # apply — so the self-improvement loop covers the whole swarm.
      #
      #   ~/.pwn/agents.yml                    # persona registry
      #   ~/.pwn/swarm/<swarm_id>/bus.jsonl    # append-only message bus
      #   ~/.pwn/swarm/<swarm_id>/personas.json# persona -> PWN::Sessions id
      #
      # Cross-session / cross-process communication == another pwn-ai (or a
      # PWN::Cron job) calling Swarm.ask/debate with the same swarm_id and
      # reading the same bus.jsonl. No daemon required.
      module Swarm
        AGENTS_FILE     = File.join(Dir.home, '.pwn', 'agents.yml')
        SWARM_ROOT      = File.join(Dir.home, '.pwn', 'swarm')
        DEFAULT_DEPTH   = 3
        DEFAULT_ITERS   = 25
        DEFAULT_TAIL    = 12
        DEFAULT_TOOLSET = %w[terminal pwn memory skills sessions learning
                             metrics extrospection].freeze

        # ------------------------------------------------------------------
        # Persona registry (~/.pwn/agents.yml)
        # ------------------------------------------------------------------

        # Supported Method Parameters::
        #   personas = PWN::AI::Agent::Swarm.personas

        public_class_method def self.personas
          return {} unless File.exist?(AGENTS_FILE)

          raw = YAML.safe_load_file(
            AGENTS_FILE,
            permitted_classes: [Symbol],
            aliases: true,
            symbolize_names: true
          ) || {}
          raw.transform_values { |v| normalize_persona(persona: v) }
        rescue StandardError => e
          warn "[pwn-ai/swarm] failed to load #{AGENTS_FILE}: #{e.class}: #{e.message}"
          {}
        end

        # Supported Method Parameters::
        #   PWN::AI::Agent::Swarm.spawn(
        #     name: 'required - persona name (snake_case)',
        #     role: 'required - system_role_content overlay for this persona',
        #     toolsets: 'optional - Array of Registry toolset names',
        #     engine: 'optional - :openai / :anthropic / :grok / :gemini / :ollama',
        #     max_iters: 'optional - per-turn iteration cap for this persona'
        #   )

        public_class_method def self.spawn(opts = {})
          name = opts[:name].to_s
          raise ArgumentError, 'name is required' if name.strip.empty?
          raise ArgumentError, 'role is required' if opts[:role].to_s.strip.empty?

          all = personas
          all[name.to_sym] = normalize_persona(persona: opts)
          FileUtils.mkdir_p(File.dirname(AGENTS_FILE))
          File.write(AGENTS_FILE, YAML.dump(deep_stringify(hash: all)))
          { name: name, persona: all[name.to_sym], file: AGENTS_FILE }
        end

        # Supported Method Parameters::
        #   PWN::AI::Agent::Swarm.retire(name: 'required - persona name')

        public_class_method def self.retire(opts = {})
          name = opts[:name].to_s
          all  = personas
          gone = all.delete(name.to_sym)
          File.write(AGENTS_FILE, YAML.dump(deep_stringify(hash: all))) if gone
          { name: name, removed: !gone.nil? }
        end

        # ------------------------------------------------------------------
        # Swarm lifecycle & bus
        # ------------------------------------------------------------------

        # Supported Method Parameters::
        #   swarm = PWN::AI::Agent::Swarm.create(topic: 'optional')

        public_class_method def self.create(opts = {})
          id  = "#{Time.now.utc.strftime('%Y%m%d_%H%M%S')}_#{SecureRandom.hex(3)}"
          dir = File.join(SWARM_ROOT, id)
          FileUtils.mkdir_p(dir)
          bus_append(swarm_id: id, from: :system, to: :all,
                     content: "swarm #{id} created: #{opts[:topic] || '(no topic)'}")
          { swarm_id: id, dir: dir, bus: bus_path(swarm_id: id) }
        end

        # Supported Method Parameters::
        #   swarms = PWN::AI::Agent::Swarm.list

        public_class_method def self.list
          FileUtils.mkdir_p(SWARM_ROOT)
          Dir.children(SWARM_ROOT).sort.reverse.map do |id|
            bp = bus_path(swarm_id: id)
            {
              swarm_id: id,
              dir: File.join(SWARM_ROOT, id),
              messages: File.exist?(bp) ? File.foreach(bp).count : 0,
              mtime: File.exist?(bp) ? File.mtime(bp).utc.iso8601 : nil
            }
          end
        end

        # Supported Method Parameters::
        #   PWN::AI::Agent::Swarm.bus_append(
        #     swarm_id: 'required', from: 'required', content: 'required',
        #     to: 'optional (default :all)'
        #   )

        public_class_method def self.bus_append(opts = {})
          sid = opts[:swarm_id].to_s
          raise ArgumentError, 'swarm_id is required' if sid.empty?

          FileUtils.mkdir_p(File.join(SWARM_ROOT, sid))
          entry = {
            ts: Time.now.utc.iso8601,
            from: opts[:from].to_s,
            to: (opts[:to] || :all).to_s,
            content: opts[:content].to_s
          }
          File.open(bus_path(swarm_id: sid), 'a') { |f| f.puts(JSON.generate(entry)) }
          entry
        end

        # Supported Method Parameters::
        #   msgs = PWN::AI::Agent::Swarm.bus_tail(swarm_id: 'required', limit: 12)

        public_class_method def self.bus_tail(opts = {})
          sid   = opts[:swarm_id].to_s
          limit = (opts[:limit] || DEFAULT_TAIL).to_i
          bp    = bus_path(swarm_id: sid)
          return [] unless File.exist?(bp)

          File.readlines(bp).last(limit).map { |l| JSON.parse(l, symbolize_names: true) }
        rescue StandardError
          []
        end

        # ------------------------------------------------------------------
        # Core: run a single persona turn under Loop.run
        # ------------------------------------------------------------------

        # Supported Method Parameters::
        #   reply = PWN::AI::Agent::Swarm.ask(
        #     name: 'required - persona name from ~/.pwn/agents.yml',
        #     request: 'required - what to ask/instruct the persona',
        #     swarm_id: 'optional - join an existing swarm (created if omitted)',
        #     to: 'optional - addressee recorded on the bus (default :all)',
        #     on_tool: 'optional - ->(name, args, result) live-UI callback'
        #   )

        public_class_method def self.ask(opts = {})
          name    = opts[:name].to_s
          persona = personas[name.to_sym]
          raise ArgumentError, "unknown persona: #{name} (see #{AGENTS_FILE})" unless persona

          sid   = opts[:swarm_id] || create(topic: opts[:request].to_s[0, 60])[:swarm_id]
          depth = Thread.current[:pwn_swarm_depth] || 0
          if depth >= max_depth
            raise "swarm recursion depth #{depth} >= max_depth #{max_depth} " \
                  '(PWN::Env[:ai][:agent][:max_depth])'
          end

          bus_append(swarm_id: sid, from: opts[:from] || caller_label,
                     to: name, content: opts[:request].to_s)

          session_id = persona_session(swarm_id: sid, name: name)
          sys        = build_persona_prompt(name: name, persona: persona,
                                            swarm_id: sid, session_id: session_id)

          Thread.current[:pwn_swarm_depth] = depth + 1
          reply = with_persona_env(persona: persona) do
            Loop.run(
              request: opts[:request].to_s,
              session_id: session_id,
              enabled_toolsets: persona[:toolsets],
              system_role_content: sys,
              on_tool: opts[:on_tool]
            )
          end

          bus_append(swarm_id: sid, from: name, to: opts[:to] || :all, content: reply)
          { swarm_id: sid, name: name, session_id: session_id, reply: reply }
        ensure
          Thread.current[:pwn_swarm_depth] = depth
        end

        # Supported Method Parameters::
        #   result = PWN::AI::Agent::Swarm.debate(
        #     names: 'required - Array of persona names, order = speaking order',
        #     topic: 'required - opening question / claim',
        #     rounds: 'optional - full passes over names (default 2)',
        #     swarm_id: 'optional - join an existing swarm',
        #     on_tool: 'optional - ->(name, args, result) live-UI callback'
        #   )

        public_class_method def self.debate(opts = {})
          names = Array(opts[:names]).map(&:to_s)
          raise ArgumentError, 'names must contain at least 2 personas' if names.length < 2

          topic = opts[:topic].to_s
          raise ArgumentError, 'topic is required' if topic.strip.empty?

          rounds = (opts[:rounds] || 2).to_i
          sid    = opts[:swarm_id] || create(topic: topic)[:swarm_id]

          last_speaker = 'moderator'
          last_msg     = topic
          transcript   = []

          rounds.times do |r|
            names.each do |n|
              req = if r.zero? && n == names.first
                      topic
                    else
                      "@#{last_speaker} said:\n#{last_msg}\n\n" \
                        'Respond, critique, or advance the objective.'
                    end
              res = ask(name: n, request: req, swarm_id: sid,
                        from: last_speaker, to: n, on_tool: opts[:on_tool])
              transcript << { round: r + 1, name: n, reply: res[:reply] }
              last_speaker = n
              last_msg     = res[:reply]
            end
          end

          { swarm_id: sid, rounds: rounds, names: names,
            transcript: transcript, bus: bus_path(swarm_id: sid) }
        end

        # Supported Method Parameters::
        #   result = PWN::AI::Agent::Swarm.broadcast(
        #     request: 'required', names: 'optional - default all personas',
        #     swarm_id: 'optional'
        #   )

        public_class_method def self.broadcast(opts = {})
          req   = opts[:request].to_s
          raise ArgumentError, 'request is required' if req.strip.empty?

          names = Array(opts[:names]).map(&:to_s)
          names = personas.keys.map(&:to_s) if names.empty?
          sid   = opts[:swarm_id] || create(topic: req[0, 60])[:swarm_id]

          replies = names.to_h do |n|
            [n, ask(name: n, request: req, swarm_id: sid,
                    from: 'broadcast', on_tool: opts[:on_tool])[:reply]]
          end
          { swarm_id: sid, replies: replies }
        end

        # ------------------------------------------------------------------
        # privates
        # ------------------------------------------------------------------

        private_class_method def self.bus_path(opts = {})
          File.join(SWARM_ROOT, opts[:swarm_id].to_s, 'bus.jsonl')
        end

        private_class_method def self.persona_session(opts = {})
          sid  = opts[:swarm_id].to_s
          name = opts[:name].to_s
          map_path = File.join(SWARM_ROOT, sid, 'personas.json')
          map = File.exist?(map_path) ? JSON.parse(File.read(map_path)) : {}
          return map[name] if map[name]

          sess = PWN::Sessions.create(
            title: "swarm:#{sid} persona:#{name}",
            source: 'pwn-ai-swarm'
          )
          map[name] = sess[:id]
          File.write(map_path, JSON.pretty_generate(map))
          sess[:id]
        end

        private_class_method def self.build_persona_prompt(opts = {})
          name    = opts[:name]
          persona = opts[:persona]
          sid     = opts[:swarm_id]
          base    = PromptBuilder.build(session_id: opts[:session_id])

          bus = bus_tail(swarm_id: sid, limit: DEFAULT_TAIL).map do |m|
            "  [#{m[:ts]}] #{m[:from]} → #{m[:to]}: #{m[:content].to_s.tr("\n", ' ')[0, 400]}"
          end.join("\n")

          peers = (personas.keys.map(&:to_s) - [name]).join(', ')

          <<~PROMPT
            #{base}

            SWARM
              swarm_id : #{sid}
              you_are  : #{name}
              peers    : #{peers.empty? ? '(none)' : peers}
              depth    : #{Thread.current[:pwn_swarm_depth] || 0} / #{max_depth}
              (Use agent_ask to delegate to a peer only if strictly necessary
               and you have the 'swarm' toolset — depth is capped.)

            PERSONA (#{name})
            #{persona[:role]}

            SWARM BUS (last #{DEFAULT_TAIL} msgs, newest last)
            #{bus.empty? ? '  (empty)' : bus}
          PROMPT
        end

        # Temporarily override PWN::Env[:ai][:active] and
        # PWN::Env[:ai][:agent][:max_iters] for the duration of a sub-agent
        # turn, restoring both afterwards even on raise.
        private_class_method def self.with_persona_env(opts = {})
          persona = opts[:persona]
          ai = env_ai
          return yield unless ai

          agent_h = (ai[:agent] ||= {})
          prev_active = ai[:active]
          prev_iters  = agent_h[:max_iters]

          ai[:active]          = persona[:engine].to_s if persona[:engine]
          agent_h[:max_iters]  = persona[:max_iters]   if persona[:max_iters]
          yield
        ensure
          if ai
            ai[:active]         = prev_active
            agent_h[:max_iters] = prev_iters
          end
        end

        private_class_method def self.normalize_persona(opts = {})
          p = opts[:persona] || {}
          {
            role: p[:role].to_s,
            engine: (p[:engine].to_s.empty? ? nil : p[:engine].to_s.downcase.to_sym),
            toolsets: Array(p[:toolsets]).map(&:to_s).then { |a| a.empty? ? DEFAULT_TOOLSET.dup : a },
            max_iters: (p[:max_iters] || DEFAULT_ITERS).to_i
          }
        end

        private_class_method def self.max_depth
          v = (PWN::Env.dig(:ai, :agent, :max_depth) if defined?(PWN::Env))
          v.to_i.positive? ? v.to_i : DEFAULT_DEPTH
        rescue StandardError
          DEFAULT_DEPTH
        end

        private_class_method def self.env_ai
          return nil unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          ai = PWN::Env[:ai]
          ai.is_a?(Hash) && !ai.frozen? ? ai : nil
        rescue StandardError
          nil
        end

        private_class_method def self.caller_label
          d = Thread.current[:pwn_swarm_depth] || 0
          d.zero? ? 'orchestrator' : "depth#{d}"
        end

        private_class_method def self.deep_stringify(opts = {})
          h = opts[:hash]
          case h
          when Hash  then h.to_h { |k, v| [k.to_s, deep_stringify(hash: v)] }
          when Array then h.map { |v| deep_stringify(hash: v) }
          when Symbol then h.to_s
          else h
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              # Define personas (or edit #{AGENTS_FILE} directly)
              PWN::AI::Agent::Swarm.spawn(
                name: 'red',
                role: 'Offensive researcher. Propose the most likely exploit path...',
                toolsets: %w[terminal pwn memory extrospection],
                engine: :anthropic
              )

              # One-shot: ask a persona (creates a swarm if none given)
              r = PWN::AI::Agent::Swarm.ask(name: 'red', request: 'Enumerate attack surface for target X')

              # Antagonistic feedback loop
              d = PWN::AI::Agent::Swarm.debate(
                names: %w[red blue],
                topic: 'Is CVE-2026-NNNN exploitable on target X?',
                rounds: 3
              )
              puts d[:transcript].map { |t| "\#{t[:name]}: \#{t[:reply][0,200]}" }

              # Fan-out
              PWN::AI::Agent::Swarm.broadcast(request: 'Summarise findings so far')

              # Inspect / resume cross-session
              PWN::AI::Agent::Swarm.list
              PWN::AI::Agent::Swarm.bus_tail(swarm_id: d[:swarm_id], limit: 50)

              Config:
                PWN::Env[:ai][:agent][:max_depth]  # recursion cap  (default #{DEFAULT_DEPTH})
                persona[:max_iters]                # per-turn iteration cap (default #{DEFAULT_ITERS})
                persona[:toolsets]                 # Registry toolset allow-list; omit 'swarm'
                                                   # to prevent that persona spawning sub-agents.

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
