# frozen_string_literal: true

require 'json'
require 'yaml'
require 'time'
require 'fileutils'
require 'securerandom'
require 'socket'
require 'digest'

module PWN
  module AI
    module Agent
      # Native multi-agent orchestration for pwn-ai.
      #
      # First-class sub-agents built on top of PWN::AI::Agent::Loop.run.
      # Each persona is a full tool-calling agent — Memory, Skills, Learning,
      # Metrics and Extrospection all apply — so the self-improvement loop
      # covers the whole swarm.
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
        SPECIALIST_ROLES = {
          recon: {
            role: 'Map the operator-named target. Record assets and working probes. Do not invent hosts.',
            skills: %w[osint penetration-testing],
            toolsets: %w[pwn terminal extrospection http]
          },
          authz: {
            role: 'Test authorization and IDOR on discovered assets. Reproduce with request/response PoCs.',
            skills: %w[web-application-penetration-testing],
            toolsets: %w[pwn terminal http]
          },
          injection: {
            role: 'Test injection on discovered inputs. Attach a working PoC, not a scanner signature.',
            skills: %w[web-application-penetration-testing deep-exploitation],
            toolsets: %w[pwn terminal http]
          },
          xss: {
            role: 'Test XSS and CSRF in a real browser session. Evidence is a reproduced payload, not a pattern hit.',
            skills: %w[web-application-penetration-testing],
            toolsets: %w[pwn terminal http]
          },
          business_logic: {
            role: 'Chain authorization, injection, and workflow flaws into one evidenced impact path.',
            skills: %w[web-application-penetration-testing bug-bounty-hunting],
            toolsets: %w[pwn terminal http]
          }
        }.freeze

        # ------------------------------------------------------------------
        # Persona registry (~/.pwn/agents.yml)
        # ------------------------------------------------------------------

        # Supported Method Parameters::
        #   personas = PWN::AI::Agent::Swarm.personas

        public_class_method def self.personas(opts = {})
          all = load_personas_file(path: AGENTS_FILE)
          sid = opts[:swarm_id].to_s
          unless sid.empty?
            local = load_personas_file(path: File.join(SWARM_ROOT, sid, 'agents.yml'))
            all = all.merge(local)
          end
          all
        end

        # Supported Method Parameters::
        #   PWN::AI::Agent::Swarm.spawn(
        #     name: 'required - persona name (snake_case)',
        #     role: 'required - system_role_content overlay for this persona',
        #     toolsets: 'optional - Array of Registry toolset names',
        #     engine: 'optional - :openai / :anthropic / :grok / :gemini / :ollama / :openwebui',
        #     model: 'optional - exact model identifier (defaults to selected provider model)',
        #     max_iters: 'optional - per-turn iteration cap for this persona'
        #   )

        public_class_method def self.spawn(opts = {})
          name = opts[:name].to_s
          raise ArgumentError, 'name is required' if name.strip.empty?
          raise ArgumentError, 'role is required' if opts[:role].to_s.strip.empty?

          packed = pack_specialist(opts)
          sid = opts[:swarm_id].to_s
          ephemeral = opts[:ephemeral] == true || (!sid.empty? && opts[:global] != true)
          path = if ephemeral && !sid.empty?
                   FileUtils.mkdir_p(File.join(SWARM_ROOT, sid))
                   File.join(SWARM_ROOT, sid, 'agents.yml')
                 else
                   AGENTS_FILE
                 end
          all = load_personas_file(path: path)
          row = normalize_persona(persona: opts.merge(toolsets: packed[:toolsets], skills: packed[:skills]))
          all[name.to_sym] = row
          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, YAML.dump(deep_stringify(hash: all)))
          { name: name, persona: row, file: path, ephemeral: ephemeral }
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
          raw = opts[:content].to_s
          entry = {
            ts: Time.now.utc.iso8601,
            from: opts[:from].to_s,
            to: (opts[:to] || :all).to_s,
            content: raw
          }
          if raw.bytesize > 400
            stored = if defined?(PWN::Plugins::ArtifactRegistry)
                       PWN::Plugins::ArtifactRegistry.put(bytes: raw, kind: 'swarm-bus', session_id: sid)
                     else
                       { sha256: Digest::SHA256.hexdigest(raw), path: bus_path(swarm_id: sid) }
                     end
            entry[:content] = raw.byteslice(0, 400)
            entry[:ref] = stored[:path]
            entry[:sha256] = stored[:sha256]
          end
          File.open(bus_path(swarm_id: sid), 'a') do |f|
            f.flock(File::LOCK_EX)
            f.puts(JSON.generate(entry))
          end
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
          depth   = Thread.current[:pwn_swarm_depth] || 0
          empty_tools = false
          prior_id = Thread.current[:pwn_swarm_id]
          prior_honesty = Thread.current[:pwn_swarm_honesty]
          sid     = opts[:swarm_id] || create(topic: opts[:request].to_s[0, 60])[:swarm_id]
          persona = personas(swarm_id: sid)[name.to_sym]
          raise ArgumentError, "unknown persona: #{name} (see #{AGENTS_FILE})" unless persona

          if opts[:unit].to_s != ''
            held = claim(unit: opts[:unit], agent_id: name, ttl: opts[:ttl] || 300, engagement_id: opts[:engagement_id] || sid)
            return { ok: false, error: 'claim_held', claim: held } unless held[:ok]
          end

          if depth >= max_depth
            raise "swarm recursion depth #{depth} >= max_depth #{max_depth} " \
                  '(PWN::Env[:ai][:agent][:max_depth])'
          end

          bus_append(swarm_id: sid, from: opts[:from] || caller_label,
                     to: name, content: opts[:request].to_s)

          session_id = persona_session(swarm_id: sid, name: name)
          sys        = build_persona_prompt(name: name, persona: persona,
                                            swarm_id: sid, session_id: session_id)

          empty_tools = opts[:text_only] == true || Array(persona[:toolsets]).empty?
          Thread.current[:pwn_swarm_depth] = depth + 1
          Thread.current[:pwn_swarm_id] = sid
          reply = with_persona_env(persona: persona) do
            Loop.run(
              request: opts[:request].to_s,
              session_id: session_id,
              enabled_toolsets: empty_tools ? [] : persona[:toolsets],
              core_only: empty_tools ? false : true,
              system_role_content: sys,
              on_tool: opts[:on_tool],
              nested: true
            )
          end

          bus_append(swarm_id: sid, from: name, to: opts[:to] || :all, content: reply)
          inbox = child_inbox(session_id: session_id, name: name)
          honesty = child_honesty(name: name, toolsets: persona[:toolsets], session_id: session_id, skills: persona[:skills])
          (Thread.current[:pwn_swarm_honesty] ||= []) << honesty.merge(name: name) unless empty_tools
          { ok: true, swarm_id: sid, name: name, session_id: session_id, reply: reply, inbox: inbox, honesty: honesty }
        ensure
          Thread.current[:pwn_swarm_depth] = depth
          if empty_tools
            Thread.current[:pwn_swarm_id] = prior_id
            Thread.current[:pwn_swarm_honesty] = prior_honesty
          end
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

          threads = names.map do |n|
            [n, Thread.new { ask(name: n, request: req, swarm_id: sid, from: 'broadcast', on_tool: opts[:on_tool])[:reply] }]
          end
          replies = threads.to_h { |n, th| [n, th.value] }
          { swarm_id: sid, replies: replies }
        end

        # ------------------------------------------------------------------
        # privates
        # ------------------------------------------------------------------

        private_class_method def self.bus_path(opts = {})
          File.join(SWARM_ROOT, opts[:swarm_id].to_s, 'bus.jsonl')
        end

        private_class_method def self.load_personas_file(opts = {})
          path = opts[:path].to_s
          return {} unless File.file?(path)

          raw = YAML.safe_load_file(
            path,
            permitted_classes: [Symbol],
            aliases: true,
            symbolize_names: true
          ) || {}
          raw = {} unless raw.is_a?(Hash)
          raw.transform_values { |v| normalize_persona(persona: v) }
        rescue StandardError => e
          warn "[pwn-ai/swarm] failed to load #{path}: #{e.class}: #{e.message}"
          {}
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

        # Scope provider selection to this turn, preserving enclosing overrides.
        # An omitted engine inherits the parent; an omitted model uses the
        # selected provider's default rather than the parent persona's model.
        private_class_method def self.with_persona_env(opts = {})
          persona = opts[:persona]
          prev_engine = Thread.current[:pwn_swarm_engine]
          prev_model = Thread.current[:pwn_swarm_model]

          Thread.current[:pwn_swarm_engine] = persona[:engine].to_s if persona[:engine]
          Thread.current[:pwn_swarm_model] = persona[:model]
          yield
        ensure
          Thread.current[:pwn_swarm_engine] = prev_engine
          Thread.current[:pwn_swarm_model] = prev_model
        end

        private_class_method def self.normalize_persona(opts = {})
          p = opts[:persona] || {}
          {
            role: p[:role].to_s,
            model: (p[:model] if p[:model].is_a?(String) && !p[:model].strip.empty?),
            engine: (p[:engine].to_s.empty? ? nil : p[:engine].to_s.downcase.to_sym),
            toolsets: begin
              raw_ts = p[:toolsets]
              raw_ts.nil? ? DEFAULT_TOOLSET.dup : Array(raw_ts).map(&:to_s)
            end,
            skills: Array(p[:skills]).map(&:to_s).first(3),
            max_iters: (p[:max_iters] || DEFAULT_ITERS).to_i
          }
        end

        private_class_method def self.max_depth
          v = (PWN::Env.dig(:ai, :agent, :max_depth) if defined?(PWN::Env))
          v.to_i.positive? ? v.to_i : DEFAULT_DEPTH
        rescue StandardError
          DEFAULT_DEPTH
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

        public_class_method def self.map_targets(opts = {})
          hosts = opts[:targets].to_s.split(/[,\s]+/).reject(&:empty?)
          ports = opts[:ports].to_s.split(/[,\s]+/).map(&:to_i).reject(&:zero?)
          ports = [80, 443] if ports.empty?
          if defined?(PWN::Plugins::Packet) && PWN::Plugins::Packet.respond_to?(:tcp_connect_scan)
            row = PWN::Plugins::Packet.tcp_connect_scan(hosts: hosts, ports: ports)
            return Array(row[:results])
          end

          hosts.product(ports).map do |host, port|
            Thread.new do
              open = begin
                sock = TCPSocket.new(host, port)
                sock.close
                true
              rescue StandardError
                false
              end
              { host: host, port: port, open: open }
            end
          end.map(&:value)
        end

        public_class_method def self.fact_record(opts = {})
          eng = (opts[:engagement_id] || 'default').to_s
          dir = File.join(Dir.home, '.pwn', 'engagements', eng)
          FileUtils.mkdir_p(dir)
          path = File.join(dir, 'facts.jsonl')
          row = {
            kind: (opts[:kind] || 'host').to_s,
            value: opts[:value],
            source_session: opts[:source_session].to_s,
            confidence: (opts[:confidence] || 0.7).to_f,
            at: Time.now.utc.iso8601
          }
          File.open(path, 'a') { |f| f.puts(JSON.generate(row)) }
          row.merge(path: path)
        end

        public_class_method def self.facts_prompt(opts = {})
          eng = (opts[:engagement_id] || 'default').to_s
          path = File.join(Dir.home, '.pwn', 'engagements', eng, 'facts.jsonl')
          return '' unless File.file?(path)

          rows = File.readlines(path).filter_map do |ln|
            JSON.parse(ln, symbolize_names: true)
          rescue JSON::ParserError
            nil
          end
          return '' if rows.empty?

          "FACTS #{rows.map { |r| "#{r[:kind]}=#{r[:value]}" }.join(' ')}"
        end

        public_class_method def self.claim(opts = {})
          eng = (opts[:engagement_id] || 'default').to_s
          unit = opts[:unit].to_s
          raise 'ERROR: unit is required' if unit.empty?

          ttl = (opts[:ttl] || 300).to_i
          agent = (opts[:agent_id] || 'anon').to_s
          dir = File.join(SWARM_ROOT, eng)
          FileUtils.mkdir_p(dir)
          path = File.join(dir, "#{unit.gsub(/[^A-Za-z0-9._:-]/, '_')}.claim")
          now = Time.now.to_i
          File.open(path, File::RDWR | File::CREAT, 0o644) do |f|
            f.flock(File::LOCK_EX)
            existing = begin
              JSON.parse(f.read, symbolize_names: true)
            rescue StandardError
              {}
            end
            return { ok: false, unit: unit, holder: existing[:agent_id] } if existing[:until].to_i > now && existing[:agent_id].to_s != agent

            row = { unit: unit, agent_id: agent, until: now + ttl }
            f.rewind
            f.truncate(0)
            f.write(JSON.generate(row))
            { ok: true, unit: unit, agent_id: agent, until: row[:until] }
          end
        end

        public_class_method def self.pack_specialist(opts = {})
          name = opts[:name].to_s
          skills = Array(opts[:skills]).map(&:to_s).reject(&:empty?).first(3)
          toolsets = Array(opts[:toolsets]).map(&:to_s)
          toolsets -= %w[swarm] unless opts[:orchestrator]
          toolsets = DEFAULT_TOOLSET.dup if toolsets.empty?
          { name: name, skills: skills, toolsets: toolsets }
        end

        # Catalog of lead-spawned offensive specialists (recon through business logic).

        public_class_method def self.specialist_roles(opts = {})
          name = opts[:name].to_s
          return SPECIALIST_ROLES.fetch(name.to_sym) unless name.empty?

          SPECIALIST_ROLES
        end

        # Write ephemeral specialist personas for a swarm without running Loop.

        public_class_method def self.ensure_specialists(opts = {})
          sid = opts[:swarm_id].to_s
          raise ArgumentError, 'swarm_id is required' if sid.empty?

          SPECIALIST_ROLES.map do |name, spec|
            spawn(
              name: name.to_s,
              role: spec[:role],
              skills: spec[:skills],
              toolsets: spec[:toolsets],
              swarm_id: sid,
              ephemeral: true
            )
          end
        end

        public_class_method def self.child_inbox(opts = {})
          sid = opts[:session_id].to_s
          findings = if defined?(PWN::Plugins::Findings)
                       Array(PWN::Plugins::Findings.report).select { |r| r[:session_id].to_s == sid || sid.empty? }
                     else
                       []
                     end
          arts = if defined?(PWN::Plugins::ArtifactRegistry)
                   Array(PWN::Plugins::ArtifactRegistry.list(session_id: sid))
                 else
                   []
                 end
          {
            name: opts[:name].to_s,
            finding_ids: findings.map { |r| r[:id].to_s },
            artifact_shas: arts.filter_map { |a| a[:sha256] || a['sha256'] },
            coverage: []
          }
        end

        public_class_method def self.child_honesty(opts = {})
          inbox = child_inbox(opts)
          toolsets = Array(opts[:toolsets]).map(&:to_s)
          pwnish = toolsets.include?('pwn') || toolsets.include?('extrospection')
          empty = Array(inbox[:finding_ids]).empty? && Array(inbox[:artifact_shas]).empty?
          gap = pwnish && empty ? 'child_filed_nothing' : nil
          { name: opts[:name].to_s, gap: gap, inbox: inbox }
        end

        public_class_method def self.honesty_unmet(opts = {})
          sid = (opts[:swarm_id] || Thread.current[:pwn_swarm_id]).to_s
          return [] if sid.empty?

          Array(Thread.current[:pwn_swarm_honesty]).filter_map do |h|
            next unless h[:gap]

            "child_filed_nothing:#{h[:name]}"
          end
        end

        public_class_method def self.view_graph(opts = {})
          sid = opts[:swarm_id].to_s
          raise ArgumentError, 'swarm_id is required' if sid.empty?

          map_path = File.join(SWARM_ROOT, sid, 'personas.json')
          map = File.file?(map_path) ? JSON.parse(File.read(map_path)) : {}
          agents = map.map { |name, sess| { name: name, session_id: sess } }
          claims = Dir[File.join(SWARM_ROOT, sid, '*.claim')].filter_map do |path|
            JSON.parse(File.read(path), symbolize_names: true)
          rescue StandardError
            nil
          end
          { swarm_id: sid, agents: agents, claims: claims }
        end

        public_class_method def self.migrate_personas(opts = {})
          path = opts[:path].to_s
          path = AGENTS_FILE if path.empty?
          return { changed: false, path: path, patched: [] } unless File.file?(path)

          raw = YAML.safe_load_file(
            path,
            permitted_classes: [Symbol],
            aliases: true,
            symbolize_names: true
          )
          return { changed: false, path: path, patched: [] } unless raw.is_a?(Hash)

          patched = []
          if raw[:escalator].is_a?(Hash)
            ts = Array(raw[:escalator][:toolsets]).map(&:to_s)
            if ts.sort == %w[memory pwn terminal]
              raw[:escalator][:toolsets] = []
              patched << 'escalator'
            end
          end
          if raw[:scribe].is_a?(Hash)
            ts = Array(raw[:scribe][:toolsets]).map(&:to_s)
            unless ts.include?('pwn')
              raw[:scribe][:toolsets] = ts + %w[pwn]
              patched << 'scribe'
            end
          end
          return { changed: false, path: path, patched: [] } if patched.empty?

          File.write(path, YAML.dump(deep_stringify(hash: raw)))
          { changed: true, path: path, patched: patched }
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Persona registry (~/.pwn/agents.yml)
            #{self}.personas(
              swarm_id: 'optional - merge ephemeral personas from this swarm'
            )

            # Run spawn and return its result
            #{self}.spawn(
              name: 'required - persona name (snake_case)',
              role: 'required - system_role_content overlay for this persona',
              toolsets: 'optional - Array of Registry toolset names',
              engine: 'optional - :openai / :anthropic / :grok / :gemini / :ollama / :openwebui',
              model: 'optional - exact model identifier (defaults to selected provider model)',
              max_iters: 'optional - per-turn iteration cap for this persona',
              skills: 'optional - Array of SOP skill names (capped at 3)',
              swarm_id: 'optional - write ephemeral persona under this swarm',
              ephemeral: 'optional - true to keep the persona off the host agents.yml',
              global: 'optional - true to write ~/.pwn/agents.yml even with swarm_id',
              orchestrator: 'optional - true to keep the swarm toolset'
            )

            # Run retire and return its result
            #{self}.retire(
              name: 'optional - binary or identifier name'
            )

            # Swarm lifecycle & bus
            #{self}.create(
              topic: 'optional - topic value consumed by #create'
            )

            # Run list and return its result
            #{self}.list

            # Run bus append and return its result
            #{self}.bus_append(
              swarm_id: 'required - required, from: required, content: required',
              to: 'optional - optional (default :all)',
              from: 'optional - sender account or address to bind as operator',
              content: 'optional - content value consumed by #bus_append'
            )

            # Run bus tail and return its result
            #{self}.bus_tail(
              swarm_id: 'optional - swarm id value consumed by #bus_tail',
              limit: 'optional - limit value consumed by #bus_tail'
            )

            # Core: run a single persona turn under Loop.run
            #{self}.ask(
              name: 'required - persona name from ~/.pwn/agents.yml',
              request: 'required - what to ask/instruct the persona',
              swarm_id: 'optional - join an existing swarm (created if omitted)',
              to: 'optional - addressee recorded on the bus (default :all)',
              on_tool: 'optional - ->(name, args, result) live-UI callback',
              from: 'optional - sender account or address to bind as operator (defaults to caller_label)',
              text_only: 'required - text only value consumed by #ask',
              unit: 'optional - claim key (host+phase) before the child runs',
              ttl: 'optional - claim TTL seconds (defaults to 300)',
              engagement_id: 'optional - claim namespace (defaults to swarm_id)'
            )

            # Run debate and return its result
            #{self}.debate(
              names: 'required - Array of persona names, order = speaking order',
              topic: 'required - opening question / claim',
              rounds: 'optional - full passes over names (default 2)',
              swarm_id: 'optional - join an existing swarm',
              on_tool: 'optional - ->(name, args, result) live-UI callback'
            )

            # Run broadcast and return its result
            #{self}.broadcast(
              request: 'required - required, names: optional - default all personas',
              swarm_id: 'optional - swarm id value consumed by #broadcast',
              names: 'required - Array names value consumed by #broadcast',
              on_tool: 'optional - on tool value consumed by #broadcast'
            )

            # TCP-connect map of hosts/CIDR tokens and ports (sequential).
            #{self}.map_targets(
              targets: 'required - comma/space separated hosts',
              ports: 'optional - comma/space separated ports (defaults to 80,443)'
            )

            # Append a typed engagement fact (port, cred, host, vuln).
            #{self}.fact_record(
              engagement_id: 'optional - engagement id (defaults to default)',
              kind: 'optional - port|cred|host|vuln (defaults to host)',
              value: 'required - fact value',
              source_session: 'optional - session id that discovered the fact',
              confidence: 'optional - 0.0..1.0 (defaults to 0.7)'
            )

            # One-line FACTS block for the system prompt.
            #{self}.facts_prompt(
              engagement_id: 'optional - engagement id (defaults to default)'
            )

            # Atomically claim a work unit (INSERT-or-fail until TTL).
            #{self}.claim(
              unit: 'required - normalized target+phase key',
              engagement_id: 'optional - engagement id (defaults to default)',
              ttl: 'optional - seconds until the claim expires (defaults to 300)',
              agent_id: 'optional - claimant id'
            )

            # Cap a child to 1-3 skills and drop swarm unless orchestrator.
            #{self}.pack_specialist(
              name: 'optional - specialist name',
              skills: 'optional - Array of SOP skill names (kept at most 3)',
              toolsets: 'optional - Registry toolset names',
              orchestrator: 'optional - true to keep the swarm toolset'
            )

            # Catalog of lead-spawned specialists (recon, authz, injection, xss, business_logic).
            #{self}.specialist_roles(
              name: 'optional - one role name; omit to return the full catalog'
            )

            # Write ephemeral specialist personas for a swarm without running Loop.
            #{self}.ensure_specialists(
              swarm_id: 'required - swarm id from #create'
            )

            # World-object inbox for a child session (finding ids, artifact shas).
            #{self}.child_inbox(
              session_id: 'optional - child PWN::Sessions id',
              name: 'optional - persona name'
            )

            # Honesty gap when a pwn child filed no findings and no artifacts.
            #{self}.child_honesty(
              name: 'optional - persona name',
              toolsets: 'optional - Array of toolset names',
              session_id: 'optional - child session id',
              skills: 'optional - Array of SOP skill names'
            )

            # Unmet tokens for parent Loop from child honesty gaps.
            #{self}.honesty_unmet(
              swarm_id: 'optional - swarm id whose children were recorded'
            )

            # Personas and live claims for a swarm (check before spawning).
            #{self}.view_graph(
              swarm_id: 'required - swarm id from #create'
            )

            # Patch stock escalator/scribe toolsets on an older agents.yml.
            #{self}.migrate_personas(
              path: 'optional - agents.yml path (defaults to ~/.pwn/agents.yml)'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
