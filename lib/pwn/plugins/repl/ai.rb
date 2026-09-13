# frozen_string_literal: true

require 'json'
require 'yaml'
require 'pry'
require 'reline'

module PWN
  module Plugins
    module REPL
      # pwn-ai REPL mode.
      module AI
        # Register Pry commands for this REPL mode.
        public_class_method def self.add_commands
          Pry::Commands.create_command 'pwn-ai' do
            description 'Initiate pwn.ai autonomous agent TUI (instruct tasks using PWN modules + CLI tools; memory/sessions/agents/cron/skills-aware from PWN::Config/PWN::Memory etc).'

            def process
              pi = pry_instance
              pi.config.pwn_ai = true
              pi.config.pwn_ai_agent = true
              pi.config.color = false if pi.config.pwn_ai

              # Switch to custom multi-line input for pwn-ai (SHIFT+ENTER newline, ENTER submit)
              pi.config.input = PWNMultiLineInput.new(pi)
              PWN::Plugins::REPL.install_pwn_ai_completer!(pry: pi)

              # Load and make aware of skills folder (scaled in PWN::Config per user pwn_env_path parent)
              skills_path = begin
                PWN::Config.pwn_skills_path
              rescue StandardError
                "#{Dir.home}/.pwn/skills"
              end
              PWN::ModuleSkills.install(pwn_skills_path: skills_path) if defined?(PWN::ModuleSkills) && PWN::ModuleSkills.respond_to?(:install)
              PWN::Config.load_skills(pwn_skills_path: skills_path)
              skills_count = (PWN.const_defined?(:Skills) ? PWN::Skills.keys.length : 0)

              # pwn-ai activation: initialise memory/sessions/cron stores
              PWN::Config.load_memory
              mem_count = (PWN.const_defined?(:Memory) ? PWN::Memory.load.keys.length : 0)
              sess = begin
                PWN::Plugins::REPL.pwn_ai_activation_session(pry: pi)
              rescue StandardError
                nil
              end
              pi.config.pwn_ai_session_id = sess[:id] if sess
              cron_count = (PWN.const_defined?(:Cron) ? PWN::Cron.list.keys.length : 0)

              puts '[*] pwn-ai agent TUI activated (PWN REPL driver w/ memory, sessions, delegation, cron).'
              puts "[*] Memory facts: #{mem_count} | Session: #{pi.config.pwn_ai_session_id} | Cron jobs: #{cron_count} | Skills: #{skills_count}"
              puts '[*] Instruct the AI agent to carry out a task, e.g.:'
              puts "    'Use NmapIt to port scan target.com then use TransparentBrowser to spider and SAST::TestCaseEngine to analyze code if cloned. Generate report with PWN::Reports.'"
              puts "    'Execute CLI nmap -sV target.com and summarize findings using PWN modules.'"
              puts "[*] Skills loaded from #{skills_path} (#{skills_count} available) + memory/sessions/cron to expand autonomous capabilities."
              puts "[*] Type 'back' or CTRL+D to exit pwn-ai mode."
              puts '[*] MULTILINE in pwn-ai: SHIFT+ENTER (or ALT+ENTER, or trailing `\\`) inserts a newline; ENTER submits to the AI.'
              puts '[*] TAB menus: leading `/` = commands (/cron /skills /sessions …); `/` later = host paths; otherwise Ruby completion (same as the pwn REPL).'
              puts "[*] tmux + terminator users: Ensure ~/.tmux.conf has 'set -s extended-keys on' and 'set -g xterm-keys on', then restart tmux. Use TERM=xterm-256color."
              tag = pi.config.pwn_ai_session_id.to_s.empty? ? '<SESSION_ID>' : pi.config.pwn_ai_session_id

              dbg_lvl = ''
              dbg_lvl = 'trace' if pi.config.pwn_ai_trace
              dbg_lvl = 'debug' if pi.config.pwn_ai_debug && !pi.config.pwn_ai_trace

              puts "\n\n\npwn-ai #{dbg_lvl} ON → ~/.pwn/logs/pwn-ai-DEBUG-#{tag}-R<REQUEST_NUMBER>.log" unless dbg_lvl.empty?
            end
          end

          Pry::Commands.create_command 'ai.profile' do
            description 'Select a session routing profile: ai.profile NAME (no args lists names).'

            def process
              PWN::Plugins::REPL.pwn_ai_profile_command(pry: pry_instance, args: args, output: output)
            end
          end

          Pry::Commands.create_command 'ai.memory' do
            description 'View/edit pinned engagement memory: ai.memory [view|edit TEXT|clear].'

            def process
              PWN::Plugins::REPL.pwn_ai_memory_command(pry: pry_instance, args: args, output: output)
            end
          end

          Pry::Commands.create_command 'pwn-ai-memory' do
            description 'Manage pwn-ai persistent memory.'

            def process
              cmd = args[0]
              case cmd
              when 'list', 'recall', nil
                q = args[1]
                res = PWN::Memory.recall(query: q)
                puts res.inspect
              when 'remember'
                key = args[1]
                val = args[2..].join(' ')
                PWN::Memory.remember(key: key, value: val)
                puts "Remembered #{key}"
              when 'forget'
                PWN::Memory.forget(key: args[1])
                puts "Forgot #{args[1]}"
              when 'clear'
                PWN::Memory.clear(force: true)
                puts 'Memory cleared'
              else
                puts PWN::Memory.help
              end
            end
          end

          Pry::Commands.create_command 'pwn-ai-sessions' do
            description 'List/resume/delete pwn-ai sessions.'

            def process
              cmd = args[0]
              case cmd
              when 'list', nil
                puts PWN::Sessions.list.inspect
              when 'resume'
                sid = args[1]
                hist = PWN::Sessions.to_response_history(session_id: sid)
                puts "Loaded session #{sid} with #{hist[:choices].size} entries (set manually into response_history if needed)"
              when 'delete'
                PWN::Sessions.delete(session_id: args[1], force: true)
                puts "Deleted #{args[1]}"
              when 'stats'
                puts PWN::Sessions.stats
              else
                puts PWN::Sessions.help
              end
            end
          end

          Pry::Commands.create_command 'pwn-ai-cron' do
            description 'Manage scheduled pwn-ai / cron jobs.'

            def process
              cmd = args[0]
              case cmd
              when 'list', nil
                puts PWN::Cron.list.inspect
              when 'create'
                # simplistic: pwn-ai-cron create '0 * * * *' 'prompt here'
                sched = args[1]
                pr = args[2..].join(' ')
                job = PWN::Cron.create(schedule: sched, prompt: pr)
                puts "Created #{job}"
              when 'run'
                res = PWN::Cron.run(id: args[1])
                puts res
              when 'remove'
                PWN::Cron.remove(id: args[1])
                puts 'Removed'
              else
                puts PWN::Cron.help
              end
            end
          end

          Pry::Commands.create_command 'pwn-ai-delegate' do
            description 'Delegate sub-task to a PWN::AI::Agent or simple sub-chat.'

            def process
              goal = args.join(' ')
              puts "[*] Delegating: #{goal}"
              # Simple delegation: use a specialized agent if matches, else another chat turn
              if goal =~ /sast|code|scan/i
                res = PWN::AI::Agent::SAST.analyze(request: goal)
              elsif goal =~ /vuln|report/i
                res = PWN::AI::Agent::VulnGen.analyze(request: goal)
              else
                # fallback sub call to active engine (no full loop here)
                engine = PWN::Env[:ai][:active].to_s.downcase.to_sym
                case engine
                when :anthropic then res = PWN::AI::Anthropic.chat(request: goal)
                when :gemini then res = PWN::AI::Gemini.chat(request: goal)
                when :grok then res = PWN::AI::Grok.chat(request: goal)
                else res = PWN::AI::Ollama.chat(request: goal)
                end
              end
              puts res
            end
          end
          Pry::Commands.create_command 'toggle-debug' do
            description 'Stream pwn-ai stage log to the TUI and ~/.pwn/logs/pwn-ai-DEBUG-<SESSION_ID>-RN.log'

            def process
              pi = pry_instance
              if pi.config.pwn_ai_debug
                path = PWN::Plugins::Log.stop_debug
                pi.config.pwn_ai_debug = false
                pi.config.pwn_ai_trace = false
                if path
                  output.puts "pwn-ai debug OFF (was #{path})"
                else
                  output.puts 'pwn-ai debug OFF'
                end
              else
                sid = pi.config.pwn_ai_session_id
                PWN::Plugins::Log.start_debug(tee: output, session_id: sid)
                pi.config.pwn_ai_debug = true
                output.puts 'pwn-ai debug ON.'
              end
            end
          end

          Pry::Commands.create_command 'toggle-trace' do
            description 'toggle-debug plus TracePoint; ENTER after each Loop step. Stored on Pry.config like toggle-debug, not Env.'

            def process
              pi = pry_instance
              if pi.config.pwn_ai_trace
                PWN::Plugins::Log.stop_debug
                pi.config.pwn_ai_debug = false
                pi.config.pwn_ai_trace = false
                output.puts 'pwn-ai trace OFF (debug OFF)'
              else
                sid = pi.config.pwn_ai_session_id
                PWN::Plugins::Log.start_debug(tee: output, session_id: sid, trace: true)
                pi.config.pwn_ai_debug = true
                pi.config.pwn_ai_trace = true
                output.puts 'pwn-ai trace ON (debug ON, TracePoint, ENTER each loop step)'
              end
            end
          end

          Pry::Commands.create_command 'toggle-pwn-ai-speaks' do
            description 'Use speech capabilities within pwn.ai to speak answers.'

            def process
              pi = pry_instance
              pi.config.pwn_ai_speak ? pi.config.pwn_ai_speak = false : pi.config.pwn_ai_speak = true
            end
          end
        end
        PWN_AI_SLASH_COMMANDS = %w[
          /back /cron /debug /delegate /help /learning /memory /mcp /model /sessions /skills /trace
        ].freeze

        PWN_AI_SLASH_SUBCOMMANDS = {
          '/cron' => %w[list create run remove],
          '/debug' => [],
          '/trace' => [],
          '/delegate' => [],
          '/help' => [],
          '/memory' => %w[list recall remember forget clear],
          '/mcp' => %w[list backends use current connect disconnect ping tools call status help],
          '/model' => %w[list],
          '/sessions' => %w[list resume delete stats],
          '/skills' => %w[list recall],
          '/learning' => %w[list requeue]
        }.freeze

        # Supported Method Parameters::
        # kind = PWN::Plugins::REPL.pwn_ai_complete_kind(line: 'optional - current input buffer')
        #
        # 1. first char is '/' → :command (pwn-ai slash menu)
        # 2. '/' anywhere else → :path (host-native file nav)
        # 3. else → :ruby (same Pry::InputCompleter menu as the pwn REPL)
        class << PWN::Plugins::REPL # rubocop:disable Metrics/ClassLength
          def pwn_ai_complete_kind(opts = {})
            line = opts[:line].to_s
            return :command if line.start_with?('/')
            return :path if line.include?('/') || line.include?('~')

            :ruby
          end

          # Supported Method Parameters::
          # hits = PWN::Plugins::REPL.pwn_ai_complete(
          #   target: 'required - token Reline is completing',
          #   line: 'optional - full line buffer',
          #   pry: 'optional - Pry instance for Ruby completion'
          # )
          def pwn_ai_complete(opts = {})
            target = opts[:target].to_s
            line = opts[:line].to_s
            line = target if line.empty?
            kind = pwn_ai_complete_kind(line: line)
            case kind
            when :command
              pwn_ai_complete_command(target: target, line: line)
            when :path
              pwn_ai_complete_path(target: target, line: line)
            else
              pwn_ai_complete_ruby(target: target, pry: opts[:pry])
            end
          end

          def pwn_ai_complete_command(opts = {})
            line = opts[:line].to_s
            target = opts[:target].to_s
            tokens = line.split(/\s+/, -1)
            tokens = [''] if tokens.empty?
            if tokens.length <= 1
              prefix = tokens.first.to_s
              prefix = '/' if prefix.empty?
              return PWN_AI_SLASH_COMMANDS.select { |c| c.start_with?(prefix) }
            end

            cmd = tokens.first
            sub_prefix = tokens.last.to_s
            if cmd == '/model'
              engines = pwn_ai_engines
              if tokens.length == 2
                pool = (%w[list] + engines)
                return pool.select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) }
              end
              return %w[llms].select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) } if tokens.length == 3 && tokens[1] == 'list'

              if tokens.length >= 3
                current = pwn_ai_engine_model(engine: tokens[1]).to_s
                hits = [current].reject(&:empty?).select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) }
                return hits unless hits.empty?
              end
            end
            if cmd == '/mcp'
              backends = begin
                PWN::AI::MCP.backends.map { |row| row[:name].to_s }
              rescue StandardError
                []
              end
              if tokens.length == 2
                pool = (Array(PWN_AI_SLASH_SUBCOMMANDS['/mcp']) + backends).uniq
                return pool.select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) }
              end
              return %w[tools].select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) } if tokens.length == 3 && tokens[1] == 'list'

              named = backends.include?(tokens[1])
              action = named ? tokens[2] : tokens[1]
              return Array(PWN_AI_SLASH_SUBCOMMANDS['/mcp']).select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) } if named && tokens.length == 3
              return backends.select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) } if tokens.length >= 3 && %w[use connect disconnect ping tools status].include?(tokens[1])

              if action == 'call' && ((named && tokens.length == 4) || (!named && tokens.length == 3))
                selected = named ? tokens[1] : PWN::AI::MCP.current.to_s
                tools = if selected.empty?
                          backends.flat_map do |name|
                            row = PWN::AI::MCP.backends.find { |backend| backend[:name] == name }
                            Array(row && row[:tools])
                          end
                        else
                          row = PWN::AI::MCP.backends.find { |backend| backend[:name] == selected }
                          Array(row && row[:tools])
                        end
                return tools.uniq.map(&:to_s).select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) }
              end
            end
            subs = Array(PWN_AI_SLASH_SUBCOMMANDS[cmd])
            hits = subs.select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) }
            hits = [target] if hits.empty? && !target.empty?
            hits
          end

          def pwn_ai_complete_path(opts = {})
            target = opts[:target].to_s
            line = opts[:line].to_s
            token = line.split(/\s+/, -1).last.to_s
            token = target if token.empty?
            return [] if token.empty?

            home = Dir.home
            glob_src = token.sub(%r{\A~(?=/|\z)}, home)
            pattern = token.end_with?('/') ? File.join(glob_src, '*') : "#{glob_src}*"
            Dir.glob(pattern).filter_map do |path|
              shown = if token.start_with?('~/') || token == '~'
                        path.sub(/\A#{Regexp.escape(home)}/, '~')
                      else
                        path
                      end
              shown = "#{shown}/" if File.directory?(path)
              shown
            end
          rescue StandardError
            []
          end

          def pwn_ai_complete_ruby(opts = {})
            target = opts[:target].to_s
            pry = opts[:pry] || Thread.current[:pwn_ai_completer_pry]
            return [] unless defined?(Pry::InputCompleter)

            return Array(pry.complete(target)) if pry.respond_to?(:complete)

            Array(Pry::InputCompleter.new(pry || Pry.new(quiet: true)).call(target))
          rescue StandardError
            []
          end

          # Install Reline dropdown for pwn-ai (commands / paths / Ruby).
          def install_pwn_ai_completer!(opts = {})
            return unless defined?(Reline)

            Thread.current[:pwn_ai_completer_pry] = opts[:pry]
            @pwn_ai_prev_completion_proc = Reline.completion_proc
            if Reline.respond_to?(:completer_word_break_characters)
              @pwn_ai_prev_word_break = Reline.completer_word_break_characters
              # Keep '/' inside the token so /cron and /opt/pwn complete as paths/cmds.
              Reline.completer_word_break_characters = Reline.completer_word_break_characters.to_s.delete('/')
            end
            Reline.autocompletion = true
            Reline.completion_proc = proc do |target|
              line = Reline.respond_to?(:line_buffer) ? Reline.line_buffer.to_s : target.to_s
              pwn_ai_complete(
                target: target,
                line: line,
                pry: Thread.current[:pwn_ai_completer_pry]
              )
            end
            Reline.completion_proc
          end

          def restore_pwn_ai_completer!(opts = {})
            return unless defined?(Reline)

            Thread.current[:pwn_ai_completer_pry] = nil
            Reline.completion_proc = @pwn_ai_prev_completion_proc if @pwn_ai_prev_completion_proc
            Reline.completer_word_break_characters = @pwn_ai_prev_word_break if @pwn_ai_prev_word_break && Reline.respond_to?(:completer_word_break_characters=)
            PWN::Plugins::REPL.enable_autocomplete(enabled: opts.fetch(:enabled, true))
            Reline.completion_proc
          end

          def pwn_ai_activation_session(opts = {})
            config = opts[:pry].config
            sid = config.pwn_ai_startup_session_id
            config.pwn_ai_startup_session_id = nil
            return { id: sid } if sid

            PWN::Sessions.create(title: "pwn-ai #{Time.now.strftime('%Y-%m-%d %H:%M')}", source: 'pwn-ai')
          end

          # Validate selection before changing request-local routing state.
          def pwn_ai_profile_command(opts = {})
            require 'pwn/ai/agent/profiles'
            env = opts[:env] || PWN::Env
            profiles = env[:ai_profiles] || {}
            router = PWN::AI::Agent::Profiles.new(profiles: profiles)
            args = Array(opts[:args])
            output = opts[:output] || $stdout
            if args.empty?
              output.puts("AI profiles: #{profiles.keys.map(&:to_s).sort.join(', ')}")
              return profiles.keys.map(&:to_s).sort
            end
            raise ArgumentError, 'Usage: ai.profile NAME' unless args.length == 1

            route = router.lookup(name: args.first)
            opts.fetch(:pry).config.pwn_ai_profile = args.first.to_s
            output.puts("AI profile: #{route[:name]} (#{route[:provider]} / #{route[:model]})")
            route
          end

          # View/edit the session's pinned block, separate from cross-session facts.
          def pwn_ai_memory_command(opts = {})
            require 'pwn/ai/agent/engagement_memory'
            sid = opts[:pry]&.config&.pwn_ai_session_id.to_s
            raise ArgumentError, 'Start pwn-ai before using ai.memory' if sid.empty?

            goal = PWN::Sessions.load(session_id: sid).find { |entry| entry[:role].to_s == 'user' }
            settings = { original_goal: goal ? goal[:content] : '', session_id: sid }
            settings[:root] = opts[:root] if opts[:root]
            memory = PWN::AI::Agent::EngagementMemory.new(**settings)
            args = Array(opts[:args])
            case args.first
            when nil, 'view'
              text = memory.view
            when 'edit'
              raise ArgumentError, 'Usage: ai.memory edit TEXT (or ai.memory clear)' if args.length < 2

              text = memory.edit(text: args.drop(1).join(' '))
            when 'clear'
              text = memory.edit(text: '')
            else
              raise ArgumentError, 'Usage: ai.memory [view|edit TEXT|clear]'
            end
            (opts[:output] || $stdout).puts(text)
            text
          end

          # Run a leading-slash pwn-ai command locally. Returns true when handled
          # (caller should not send the line to Loop.run).
          def pwn_ai_dispatch_slash!(opts = {})
            request = opts[:request].to_s
            if request.strip.match?(/\Aai\.profile(?:\s|$)/)
              pwn_ai_profile_command(pry: opts[:pry], args: request.strip.split(/\s+/).drop(1))
              return true
            end
            if request.strip.match?(/\Aai\.memory(?:\s|$)/)
              pwn_ai_memory_command(pry: opts[:pry], args: request.strip.split(/\s+/).drop(1))
              return true
            end
            return false unless pwn_ai_complete_kind(line: request) == :command

            tokens = request.strip.split(/\s+/)
            cmd = tokens[0].to_s
            return false unless PWN_AI_SLASH_COMMANDS.include?(cmd)

            args = tokens[1..]
            pi = opts[:pry]
            case cmd
            when '/help'
              puts 'pwn-ai commands:'
              PWN_AI_SLASH_COMMANDS.each do |c|
                subs = Array(PWN_AI_SLASH_SUBCOMMANDS[c])
                puts(subs.empty? ? "  #{c}" : "  #{c} #{subs.join('|')}")
              end
              puts '  TAB: /… command menu · slash later in the line: path nav · else Ruby completion'
            when '/back'
              if pi.respond_to?(:eval)
                pi.eval('back')
              else
                puts "[*] Type 'back' to leave pwn-ai."
              end
            when '/debug'
              if pi.respond_to?(:eval)
                pi.eval('toggle-debug')
              else
                puts '[*] toggle-debug'
              end
            when '/trace'
              if pi.respond_to?(:eval)
                pi.eval('toggle-trace')
              else
                puts '[*] toggle-trace'
              end
            when '/cron'
              pwn_ai_run_cron(args: args)
            when '/sessions'
              pwn_ai_run_sessions(args: args)
            when '/memory'
              pwn_ai_run_memory(args: args)
            when '/skills'
              pwn_ai_run_skills(args: args)
            when '/delegate'
              puts "[*] Delegating: #{args.join(' ')}"
              puts '    Use agent_list / agent_debate from pwn-ai, or pwn-ai-delegate in the pwn REPL.'
            when '/model'
              pwn_ai_run_model(args: args)
            when '/mcp'
              pwn_ai_run_mcp(args: args)
            when '/learning'
              pwn_ai_run_learning(args: args)
            end
            true
          rescue StandardError => e
            warn "[pwn-ai] #{cmd}: #{e.class}: #{e.message}"
            true
          end

          def pwn_ai_engines(opts = {})
            return [] unless opts.is_a?(Hash)

            tmpl = {}
            tmpl = PWN::Config.env_template[:ai] if defined?(PWN::Config) && PWN::Config.respond_to?(:env_template)
            keys = tmpl.select { |_k, v| v.is_a?(Hash) && v.key?(:model) }.keys.map(&:to_s)
            if defined?(PWN::Env) && PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash)
              PWN::Env[:ai].each do |k, v|
                next unless v.is_a?(Hash)
                next if %i[agent driver_opts].include?(k.to_sym)

                keys << k.to_s if v.key?(:model) || v.key?(:key) || v.key?(:base_uri)
              end
            end
            keys.uniq.sort
          end

          def pwn_ai_provider_class(opts = {})
            engine = opts[:engine].to_s.downcase
            map = {
              'anthropic' => 'Anthropic',
              'gemini' => 'Gemini',
              'grok' => 'Grok',
              'ollama' => 'Ollama',
              'openai' => 'OpenAI',
              'openwebui' => 'OpenWebUI'
            }
            name = map[engine]
            return nil if name.nil? || !defined?(PWN::AI) || !PWN::AI.const_defined?(name)

            PWN::AI.const_get(name)
          end

          def pwn_ai_model_ids(opts = {})
            raw = opts[:models]
            rows = case raw
                   when Array then raw
                   when Hash then raw[:data] || raw[:models] || raw['data'] || raw['models'] || []
                   else []
                   end
            Array(rows).filter_map do |row|
              if row.is_a?(Hash)
                row[:id] || row['id'] || row[:slug] || row['slug'] || row[:name] || row['name'] || row[:model] || row['model']
              else
                row.to_s
              end
            end.map(&:to_s).reject(&:empty?).uniq
          end

          def pwn_ai_list_llms(opts = {})
            engine = opts[:engine].to_s
            engine = PWN::Env.dig(:ai, :active).to_s if engine.empty? && defined?(PWN::Env)
            raise 'no active engine — /model <engine> first' if engine.empty?

            klass = pwn_ai_provider_class(engine: engine)
            raise "#{engine} has no PWN::AI provider with get_models" unless klass.respond_to?(:get_models)

            ids = pwn_ai_model_ids(models: klass.get_models)
            puts "[*] #{engine} llms (#{ids.length})"
            ids.each { |id| puts id }
            ids
          end

          def pwn_ai_engine_model(opts = {})
            engine = opts[:engine].to_s.downcase.to_sym
            return '' if engine.empty?
            return '' unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

            PWN::Env.dig(:ai, engine, :model).to_s
          end

          def pwn_ai_run_model(opts = {})
            args = Array(opts[:args]).map(&:to_s)
            engines = pwn_ai_engines
            current = defined?(PWN::Env) && PWN::Env.is_a?(Hash) ? PWN::Env.dig(:ai, :active).to_s : ''
            current_model = pwn_ai_engine_model(engine: current)
            sub = args[0].to_s
            if sub.empty? || %w[show status].include?(sub)
              msg = "active=#{current.empty? ? '(none)' : current} model=#{current_model.empty? ? '(unset)' : current_model}"
              puts "[*] #{msg}"
              return msg
            end
            if %w[list help].include?(sub)
              return pwn_ai_list_llms(engine: current) if args[1].to_s == 'llms'

              puts 'pwn-ai /model — switch provider and model in this session'
              puts "  current: #{current} #{current_model}"
              puts '  usage: /model [list] | /model list llms | /model <engine> [model] | /model <model>'
              engines.each do |eng|
                mark = eng == current ? '*' : ' '
                puts "  #{mark} #{eng}  #{pwn_ai_engine_model(engine: eng)}"
              end
              return engines
            end

            engine = nil
            model = nil
            if engines.include?(sub)
              engine = sub
              model = args[1..].join(' ')
              model = nil if model.strip.empty?
            else
              engine = current
              model = args.join(' ')
            end
            raise "no active engine — /model <engine> first (#{engines.join(', ')})" if engine.to_s.empty?
            raise "unknown engine #{engine.inspect} — try: #{engines.join(', ')}" unless engines.include?(engine.to_s)

            PWN::Env[:ai] ||= {}
            PWN::Env[:ai][engine.to_sym] ||= {}
            PWN::Env[:ai][:active] = engine.to_s
            PWN::Env[:ai][engine.to_sym][:model] = model unless model.to_s.strip.empty?
            persisted = persist_ai_selection(engine: engine, model: PWN::Env[:ai][engine.to_sym][:model])
            shown = PWN::Env[:ai][engine.to_sym][:model]
            msg = "active=#{engine} model=#{shown.to_s.empty? ? '(unset)' : shown}"
            msg = "#{msg} (session only)" unless persisted
            puts "[*] #{msg}"
            msg
          end

          def persist_ai_selection(opts = {})
            engine = opts[:engine].to_s
            model = opts[:model]
            return false if engine.empty?

            env_path = nil
            dec_path = nil
            if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
              env_path = PWN::Env.dig(:driver_opts, :pwn_env_path)
              dec_path = PWN::Env.dig(:driver_opts, :pwn_dec_path)
            end
            env_path = env_path.to_s.strip
            env_path = File.join(Dir.home, '.pwn', 'pwn.yaml') if env_path.empty?
            dec_path = dec_path.to_s.strip
            dec_path = "#{env_path}.decryptor" if dec_path.empty?
            return false unless File.exist?(env_path) && File.exist?(dec_path) && File.readable?(dec_path)

            decryptor = YAML.load_file(dec_path, symbolize_names: true)
            key = decryptor.is_a?(Hash) ? decryptor[:key] : nil
            iv = decryptor.is_a?(Hash) ? decryptor[:iv] : nil
            return false if key.to_s.strip.empty? || iv.to_s.strip.empty?

            PWN::Plugins::Vault.decrypt(file: env_path, key: key, iv: iv)
            begin
              cfg = YAML.load_file(env_path, symbolize_names: true)
              cfg = {} unless cfg.is_a?(Hash)
              cfg[:ai] = {} unless cfg[:ai].is_a?(Hash)
              cfg[:ai][:active] = engine
              unless model.to_s.strip.empty?
                slot = engine.to_sym
                cfg[:ai][slot] = {} unless cfg[:ai][slot].is_a?(Hash)
                cfg[:ai][slot][:model] = model
              end
              yaml_env = YAML.dump(cfg).gsub(/^(\s*):/, '\1')
              File.write(env_path, yaml_env)
              File.chmod(0o600, env_path)
            ensure
              PWN::Plugins::Vault.encrypt(file: env_path, key: key, iv: iv)
            end
            true
          rescue StandardError => e
            warn "[pwn-ai] /model persist skipped: #{e.class}: #{e.message}"
            false
          end

          def pwn_ai_run_cron(opts = {})
            args = Array(opts[:args])
            sub = args[0] || 'list'
            case sub
            when 'list'
              puts PWN::Cron.list.inspect
            when 'create'
              job = PWN::Cron.create(schedule: args[1], prompt: args[2..].join(' '))
              puts "Created #{job}"
            when 'run'
              puts PWN::Cron.run(id: args[1])
            when 'remove'
              PWN::Cron.remove(id: args[1])
              puts 'Removed'
            else
              puts PWN::Cron.help
            end
          end

          def pwn_ai_run_sessions(opts = {})
            args = Array(opts[:args])
            sub = args[0] || 'list'
            case sub
            when 'list'
              puts PWN::Sessions.list.inspect
            when 'resume'
              sid = args[1]
              hist = PWN::Sessions.to_response_history(session_id: sid)
              puts "Loaded session #{sid} with #{hist[:choices].size} entries"
            when 'delete'
              PWN::Sessions.delete(session_id: args[1], force: true)
              puts "Deleted #{args[1]}"
            when 'stats'
              puts PWN::Sessions.stats
            else
              puts PWN::Sessions.help
            end
          end

          def pwn_ai_run_memory(opts = {})
            args = Array(opts[:args])
            sub = args[0] || 'list'
            case sub
            when 'list', 'recall'
              puts PWN::Memory.recall(query: args[1]).inspect
            when 'remember'
              PWN::Memory.remember(key: args[1], value: args[2..].join(' '))
              puts "Remembered #{args[1]}"
            when 'forget'
              PWN::Memory.forget(key: args[1])
              puts "Forgot #{args[1]}"
            when 'clear'
              PWN::Memory.clear(force: true)
              puts 'Memory cleared'
            else
              puts PWN::Memory.help
            end
          end

          def pwn_ai_run_learning(opts = {})
            args = Array(opts[:args])
            sub = args[0] || 'list'
            case sub
            when 'list'
              flag = args.include?('--conflicted') || args.include?('conflicted')
              rows = flag ? PWN::AI::Agent::Learning.list_conflicted : PWN::AI::Agent::Learning.outcomes(limit: 20)
              puts rows.inspect
            when 'requeue'
              puts PWN::AI::Agent::Learning.requeue_conflicted.inspect
            else
              puts 'Usage: /learning [list [--conflicted]|requeue]'
            end
          end

          def pwn_ai_run_skills(opts = {})
            args = Array(opts[:args])
            sub = args[0] || 'list'
            names = if PWN.const_defined?(:Skills)
                      PWN::Skills.keys.map(&:to_s)
                    else
                      []
                    end
            case sub
            when 'list'
              puts names.sort
            when 'recall'
              q = args[1].to_s
              hits = names.select { |n| n.include?(q) }
              puts(hits.empty? ? names.sort : hits.sort)
            else
              puts 'Usage: /skills [list|recall <query>]'
            end
          end

          # Run pwn-ai /mcp locally without sending the line through Loop.run.

          def pwn_ai_run_mcp(opts = {})
            args = Array(opts[:args]).map(&:to_s)
            backends = begin
              PWN::AI::MCP.backends.map { |row| row[:name].to_s }
            rescue StandardError
              []
            end
            backend = nil
            if backends.include?(args[0].to_s)
              backend = args[0]
              args = args[1..]
            end
            sub = args[0].to_s
            rest = args[1..]
            sub = 'use' if backend && sub.empty?
            if sub.empty? || sub == 'help'
              puts 'pwn-ai /mcp — local MCP session broker for every PWN::AI::MCP::* client'
              puts '  usage: /mcp [list|backends|use|current|connect|disconnect|ping|tools|call|status|help]'
              puts '         /mcp <backend> [connect|disconnect|ping|tools|call|status]'
              puts '         /mcp use <backend>'
              puts '         /mcp call <tool> [key=value|{"k":"v"}]'
              result = PWN::AI::MCP.invoke(action: 'backends')
              current = PWN::AI::MCP.current
              Array(result[:backends]).each do |row|
                mark = row[:name] == current ? '*' : ' '
                puts "  #{mark} #{row[:name]}  #{row[:constant]}"
              end
              return result.merge(current: current)
            end

            hardware = rest.intersect?(%w[hardware --hardware --mcp-allow-hardware])
            rest = rest.reject { |tok| %w[hardware --hardware --mcp-allow-hardware].include?(tok) }
            payload =
              case sub
              when 'list'
                rest[0].to_s == 'tools' ? { action: 'list_tools', backend: rest[1] || backend } : { action: 'backends' }
              when 'backends'
                { action: 'backends' }
              when 'use'
                { action: 'use', backend: rest[0] || backend }
              when 'current'
                { action: 'current' }
              when 'connect'
                { action: 'connect', backend: rest[0] || backend, allow_hardware: hardware }
              when 'disconnect', 'close'
                { action: 'disconnect', backend: rest[0] || backend }
              when 'ping'
                { action: 'ping', backend: rest[0] || backend }
              when 'tools'
                { action: 'list_tools', backend: rest[0] || backend }
              when 'status'
                { action: 'status', backend: rest[0] || backend }
              when 'call'
                name = rest[0].to_s
                raise ArgumentError, 'usage: /mcp call <tool> [key=value]' if name.empty?

                { action: 'call_tool', backend: backend, name: name }.merge(pwn_ai_mcp_call_args(tokens: rest[1..]))
              else
                raise ArgumentError, "unknown /mcp #{sub.inspect}"
              end
            payload[:backend] = payload[:backend].to_s
            payload.delete(:backend) if payload[:backend].empty?
            result = PWN::AI::MCP.invoke(payload)
            puts result.inspect
            result
          end

          def pwn_ai_mcp_call_args(opts = {})
            tokens = Array(opts[:tokens]).map(&:to_s)
            joined = tokens.join(' ').strip
            if joined.start_with?('{')
              parsed = JSON.parse(joined)
              raise ArgumentError, 'JSON call args must be an object' unless parsed.is_a?(Hash)

              return { arguments: parsed }
            end

            arguments = {}
            tokens.each do |tok|
              next unless tok.include?('=')

              key, value = tok.split('=', 2)
              arguments[key] = pwn_ai_mcp_coerce(value: value)
            end
            arguments.empty? ? {} : { arguments: arguments }
          end

          def pwn_ai_mcp_coerce(opts = {})
            value = opts[:value].to_s
            return value if value.match?(/\A\d+\.\d+\z/)
            return true if value == 'true'
            return false if value == 'false'
            return Integer(value) if value.match?(/\A-?\d+\z/)

            value
          end

          private :pwn_ai_mcp_call_args, :pwn_ai_mcp_coerce
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display usage for this module.

        public_class_method def self.help
          puts "USAGE:
            # Register pwn-ai Pry commands and debug toggles.
            #{self}.add_commands

            # Classify pwn-ai TAB completion as command, path, or Ruby.
            #{self}.pwn_ai_complete_kind(
              line: 'optional - full line buffer used to classify completion'
            )

            # TAB hits for pwn-ai slash commands, host paths, or Ruby.
            #{self}.pwn_ai_complete(
              target: 'required - token Reline is completing',
              line: 'optional - full line buffer',
              pry: 'optional - Pry instance for Ruby completion'
            )

            # TAB hits for leading-slash pwn-ai commands.
            #{self}.pwn_ai_complete_command(
              line: 'optional - full line buffer',
              target: 'required - token Reline is completing'
            )

            # TAB hits for host paths when slash is not first.
            #{self}.pwn_ai_complete_path(
              target: 'required - path prefix to complete',
              line: 'optional - full line buffer'
            )

            # TAB hits for Ruby constants and methods in pwn-ai.
            #{self}.pwn_ai_complete_ruby(
              target: 'optional - token Reline is completing',
              pry: 'optional - Pry instance (defaults to Thread.current[:pwn_ai_completer_pry])'
            )

            # Install Reline dropdown for pwn-ai (commands / paths / Ruby).
            #{self}.install_pwn_ai_completer!(
              pry: 'optional - Pry instance stored for pwn-ai TAB completion'
            )

            # Restore Pry Ruby completion after leaving pwn-ai.
            #{self}.restore_pwn_ai_completer!

            # Consume a prepared CLI session or create a new interactive session.
            #{self}.pwn_ai_activation_session(pry: 'required - Pry instance')

            # Validate/select a named model profile without changing provider defaults.
            #{self}.pwn_ai_profile_command(
              pry: 'required - Pry instance', args: ['profile-name'],
              env: 'optional - configuration hash', output: 'optional - output IO'
            )

            # View/edit the current session pinned engagement notes.
            #{self}.pwn_ai_memory_command(
              pry: 'required - Pry instance', args: ['edit', 'evidence notes'],
              root: 'optional - artifacts root', output: 'optional - output IO'
            )

            # Run a leading-slash pwn-ai command locally. Returns true when handled.
            #{self}.pwn_ai_dispatch_slash!(
              request: 'optional - full line such as /skills list',
              pry: 'optional - Pry instance used by /back'
            )

            # List configured pwn-ai engine names.
            #{self}.pwn_ai_engines

            # Resolve the provider class for an engine name.
            #{self}.pwn_ai_provider_class(
              engine: 'optional - engine name such as ollama or openai'
            )

            # Normalize provider catalog hashes into model id strings.
            #{self}.pwn_ai_model_ids(
              models: 'optional - catalog payload from a provider list call'
            )

            # List LLM ids for an engine including Codex slug catalogs.
            #{self}.pwn_ai_list_llms(
              engine: 'required - engine name such as openai or ollama'
            )

            # Return the currently selected model string for an engine.
            #{self}.pwn_ai_engine_model(
              engine: 'required - engine name such as ollama'
            )

            # Apply /model arguments to the active engine.
            #{self}.pwn_ai_run_model(
              args: 'optional - Array of slash tokens after /model'
            )

            # Persist engine and model into the encrypted pwn.yaml vault.
            #{self}.persist_ai_selection(
              engine: 'required - engine name to store as ai.active',
              model: 'required - model id to store for that engine'
            )

            # Run /cron locally without Loop.run.
            #{self}.pwn_ai_run_cron(
              args: 'optional - Array of slash tokens after /cron'
            )

            # Run /sessions locally without Loop.run.
            #{self}.pwn_ai_run_sessions(
              args: 'optional - Array of slash tokens after /sessions'
            )

            # Run /memory locally without Loop.run.
            #{self}.pwn_ai_run_memory(
              args: 'optional - Array of slash tokens after /memory'
            )

            # List or requeue conflicted learning outcomes.
            #{self}.pwn_ai_run_learning(
              args: 'optional - list [--conflicted] or requeue'
            )

            # Run /skills locally without Loop.run.
            #{self}.pwn_ai_run_skills(
              args: 'optional - Array of slash tokens after /skills'
            )

            # Run /mcp locally without Loop.run.
            #{self}.pwn_ai_run_mcp(
              args: 'optional - slash tokens after /mcp such as list tools'
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
