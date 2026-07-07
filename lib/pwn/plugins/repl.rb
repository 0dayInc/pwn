# frozen_string_literal: true

require 'curses'
require 'fileutils'
require 'meshtastic'
require 'pry'
require 'reline'
require 'tty-prompt'
require 'unicode/display_width'
require 'yaml'

module PWN
  module Plugins
    # This module contains methods related to the pwn REPL Driver.
    module REPL
      # Custom input handler for pwn-ai and pwn-asm to support multi-line
      # submissions:
      # - Use *only* SHIFT+ENTER to insert a newline (continue editing).
      # - Plain ENTER submits the full (possibly multi-line) buffer.
      # - Multi-line pastes are supported (Reline handles \n in buffer; submit with ENTER).
      # Strict SHIFT+ENTER only — no Ctrl+J, Alt-Enter, or other fallbacks (per requirements).
      class PWNMultiLineInput
        attr_reader :line_buffer

        # SHIFT+ENTER escape sequences (byte arrays). These are terminal-dependent.
        # Listed common ones for xterm, VTE (terminator), kitty, wezterm, etc.
        # (with modifyOtherKeys / extended-keys enabled).
        #
        # For tmux + terminator (or similar):
        #   In ~/.tmux.conf (then `tmux kill-server` + new session):
        #     set -s extended-keys on
        #     set -g xterm-keys on
        #   Use TERM=xterm-256color (or equivalent that supports the CSI) in your terminal profile.
        #
        # The bindings make matching sequences produce :key_newline (insert \n without submit).
        #
        # If after typing text + SHIFT+ENTER it still submits instead of newline:
        #   1. Apply the tmux.conf + TERM changes above and fully restart tmux.
        #   2. In your *real* terminal (the one running `pwn`), run a capture script from /tmp ONLY:
        #        ruby /tmp/capture_keys.rb
        #      (Debugging scripts must live in /tmp per user rule; never commit them to /opt/pwn.)
        #   3. Paste the exact bytes array for the SHIFT+ENTER press here so it can be added to the list.
        SHIFT_ENTER_SEQS = [
          [27, 91, 49, 51, 59, 50, 126],             # \e[13;2~
          [27, 91, 50, 55, 59, 50, 59, 49, 51, 126], # \e[27;2;13~
          [27, 91, 49, 51, 59, 50, 117],             # \e[13;2u (CSI u)
          [27, 91, 50, 55, 59, 50, 59, 49, 51, 117], # \e[27;2;13u
          [27, 91, 49, 59, 50, 126],                 # \e[1;2~
          [27, 13],                                  # \e\r (ESC+CR variant)
          [27, 10],                                  # \e\n (ESC+LF variant)
          [27, 91, 13, 59, 50, 126],                 # \e[13;2~ alt numeric
          [27, 91, 49, 59, 50, 117],                 # \e[1;2u
          [27, 91, 50, 55, 59, 50, 13, 126],         # \e[27;2;13~ variant
          [27, 79, 77]                               # \eOM (application-keypad Enter; some emulators emit this for S-Enter)
        ].freeze

        # CSI sequences that ask the terminal to start/stop encoding
        # Shift+Enter (and other modified keys) distinctly from plain Enter.
        # Without one of these active, most emulators send the SAME byte
        # (0x0D) for both, so SHIFT_ENTER_SEQS can never match.
        #
        #   \e[>4;1m / \e[>4;0m   xterm modifyOtherKeys on/off (level 1 —
        #                         disambiguates Shift+Enter without altering
        #                         Ctrl-C). xterm, VTE/Terminator, iTerm2,
        #                         Konsole. tmux ≥3.2 with `extended-keys on`
        #                         honours this request and re-encodes as
        #                         CSI-u to the inner app.
        #   \e[>1u   / \e[<u      kitty keyboard protocol push/pop, flags=1
        #                         "disambiguate escape codes". kitty, wezterm,
        #                         foot, ghostty, alacritty, recent tmux.
        #
        # Emitting both is harmless on terminals that support neither —
        # they're DEC-private CSIs and get silently ignored.
        ENABLE_EXTENDED_KEYS  = "\e[>4;1m\e[>1u"
        DISABLE_EXTENDED_KEYS = "\e[<u\e[>4;0m"

        def initialize(pry_instance)
          @line_buffer = ''
          pry_instance.config.pwn_ai_original_input = Pry.input
          ensure_tmux_extended_keys
          install_shift_enter_bindings
        end

        # Reline ≤ 0.5.x exposed a top-level `Reline.config` delegator.
        # Reline ≥ 0.6.x removed it; the Config object now lives only on
        # the (private) singleton `Reline.core`. Probe in order of
        # preference so the same code works across both.
        def reline_config
          return Reline.config if Reline.respond_to?(:config)
          return Reline.core.config if Reline.respond_to?(:core)

          Reline.send(:core).config
        end

        # tmux gates modifyOtherKeys / kitty-keyboard requests behind its
        # `extended-keys` *server* option. When `off` (the shipped default
        # on many distros / older ~/.tmux.conf), tmux silently drops the
        # ENABLE_EXTENDED_KEYS CSI we emit in #readline and forwards plain
        # 0x0D for BOTH Enter and Shift+Enter — SHIFT_ENTER_SEQS can then
        # never match and Shift+Enter "still just submits".
        #
        # Detect tmux via $TMUX, read the current server option, and flip it
        # to `on` (NOT `always`) so tmux honours the per-read enable/disable
        # we send around Reline.readmultiline. `on` is scoped: tmux only
        # encodes extended keys while the inner app is requesting them, so
        # this does not affect other panes or the main pwn REPL.
        #
        # Verified on tmux 3.6b: `extended-keys on` + `\e[>4;1m` → S-Enter is
        # delivered as `\e[27;2;13~` (matches SHIFT_ENTER_SEQS[1]).
        def ensure_tmux_extended_keys
          return if self.class.instance_variable_get(:@tmux_extkeys_checked)

          self.class.instance_variable_set(:@tmux_extkeys_checked, true)
          return if ENV['TMUX'].to_s.empty?

          # (1) Inner side: tmux → app. `extended-keys on` makes tmux honour the
          #     ENABLE_EXTENDED_KEYS request we emit in #readline and re-encode
          #     S-Enter to the pane as CSI 27;2;13~ / CSI 13;2u.
          cur = `tmux show -sv extended-keys 2>/dev/null`.to_s.strip
          unless %w[on always].include?(cur)
            if system('tmux', 'set', '-s', 'extended-keys', 'on', out: File::NULL, err: File::NULL)
              warn '[pwn] tmux `extended-keys` was off; auto-enabled (server scope) so SHIFT+ENTER is distinguishable from ENTER.'
              warn '[pwn] Persist it: add `set -s extended-keys on` to ~/.tmux.conf'
            else
              warn '[pwn] tmux `extended-keys` is off and could not be enabled; SHIFT+ENTER will behave like ENTER.'
              warn '[pwn] Fix: run `tmux set -s extended-keys on` (and add `set -s extended-keys on` to ~/.tmux.conf).'
            end
          end

          # (2) Outer side: terminal → tmux. tmux only ASKS the outer terminal
          #     to encode S-Enter distinctly (sends `\e[>4;2m` at attach) if the
          #     client tty has the `extkeys` feature. That comes from the
          #     `terminal-features` server option matched against the client's
          #     $TERM at attach time. No match ⇒ outer emulator keeps sending
          #     0x0D for BOTH Enter and Shift+Enter ⇒ tmux can't disambiguate ⇒
          #     step (1) is moot. Add it for common outer TERMs (and tmux* to
          #     cover `alias tmux='TERM=tmux-256color tmux'` and nested tmux).
          tf = `tmux show -sv terminal-features 2>/dev/null`.to_s
          unless tf.include?('extkeys')
            %w[xterm* tmux* screen*].each do |pat|
              system('tmux', 'set', '-as', 'terminal-features', "#{pat}:extkeys", out: File::NULL, err: File::NULL)
            end
            warn '[pwn] Added `extkeys` to tmux terminal-features (xterm*/tmux*/screen*) so tmux requests extended keys from the OUTER terminal.'
            warn "[pwn] Persist it: add `set -as terminal-features 'xterm*:extkeys'` (and tmux*/screen*) to ~/.tmux.conf"
          end

          # (3) terminal-features is evaluated at CLIENT ATTACH time. If the
          #     current client attached before `extkeys` was present, tmux never
          #     sent the enable CSI to the outer terminal. Detect and warn.
          feats = `tmux display -p '\#{client_termfeatures}' 2>/dev/null`.to_s
          return if feats.include?('extkeys')

          warn '[pwn] This tmux client attached before `extkeys` was configured; the outer terminal is still sending plain 0x0D for SHIFT+ENTER.'
          warn '[pwn] Fix: detach (prefix + d) and reattach (`tmux attach -t <session>`) so tmux re-negotiates extended keys with the terminal.'
        rescue StandardError => e
          warn "[pwn] ensure_tmux_extended_keys: #{e.class}: #{e.message}"
        end

        # Register SHIFT+ENTER → :key_newline on Reline's default keymaps.
        #
        # IMPORTANT: do NOT use add_oneshot_key_binding for this. Reline's
        # LineEditor#input_key calls reset_oneshot_key_bindings on EVERY
        # keystroke (it's designed for dialog trap-keys = "next keypress
        # only"), so oneshot bindings are wiped the moment the user types
        # their first character — Shift+Enter then falls through as an
        # unrecognised CSI and is silently swallowed. Default-keymap
        # bindings persist for the life of the Config object.
        #
        # Scoping is handled by the input-handler swap, not the binding
        # lifetime: outside pwn-ai/pwn-asm, Pry uses its own input,
        # PWNMultiLineInput#readline never runs, ENABLE_EXTENDED_KEYS is never
        # emitted, the terminal sends plain 0x0D for Shift+Enter, and these
        # bindings never match. So registering once at construction is safe.
        def install_shift_enter_bindings
          return if self.class.instance_variable_get(:@shift_enter_installed)

          cfg = reline_config
          %i[emacs vi_insert].each do |keymap|
            SHIFT_ENTER_SEQS.each do |seq|
              cfg.add_default_key_binding_by_keymap(keymap, seq, :key_newline)
            end
          end
          self.class.instance_variable_set(:@shift_enter_installed, true)
        end

        def readline(prompt)
          # Ask the terminal to encode Shift+Enter distinctly from Enter for
          # the duration of this read. Without this, most emulators send 0x0D
          # for both and SHIFT_ENTER_SEQS can never match. Reset in `ensure`.
          tty = $stdout.respond_to?(:tty?) && $stdout.tty?
          if tty
            $stdout.write(ENABLE_EXTENDED_KEYS)
            $stdout.flush
          end

          begin
            # readmultiline with confirm block that *always* returns true:
            #   => default (plain) ENTER triggers finish/submit of the (multi-line) buffer
            # SHIFT+ENTER (matched seq) triggers :key_newline (insert \n, stay in edit mode)
            # Reline handles multi-line pastes by splitting on \n in the buffer.
            @line_buffer = Reline.readmultiline(prompt, true) { |_buffer| true } || ''
          ensure
            if tty
              $stdout.write(DISABLE_EXTENDED_KEYS)
              $stdout.flush
            end
          end
          @line_buffer
        end

        # Compatibility with Pry input expectations
        def tty?
          true
        end

        def winsize
          [TTY::Screen.rows || 24, TTY::Screen.columns || 80]
        end
      end

      public_class_method def self.refresh_ps1_proc(opts = {})
        mode = opts[:mode]

        proc do |_target_self, _nest_level, pi|
          PWN::Config.refresh_env(opts) if Pry.config.refresh_pwn_env

          pi.config.pwn_repl_line += 1
          line_pad = format(
            '%0.3d',
            pi.config.pwn_repl_line
          )

          pi.config.prompt_name = :pwn
          name = "\001\e[1m\002\001\e[31m\002#{pi.config.prompt_name}\001\e[0m\002"
          version = "\001\e[36m\002v#{PWN::VERSION}\001\e[0m\002"
          line_count = "\001\e[34m\002#{line_pad}\001\e[0m\002"
          dchars = "\001\e[32m\002>>>\001\e[0m\002"
          dchars = "\001\e[33m\002***\001\e[0m\002" if mode == :splat

          if pi.config.pwn_asm
            arch = PWN::Env[:plugins][:asm][:arch] ||= PWN::Plugins::DetectOS.arch
            endian = PWN::Env[:plugins][:asm][:endian] ||= PWN::Plugins::DetectOS.endian

            pi.config.prompt_name = "pwn.asm:#{arch}/#{endian}"
            name = "\001\e[1m\002\001\e[37m\002#{pi.config.prompt_name}\001\e[0m\002"
            dchars = "\001\e[32m\002>>>\001\e[33m\002"
            dchars = "\001\e[33m\002***\001\e[33m\002" if mode == :splat
          end

          if pi.config.pwn_ai
            engine = PWN::Env[:ai][:active].to_s.downcase.to_sym
            model = PWN::Env[:ai][engine][:model]
            system_role_content = PWN::Env[:ai][engine][:system_role_content]
            temp = PWN::Env[:ai][engine][:temp]
            pname = "pwn.ai:#{engine}"
            pname = "pwn.ai:#{engine}/#{model}" if model
            pname = "pwn.ai:#{engine}/#{model}.SPEAK" if pi.config.pwn_ai_speak
            pi.config.prompt_name = pname

            name = "\001\e[1m\002\001\e[33m\002#{pi.config.prompt_name}\001\e[0m\002"
            dchars = "\001\e[32m\002>>>\001\e[33m\002"
            dchars = "\001\e[33m\002***\001\e[33m\002" if mode == :splat
            if pi.config.pwn_ai_debug
              dchars = "\001\e[32m\002(DEBUG) >>>\001\e[33m\002"
              dchars = "\001\e[33m\002(DEBUG) ***\001\e[33m\002" if mode == :splat
            end
          end

          ps1_proc = "#{name}[#{version}]:#{line_count} #{dchars} ".to_s.scrub
          ps1_proc = '' if pi.config.pwn_mesh

          ps1_proc
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::REPL.add_commands

      public_class_method def self.add_commands
        # Load any existing pwn.yaml configuration file
        # Define Custom REPL Commands
        Pry::Commands.create_command 'welcome-banner' do
          description 'Display the random welcome banner, including basic usage.'

          def process
            puts PWN::Banner.welcome
          end
        end

        Pry::Commands.create_command 'toggle-pager' do
          description 'Toggle less on returned objects surpassing the terminal.'

          def process
            pi = pry_instance
            pi.config.pager ? pi.config.pager = false : pi.config.pager = true
          end
        end

        #  class PWNCompleter < Pry::InputCompleter
        #    def call(input)
        #    end
        #  end

        Pry::Commands.create_command 'pwn-asm' do
          description 'Initiate pwn.asm shell.'

          def process
            pi = pry_instance
            pi.config.pwn_asm = true

            # Switch to custom multi-line input (SHIFT+ENTER newline, ENTER submit) —
            # same handler pwn-ai uses; restored by `back`.
            pi.config.input = PWNMultiLineInput.new(pi)

            pi.custom_completions = proc do
              [pi.input.line_buffer]
            end

            puts '[*] MULTILINE in pwn-asm: SHIFT+ENTER inserts a newline (e.g. multi-instruction asm); ENTER submits.'
          end
        end

        Pry::Commands.create_command 'pwn-ai' do
          description 'Initiate pwn.ai autonomous agent TUI (instruct tasks using PWN modules + CLI tools; memory/sessions/agents/cron/skills-aware from PWN::Config/PWN::Memory etc).'

          def process
            pi = pry_instance
            pi.config.pwn_ai = true
            pi.config.pwn_ai_agent = true
            pi.config.color = false if pi.config.pwn_ai

            # Switch to custom multi-line input for pwn-ai (SHIFT+ENTER newline, ENTER submit)
            pi.config.input = PWNMultiLineInput.new(pi)

            # Load and make aware of skills folder (scaled in PWN::Config per user pwn_env_path parent)
            skills_path = begin
              PWN::Config.pwn_skills_path
            rescue StandardError
              "#{Dir.home}/.pwn/skills"
            end
            PWN::Config.load_skills(pwn_skills_path: skills_path)
            skills_count = (PWN.const_defined?(:Skills) ? PWN::Skills.keys.length : 0)

            # pwn-ai activation: initialise memory/sessions/cron stores
            PWN::Config.load_memory
            mem_count = (PWN.const_defined?(:Memory) ? PWN::Memory.load.keys.length : 0)
            sess = begin
              PWN::Sessions.create(title: "pwn-ai #{Time.now.strftime('%Y-%m-%d %H:%M')}", source: 'pwn-ai-repl')
            rescue StandardError
              nil
            end
            pi.config.pwn_ai_session_id = sess[:id] if sess
            cron_count = (PWN.const_defined?(:Cron) ? PWN::Cron.list.keys.length : 0)

            puts "\
[*] pwn-ai agent TUI activated (PWN REPL driver w/ memory, sessions, delegation, cron)."
            puts "[*] Memory facts: #{mem_count} | Session: #{pi.config.pwn_ai_session_id} | Cron jobs: #{cron_count} | Skills: #{skills_count}"
            puts '[*] Instruct the AI agent to carry out a task, e.g.:'
            puts "    'Use NmapIt to port scan target.com then use TransparentBrowser to spider and SAST::TestCaseEngine to analyze code if cloned. Generate report with PWN::Reports.'"
            puts "    'Execute CLI nmap -sV target.com and summarize findings using PWN modules.'"
            puts "[*] Skills loaded from #{skills_path} (#{skills_count} available) + memory/sessions/cron to expand autonomous capabilities."
            puts "[*] Type 'back' to exit pwn-ai mode."
            puts '[*] MULTILINE in pwn-ai: Use ONLY SHIFT+ENTER for newlines (plain ENTER submits to AI).'
            puts "[*] tmux + terminator users: Ensure ~/.tmux.conf has 'set -s extended-keys on' and 'set -g xterm-keys on', then restart tmux. Use TERM=xterm-256color."
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
              val = args[2..-1].join(' ')
              PWN::Memory.remember(key: key, value: val)
              puts "Remembered #{key}"
            when 'forget'
              PWN::Memory.forget(key: args[1])
              puts "Forgot #{args[1]}"
            when 'clear'
              PWN::Memory.clear
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
              PWN::Sessions.delete(session_id: args[1])
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
              pr = args[2..-1].join(' ')
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

        Pry::Commands.create_command 'pwn-irc' do
          description 'IRC viewport onto a PWN::AI::Agent::Swarm (deprecated as multi-agent transport).'

          # pwn-irc is now a THIN OBSERVER over PWN::AI::Agent::Swarm.
          # The old inspircd/weechat block spun up N text-only .chat bots
          # per nick — that bypassed tools, Memory, Skills, Learning,
          # Metrics and Extrospection. Multi-agent now lives in
          # PWN::AI::Agent::Swarm (agent_ask / agent_debate / agent_broadcast
          # from inside pwn-ai). This command just bridges a swarm's
          # bus.jsonl into an IRC channel so you can watch in weechat and
          # type `@red enumerate ports on 10.0.0.5` to route into Swarm.ask.
          def process
            host = '127.0.0.1'
            port = 6667
            chan = '#pwn'

            unless PWN::Plugins::Sock.check_port_in_use(server_ip: host, port: port)
              puts <<~MIGRATE
                pwn-irc is now an optional viewport onto PWN::AI::Agent::Swarm.
                Multi-agent no longer requires IRC:

                  pwn-ai
                  » agent_list
                  » agent_debate(names: %w[red blue], topic: '...', rounds: 3)

                or from Ruby:
                  PWN::AI::Agent::Swarm.debate(names: %w[red blue], topic: '...')

                Personas: #{PWN::AI::Agent::Swarm::AGENTS_FILE}
                Bus     : ~/.pwn/swarm/<swarm_id>/bus.jsonl

                (Start inspircd on #{host}:#{port} if you still want the weechat view.)
              MIGRATE
              return
            end

            personas = PWN::AI::Agent::Swarm.personas
            if personas.empty?
              puts "No personas defined in #{PWN::AI::Agent::Swarm::AGENTS_FILE} — " \
                   'use PWN::AI::Agent::Swarm.spawn or agent_spawn from pwn-ai.'
              return
            end

            swarm  = PWN::AI::Agent::Swarm.create(topic: 'pwn-irc bridge')
            sid    = swarm[:swarm_id]
            bus    = swarm[:bus]
            ui     = ENV.fetch('USER', 'human')
            bridge = 'swarmbot'

            irc = PWN::Plugins::IRC.connect(host: host.to_s, port: port.to_s, nick: bridge)
            PWN::Plugins::IRC.join(irc_obj: irc, nick: bridge, chan: chan)
            PWN::Plugins::IRC.privmsg(
              irc_obj: irc, nick: bridge, chan: chan,
              message: "*** swarm #{sid} bridged | personas: #{personas.keys.join(', ')} " \
                       "| say '@<persona> <request>' | tailing #{bus}"
            )

            # bus.jsonl → #pwn
            tailer = Thread.new do
              seen = File.exist?(bus) ? File.foreach(bus).count : 0
              loop do
                lines = File.exist?(bus) ? File.readlines(bus) : []
                lines[seen..].to_a.each do |l|
                  m = JSON.parse(l, symbolize_names: true)
                  PWN::Plugins::IRC.privmsg(
                    irc_obj: irc, nick: bridge, chan: chan,
                    message: "[#{m[:from]}→#{m[:to]}] #{m[:content].to_s.tr("\n", ' ')[0, 400]}"
                  )
                rescue StandardError
                  next
                end
                seen = lines.length
                sleep 1
              end
            end

            # #pwn '@persona ...' → Swarm.ask
            listener = Thread.new do
              PWN::Plugins::IRC.listen(irc_obj: irc) do |raw|
                next unless raw.to_s.split[1] == 'PRIVMSG'

                body = raw.to_s.split(' :', 2).last.to_s
                from = raw.to_s.split('!').first.to_s.delete_prefix(':')
                m    = body.match(/@(\w+)\s+(.+)/)
                next unless m && personas.key?(m[1].to_sym)

                begin
                  PWN::AI::Agent::Swarm.ask(
                    name: m[1], request: m[2], swarm_id: sid, from: from
                  )
                rescue StandardError => e
                  PWN::Plugins::IRC.privmsg(
                    irc_obj: irc, nick: bridge, chan: chan,
                    message: "[error] #{m[1]}: #{e.class}: #{e.message[0, 200]}"
                  )
                end
              end
            end

            if File.exist?('/usr/bin/weechat')
              cmds = [
                "/server add pwn #{host}/#{port} -notls", '/connect pwn',
                "/wait 3 /allserv /nick #{ui}", "/wait 4 /join -server pwn #{chan}"
              ].join(';')
              system('/usr/bin/weechat', '--run-command', "'#{cmds}'")
            else
              puts "Bridging swarm #{sid} on ##{chan} (weechat not found — use any IRC client). Ctrl-C to stop."
              listener.join
            end
          ensure
            tailer&.kill
            listener&.kill
            PWN::Plugins::IRC.quit(irc_obj: irc) if defined?(irc) && irc
          end
        end

        Pry::Commands.create_command 'pwn-mesh' do
          description 'Communicate with Meshtastic network within pwn REPL.'

          def process
            pi = pry_instance
            pi.config.pwn_mesh = true
            meshtastic_env = PWN::Env[:plugins][:meshtastic]

            PWN.send(:remove_const, :MeshTxEchoThread) if PWN.const_defined?(:MeshTxEchoThread)
            PWN.send(:remove_const, :MqttObj) if PWN.const_defined?(:MqttObj)
            PWN.send(:remove_const, :MeshRxHeaderWin) if PWN.const_defined?(:MeshRxHeaderWin)
            PWN.send(:remove_const, :MeshRxBodyWin) if PWN.const_defined?(:MeshRxBodyWin)
            PWN.send(:remove_const, :MeshTxWin) if PWN.const_defined?(:MeshTxWin)
            PWN.send(:remove_const, :MeshMutex) if PWN.const_defined?(:MeshMutex)
            PWN.send(:remove_const, :MqttSubThread) if PWN.const_defined?(:MqttSubThread)

            mqtt_env = meshtastic_env[:mqtt]
            host = mqtt_env[:host]
            port = mqtt_env[:port]
            tls = mqtt_env[:tls]
            username = mqtt_env[:user]
            password = mqtt_env[:pass]

            mqtt_obj = Meshtastic::MQTT.connect(
              host: host,
              port: port,
              tls: tls,
              username: username,
              password: password
            )
            PWN.const_set(:MqttObj, mqtt_obj)

            active_channel = meshtastic_env[:channel][:active].to_s.to_sym
            channel_env = meshtastic_env[:channel][active_channel]
            psk = channel_env[:psk]
            region = channel_env[:region]
            topic = channel_env[:topic]
            channel_num = channel_env[:channel_num]

            # Init ncurses UI (idempotent) with separate RX (top) and TX (bottom) panes
            Curses.init_screen
            Curses.curs_set(0)
            Curses.noecho
            Curses.cbreak
            Curses.crmode
            Curses.ESCDELAY = 0
            Curses.start_color
            Curses.use_default_colors

            mesh_highlight_colors = [
              { fg: Curses::COLOR_RED, bg: Curses::COLOR_WHITE },
              { fg: Curses::COLOR_GREEN, bg: Curses::COLOR_BLACK },
              { fg: Curses::COLOR_YELLOW, bg: Curses::COLOR_BLACK },
              { fg: Curses::COLOR_BLUE, bg: Curses::COLOR_WHITE },
              { fg: Curses::COLOR_CYAN, bg: Curses::COLOR_BLACK },
              { fg: Curses::COLOR_MAGENTA, bg: Curses::COLOR_WHITE },
              { fg: Curses::COLOR_WHITE, bg: Curses::COLOR_BLUE }
            ]
            mesh_highlight_colors.each_with_index do |hash, idx|
              color_id = idx + 1
              color_fg = hash[:fg]
              color_bg = hash[:bg]
              Curses.init_pair(color_id, color_fg, color_bg)
            end
            PWN.const_set(:MeshColors, (1..mesh_highlight_colors.length).to_a)
            PWN.const_set(:MeshLastColor, PWN::MeshColors.sample)

            mesh_ui_colors = []
            mesh_highlight_colors.each_with_index do |hl_hash, idx|
              ui_hash = {
                color_id: idx + 10,
                fg: hl_hash[:fg],
                bg: -1
              }
              Curses.init_pair(ui_hash[:color_id], ui_hash[:fg], ui_hash[:bg])
              mesh_ui_colors.push(ui_hash)
            end

            red = mesh_ui_colors[0][:color_id]
            green = mesh_ui_colors[1][:color_id]
            yellow = mesh_ui_colors[2][:color_id]
            blue = mesh_ui_colors[3][:color_id]
            cyan = mesh_ui_colors[4][:color_id]
            magenta = mesh_ui_colors[5][:color_id]
            white = mesh_ui_colors[6][:color_id]

            rx_height = Curses.lines - 4
            rx_header_win = Curses::Window.new(rx_height, Curses.cols, 0, 0)
            # TODO: Scrollable but should stay below header_line
            rx_header_win.scrollok(false)
            rx_header_win.nodelay = true
            rx_header_win.attron(Curses.color_pair(cyan) | Curses::A_BOLD)

            # Make rx_header bold and green
            rx_header_win.attron(Curses.color_pair(green) | Curses::A_BOLD)
            rx_header = "<<< #{host}:#{port} | #{region}/#{topic} | ch:#{channel_num} >>>"
            rx_header_len = rx_header.length
            rx_header_pos = (Curses.cols / 2) - (rx_header_len / 2)
            rx_header_win.setpos(1, rx_header_pos)
            rx_header_win.addstr(rx_header)
            rx_header_win.attroff(Curses.color_pair(green) | Curses::A_BOLD)
            # Jump two lines below header before messages begin
            rx_header_win.setpos(2, 0)
            rx_header_win.attron(Curses.color_pair(cyan) | Curses::A_BOLD)
            header_line = "\u2014" * Curses.cols
            rx_header_bottom_line_pos = (Curses.cols / 2) - (header_line.length / 2)
            rx_header_win.addstr(header_line)
            rx_header_win.attroff(Curses.color_pair(cyan) | Curses::A_BOLD)
            rx_header_win.refresh
            PWN.const_set(:MeshRxHeaderWin, rx_header_win)

            body_start_row = 3
            body_height = rx_height - body_start_row
            rx_body_win = Curses::Window.new(body_height, Curses.cols, body_start_row, 0)
            rx_body_win.scrollok(true)
            rx_body_win.nodelay = true
            rx_body_win.refresh
            PWN.const_set(:MeshRxBodyWin, rx_body_win)

            tx_height = rx_height - 1
            tx_win = Curses::Window.new(4, Curses.cols, tx_height, 0)
            tx_win.scrollok(false)
            tx_win.nodelay = true
            tx_win.refresh

            PWN.const_set(:MeshTxWin, tx_win)
            PWN.const_set(:MeshMutex, Mutex.new)

            # Live typing echo thread (idempotent)
            tx_prompt = "pwn.mesh:#{region}/#{topic} >>> "
            echo_thread = Thread.new do
              last_line = nil
              last_cursor_pos = -1
              loop do
                break unless pi.config.pwn_mesh

                tx_win = PWN.const_get(:MeshTxWin)
                mutex = PWN.const_get(:MeshMutex)
                msg_input = pi.input.line_buffer.to_s
                ts = Time.now.strftime('%H:%M:%S%z')
                cursor_pos = Readline.point
                base_line = "#{tx_prompt}#{msg_input}"
                cursor_abs_index = tx_prompt.length + cursor_pos
                current_line = base_line
                if last_line != current_line || cursor_pos != last_cursor_pos
                  mutex.synchronize do
                    tx_win.clear
                    tx_win.attron(Curses.color_pair(red) | Curses::A_BOLD)
                    tx_header_line_pos = (Curses.cols / 2) - (header_line.length / 2)
                    tx_win.addstr(header_line)
                    tx_win.attroff(Curses.color_pair(red) | Curses::A_BOLD)

                    tx_win.attron(Curses.color_pair(yellow) | Curses::A_BOLD)
                    inner_width = Curses.cols
                    segments = current_line.chars.each_slice(inner_width).map(&:join)
                    available_rows = tx_win.maxy - 1
                    segments.first(available_rows).each_with_index do |seg, idx|
                      tx_win.setpos(1 + idx, 0)
                      start_index = idx * inner_width
                      end_index = start_index + inner_width
                      if cursor_abs_index.between?(start_index, end_index)
                        cursor_col = cursor_abs_index - start_index
                        (0..inner_width).each do |col|
                          ch = seg[col] || ' '
                          if col == cursor_col
                            tx_win.attron(Curses.color_pair(red) | Curses::A_REVERSE | Curses::A_BOLD)
                            tx_win.addch(ch)
                            tx_win.attroff(Curses.color_pair(red) | Curses::A_REVERSE | Curses::A_BOLD)
                          else
                            tx_win.addch(ch)
                          end
                        end
                      else
                        tx_win.addstr(seg.ljust(inner_width))
                      end
                    end
                    tx_win.attroff(Curses.color_pair(yellow) | Curses::A_BOLD)
                    tx_win.refresh
                  end
                  last_line = current_line
                  last_cursor_pos = cursor_pos
                end
                sleep 0.00001
              end
            end
            echo_thread.abort_on_exception = false
            PWN.const_set(:MeshTxEchoThread, echo_thread)

            # Start single subscriber thread (idempotent)
            psks = { active_channel => psk }
            PWN::Plugins::ThreadPool.fill(
              enumerable_array: [:mesh_sub],
              max_threads: 1,
              detach: true
            ) do |_|
              last_from = nil
              last_line = nil
              Meshtastic::MQTT.subscribe(
                mqtt_obj: mqtt_obj,
                region: region,
                topic: topic,
                channel: channel_num,
                psks: psks
              ) do |msg|
                next unless msg.key?(:packet) && msg[:packet].key?(:decoded) && msg[:packet][:decoded].is_a?(Hash)

                packet = msg[:packet]
                decoded = packet[:decoded]
                next unless decoded.key?(:portnum) && decoded[:portnum] == :TEXT_MESSAGE_APP

                # rx_header_win = PWN.const_get(:MeshRxHeaderWin)
                mutex = PWN.const_get(:MeshMutex)

                from = "#{packet[:node_id_from]} ".ljust(9, ' ')
                absolute_topic = "#{region}/#{topic.gsub('#', from)}"
                to = packet[:node_id_to]
                rx_text = decoded[:payload]
                ts = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')

                # Select a random color different from the last used one
                colors_arr = PWN.const_get(:MeshColors)
                last_color = PWN.const_get(:MeshLastColor)
                color = last_color
                unless last_from == from
                  PWN.send(:remove_const, :MeshLastColor)
                  color_choices = colors_arr.reject { |c| c == last_color }
                  color = color_choices.sample
                  PWN.const_set(:MeshLastColor, color)
                end

                to_label = 'To'
                to_label = 'DM' unless to == '!ffffffff'
                current_line = "\nDate: #{ts}\nFrom: #{from}\n#{to_label}: #{to}\nTopic: #{absolute_topic}\n> #{rx_text.gsub("\n", "\n> ")}"

                if last_line != current_line
                  rx_body_win = PWN.const_get(:MeshRxBodyWin)
                  mutex.synchronize do
                    inner_height = rx_body_win.maxy - 5
                    inner_width = rx_body_win.maxx
                    segments = current_line.scan(/.{1,#{inner_width}}/)
                    rx_body_win.attron(Curses.color_pair(color) | Curses::A_REVERSE)
                    segments.each do |seg|
                      rx_body_win.setpos(rx_body_win.cury, 0)
                      # Handle wide Unicode characters for proper alignment
                      display_width = Unicode::DisplayWidth.of(seg)
                      width_diff = seg.length - display_width
                      shift_width = inner_width + width_diff
                      line = seg.ljust(shift_width)
                      rx_body_win.addstr(line)
                    end
                    rx_body_win.attroff(Curses.color_pair(color) | Curses::A_REVERSE)
                    rx_body_win.refresh
                  end
                  last_line = current_line
                  last_from = from
                end
              end
            end
          rescue StandardError => e
            raise e
          end
        end

        Pry::Commands.create_command 'pwn-vault' do
          description 'Edit the pwn.yaml configuration file.'

          def process
            pi = pry_instance
            pwn_env_path = PWN::Env[:driver_opts][:pwn_env_path] ||= "#{Dir.home}/.pwn/pwn.yaml"
            unless File.exist?(pwn_env_path)
              puts "ERROR: pwn environment file not found: #{pwn_env_path}"
              return
            end

            pwn_dec_path = PWN::Env[:driver_opts][:pwn_dec_path] ||= "#{Dir.home}/.pwn/pwn.decryptor.yaml"
            unless File.exist?(pwn_dec_path)
              puts "ERROR: pwn decryptor file not found: #{pwn_dec_path}"
              return
            end

            decryptor = YAML.load_file(pwn_dec_path, symbolize_names: true)
            key = decryptor[:key]
            iv = decryptor[:iv]

            PWN::Plugins::Vault.edit(
              file: pwn_env_path,
              key: key,
              iv: iv
            )
          rescue StandardError => e
            raise e
          end
        end

        Pry::Commands.create_command 'toggle-pwn-ai-debug' do
          description 'Display the response_history object while using pwn.ai'

          def process
            pi = pry_instance
            pi.config.pwn_ai_debug ? pi.config.pwn_ai_debug = false : pi.config.pwn_ai_debug = true
          end
        end

        Pry::Commands.create_command 'toggle-pwn-ai-speaks' do
          description 'Use speech capabilities within pwn.ai to speak answers.'

          def process
            pi = pry_instance
            pi.config.pwn_ai_speak ? pi.config.pwn_ai_speak = false : pi.config.pwn_ai_speak = true
          end
        end

        Pry::Commands.create_command 'back' do
          description 'Jump back to pwn REPL when in pwn-asm || pwn-ai.'

          def process
            pi = pry_instance
            pi.config.color = true
            pi.config.pwn_asm = false if pi.config.pwn_asm
            pi.config.pwn_ai = false if pi.config.pwn_ai
            pi.config.pwn_ai_agent = false if pi.config.pwn_ai_agent
            pi.config.pwn_ai_debug = false if pi.config.pwn_ai_debug
            pi.config.pwn_ai_speak = false if pi.config.pwn_ai_speak
            pi.config.completer = Pry::InputCompleter
            # pi.config.pwn_ai_original_input ||= Pry.config.input.clone
            if pi.config.pwn_ai_original_input
              pi.config.input = pi.config.pwn_ai_original_input
              pi.config.pwn_ai_original_input = nil
            end
            return unless pi.config.pwn_mesh

            pi.config.pwn_mesh = false
            # Stop echo thread
            if PWN.const_defined?(:MeshTxEchoThread)
              PWN.const_get(:MeshTxEchoThread).kill
              PWN.send(:remove_const, :MeshTxEchoThread)
            end

            if PWN.const_defined?(:MqttObj)
              Meshtastic::MQTT.disconnect(mqtt_obj: PWN.const_get(:MqttObj))
              PWN.send(:remove_const, :MqttObj)
            end

            if PWN.const_defined?(:MeshRxHeaderWin)
              PWN.const_get(:MeshRxHeaderWin).close
              PWN.send(:remove_const, :MeshRxHeaderWin)
            end

            if PWN.const_defined?(:MeshRxBodyWin)
              PWN.const_get(:MeshRxBodyWin).close
              PWN.send(:remove_const, :MeshRxBodyWin)
            end

            if PWN.const_defined?(:MeshTxWin)
              PWN.const_get(:MeshTxWin).close
              PWN.send(:remove_const, :MeshTxWin)
            end
            PWN.send(:remove_const, :MeshColors) if PWN.const_defined?(:MeshColors)
            PWN.send(:remove_const, :MeshLastColor) if PWN.const_defined?(:MeshLastColor)
            PWN.send(:remove_const, :MeshMutex) if PWN.const_defined?(:MeshMutex)
            PWN.send(:remove_const, :MqttSubThread) if PWN.const_defined?(:MqttSubThread)
            Curses.close_screen
          end
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::REPL.add_hooks

      public_class_method def self.add_hooks
        # Define REPL Hooks
        # Welcome Banner Hook
        Pry.config.hooks.add_hook(:before_session, :welcome) do |output, _binding, _pi|
          Pry.config.refresh_pwn_env = false
          output.puts PWN::Banner.welcome
        end

        Pry.config.hooks.add_hook(:after_read, :pwn_asm_hook) do |request, pi|
          if pi.config.pwn_asm && !request.chomp.empty?
            request = pi.input.line_buffer

            arch = PWN::Env[:plugins][:asm][:arch]
            endian = PWN::Env[:plugins][:asm][:endian]

            # Analyze request to determine if it should be processed as opcodes or asm.
            straight_hex = /^[a-fA-F0-9\s]+$/
            hex_esc_strings = /\\x[\da-fA-F]{2}/
            hex_comma_delim_w_dbl_qt = /"(?:[0-9a-fA-F]{2})",?/
            hex_comma_delim_w_sng_qt = /'(?:[0-9a-fA-F]{2})',?/
            hex_byte_array_as_str = /^\[\s*(?:"[0-9a-fA-F]{2}",\s*)*"[0-9a-fA-F]{2}"\s*\]$/

            if request.match?(straight_hex) ||
               request.match?(hex_esc_strings) ||
               request.match?(hex_comma_delim_w_dbl_qt) ||
               request.match?(hex_comma_delim_w_sng_qt) ||
               request.match?(hex_byte_array_as_str)

              response = PWN::Plugins::Assembly.opcodes_to_asm(
                opcodes: request,
                opcodes_always_strings_obj: true,
                arch: arch,
                endian: endian
              )
            else
              response = PWN::Plugins::Assembly.asm_to_opcodes(
                asm: request,
                arch: arch,
                endian: endian
              )
            end
            puts "\001\e[31m\002#{response}\001\e[0m\002"
          end
        end

        Pry.config.hooks.add_hook(:after_read, :pwn_ai_hook) do |request, pi|
          if pi.config.pwn_ai && !request.chomp.empty?
            orig_request = pi.input.line_buffer.to_s

            # ----------------------------------------------------------------
            # NATIVE TOOL-CALLING AGENT LOOP (default path)
            #
            # Routes through PWN::AI::Agent::Loop, which uses real
            # function-calling (tools: array on the chat/completions request,
            # role:'tool' result messages) instead of the regex-ReAct below.
            #
            # Disable by setting in pwn.yaml:
            #   ai:
            #     agent:
            #       native_tools: false
            # ----------------------------------------------------------------
            native = PWN::Env.dig(:ai, :agent, :native_tools)
            native = true if native.nil?
            if pi.config.pwn_ai_agent && native
              begin
                sess_id = pi.config.pwn_ai_session_id
                on_tool = lambda do |name, args, result|
                  arg_preview = args.is_a?(String) ? args[0, 80] : args.inspect[0, 80]
                  puts "\001\e[33m\002[ pwn-ai → #{name} ]\001\e[0m\002 #{arg_preview}"
                  puts "\001\e[36m\002#{result[0, 700]}\001\e[0m\002\n"
                end
                final = PWN::AI::Agent::Loop.run(
                  request: orig_request,
                  session_id: sess_id,
                  enabled_toolsets: PWN::Env.dig(:ai, :agent, :toolsets),
                  on_tool: on_tool
                )
                puts "\n\001\e[32m\002#{final}\001\e[0m\002\n\n"
                pp PWN::Sessions.load(session_id: sess_id) if pi.config.pwn_ai_debug && sess_id && PWN.const_defined?(:Sessions)
                request.replace('nil')
                next
              rescue StandardError => e
                warn "[pwn-ai] native agent loop failed (#{e.class}: #{e.message}\n#{e.backtrace}); " \
                     'falling back to legacy regex-ReAct.'
              end
            end

            # ----------------------------------------------------------------
            # LEGACY regex-ReAct path (kept as fallback; remove once all
            # engines have a working .chat_with_tools and the native loop has had
            # real-API smoke time on each).
            # ----------------------------------------------------------------
            # Do NOT rebind the 'request' parameter (the string object passed by Pry's after_read hook).
            # We will mutate it to 'nil' at the end of handling so Pry does not eval the natural-language
            # prompt text as Ruby (which was causing noisy exceptions *after* the green AI response print).
            debug = pi.config.pwn_ai_debug
            engine = PWN::Env[:ai][:active].to_s.downcase.to_sym
            response_history = PWN::Env[:ai][engine][:response_history]
            speak_answer = pi.config.pwn_ai_speak
            is_agent = (pi.config.pwn_ai_agent == true)

            # pwn-ai agent mode: load skills context for autonomous task carrying
            skills_context = ''
            PWN::Skills.each { |n, m| skills_context += "\n--- SKILL #{n} ---\n#{m[:content].to_s[0, 1200]}\n" } if is_agent && PWN.const_defined?(:Skills) && PWN::Skills.is_a?(Hash)

            memory_context = ''
            memory_context = PWN::Memory.to_context(limit: 25) if is_agent && PWN.const_defined?(:Memory)

            sess_id = begin
              pi.config.pwn_ai_session_id
            rescue StandardError
              nil
            end

            # Pre-process for clear CLI execution intent (e.g. "what does `id` return?")
            # This makes the agent actually *run* commands instead of just explaining them.
            curr_req = orig_request.chomp
            if is_agent && sess_id && PWN.const_defined?(:Sessions)
              begin
                PWN::Sessions.append(session_id: sess_id, role: 'user', content: orig_request)
              rescue StandardError
                nil
              end
            end
            if is_agent && request =~ /`([^`]+)`/
              potential = ::Regexp.last_match(1).strip
              # Looks like a shell command (not PWN ruby)
              unless potential =~ /^(PWN::|def |class |require |puts |pp )/
                curr_req = "The user wants the *actual raw output* of this command (do not just describe it): `#{potential}`. " \
                           'To fulfill the request accurately, you MUST immediately output ONLY a bash code block with the exact command. ' \
                           "Example format: ```bash\n#{potential}\n``` . After the host executes it, you will receive the OBSERVATION with the real output."
              end
            end

            # Strict system prompt for agent mode (forces tool use over explanation)
            system_role = nil
            if is_agent
              base = PWN::Env[:ai][engine][:system_role_content] || 'You are an ethical hacker.'
              system_role = base + <<~PROMPT

                                You are operating as an autonomous agent inside the PWN REPL driver.

                                PRIMARY RULE FOR CLI AND TOOLS: When the user asks for the output of a command, "what does X return?", "run X", or anything that requires real execution, you MUST use a tool call.#{' '}
                                NEVER just explain what a command does or what its output "would be".#{' '}
                                To execute anything:
                                  - Output *exactly and only* a fenced code block.
                                  - For shell/CLI: ```bash
                                <exact command here>
                                ```
                                  - For PWN Ruby modules: ```ruby
                                PWN::Plugins::NmapIt.port_scan(...)
                                ```
                                The host will execute it (Ruby in full PWN context, bash via shell) and reply with an OBSERVATION containing the real result.#{' '}
                                Then continue or give the final answer.

                                Available tools include all PWN::Plugins (NmapIt, TransparentBrowser, etc.), SAST, Reports, and any CLI via bash blocks.
                                Skills available this session:#{skills_context}
                #{memory_context}

                                PERSISTENT CAPABILITIES (use via ruby code blocks or direct calls):
                                - Memory (cross-session): PWN::Memory.remember(key: :key, value: val, category: :fact|:preference|:lesson)
                                  PWN::Memory.recall(query: 'foo'), PWN::Memory.forget(key: key)
                                - Sessions: current session id = #{sess_id}; PWN::Sessions.append(session_id: '#{sess_id}', role: 'observation', content: obs)
                                - Cron: PWN::Cron.create(schedule: '0 * * * *', prompt: 'task here', name: 'foo')
                                  PWN::Cron.run(id: 'id'); list with PWN::Cron.list
                                - Agents/Delegation: PWN::AI::Agent::SAST.analyze(request: ...); PWN::AI::Agent::VulnGen etc.
                                  For sub-agents use threads or separate eval calls and feed results back as OBS.

                                After receiving an observation, decide the next step or conclude.
                                If you output text without a code block, it will be treated as your final answer to the user.
              PROMPT
            end

            max_turns = is_agent ? 7 : 1
            turn = 0
            last_response = ''
            tool_was_executed_this_turn = false

            while turn < max_turns
              chat_opts = {
                request: curr_req,
                response_history: response_history,
                speak_answer: speak_answer,
                spinner: true
              }
              chat_opts[:system_role_content] = system_role if system_role

              case engine
              when :grok
                response = PWN::AI::Grok.chat(**chat_opts)
              when :ollama
                response = PWN::AI::Ollama.chat(**chat_opts)
              when :openai
                response = PWN::AI::OpenAI.chat(**chat_opts)
              when :anthropic
                response = PWN::AI::Anthropic.chat(**chat_opts)
              when :gemini
                response = PWN::AI::Gemini.chat(**chat_opts)
              else
                raise "ERROR: Unsupported AI Engine: #{engine}"
              end

              if response.nil?
                last_response = 'Model not currently supported with API key.'
              else
                if response[:choices].last.keys.include?(:text)
                  last_response = response[:choices].last[:text].to_s
                else
                  last_response = response[:choices].last[:content].to_s
                end
                response_history = {
                  id: response[:id],
                  object: response[:object],
                  model: response[:model],
                  usage: response[:usage]
                }
                response_history[:choices] ||= response[:choices]
              end

              puts "\n\001\e[32m\002#{last_response}\001\e[0m\002\n\n"
              if is_agent && sess_id && PWN.const_defined?(:Sessions)
                begin
                  PWN::Sessions.append(session_id: sess_id, role: 'assistant', content: last_response)
                rescue StandardError
                  nil
                end
              end

              if debug
                puts 'DEBUG: response_history => '
                pp response_history
              end
              PWN::Env[:ai][engine][:response_history] = response_history

              # === Agent tool execution: parse code blocks from *this* response and actually run them ===
              tool_was_executed_this_turn = false
              if is_agent
                # Robust regex: tolerate language specifier, extra whitespace, and text around the block
                last_response.scan(/```(?:\s*(ruby|bash|sh|shell|zsh))?\s*\n?(.*?)\n?```/m).each do |lang, code|
                  code = code.strip
                  next if code.empty? || tool_was_executed_this_turn

                  lang = (lang || 'bash').downcase
                  puts "\001\e[33m\002[ pwn-ai AGENT EXEC #{lang} ]\e[0m\002 #{code[0..90]}..."

                  obs = ''
                  begin
                    if lang == 'ruby'
                      require 'stringio'
                      old_stdout = $stdout
                      $stdout = StringIO.new
                      res = eval(code, TOPLEVEL_BINDING) # rubocop:disable Security/Eval -- intentional for pwn-ai agent to run PWN Ruby modules/tools in REPL context
                      captured = $stdout.string
                      $stdout = old_stdout
                      obs = (captured + "\n=> #{res.inspect}").strip
                    else
                      # CLI execution - use Open3 for cleaner capture (no extra shell if possible, but backticks are simple and work)
                      require 'open3'
                      stdout, stderr, status = Open3.capture3(code)
                      obs = stdout
                      obs += "\n[stderr]\n#{stderr}" unless stderr.to_s.strip.empty?
                      obs += "\n[exit: #{status.exitstatus}]" unless status.success?
                      obs = obs.strip
                    end
                  rescue StandardError => e
                    obs = "ERROR executing #{lang} block: #{e.class} - #{e.message}"
                  end

                  puts "\001\e[36m\002[OBSERVATION from #{lang}]\001\e[0m\002\n#{obs[0..700]}\n"
                  if is_agent && sess_id && PWN.const_defined?(:Sessions)
                    begin
                      PWN::Sessions.append(session_id: sess_id, role: 'observation', content: obs)
                    rescue StandardError
                      nil
                    end
                  end

                  # Feed real result back to the model as the next "user" message in the loop
                  curr_req = "OBSERVATION (#{lang} execution result for previous block):\n#{obs}\n\n" \
                             "Now continue fulfilling the original user request: #{orig_request}. " \
                             'If the task is complete, give the final answer (no more code blocks). Otherwise output the next needed tool block.'

                  tool_was_executed_this_turn = true
                  turn += 1
                  break # one execution per model turn for controlled pacing
                end
              end

              # If we executed something, loop to let the model react to the OBS
              next if tool_was_executed_this_turn

              # No tool executed this turn -> this last_response is the final answer
              break
            end

            # If in agent mode and the model never produced an executable block but the query clearly wanted execution,
            # give one last chance with a strong reminder (helps weaker models like some Ollama ones)
            if is_agent && !tool_was_executed_this_turn && orig_request =~ /`[^`]+`/ && turn < max_turns
              reminder = 'The user explicitly asked about the output of a command in backticks. ' \
                         'Do not describe the command. Output *only* the corresponding ```bash block now so the host can run it and give you the real result.'
              curr_req = "#{reminder}\nOriginal: #{orig_request}"
              # One final direct call (no full re-loop to avoid complexity)
              # (The main loop already handled most cases; this is a safety net)
            end
          end
        end

        Pry.config.hooks.add_hook(:after_read, :pwn_mesh_hook) do |request, pi|
          if pi.config.pwn_mesh && !request.chomp.empty?
            mqtt_obj = PWN.const_get(:MqttObj)
            active_channel = PWN::Env[:plugins][:meshtastic][:channel][:active].to_s.to_sym
            region = PWN::Env[:plugins][:meshtastic][:channel][active_channel][:region]
            topic = PWN::Env[:plugins][:meshtastic][:channel][active_channel][:topic]
            channel_num = PWN::Env[:plugins][:meshtastic][:channel][active_channel][:channel_num]
            from = PWN::Env[:plugins][:meshtastic][:channel][active_channel][:from] ||= "!#{mqtt_obj.client_id}"
            psk = PWN::Env[:plugins][:meshtastic][:channel][active_channel][:psk]

            psks = {}
            psks[active_channel] = psk

            tx_text = pi.input.line_buffer.to_s
            to = '!ffffffff'
            # If text include @! with 8 byte length,
            # send DM to that address
            if tx_text.include?('@!')
              to_raw = tx_text.split('@').last.chomp[0..8]
              # If to_raw[1..-1] is hex than set to = to_raw
              to = to_raw if to_raw[1..-1].match?(/^[a-fA-F0-9]{8}$/)
              # Remove any spaces from beginning of to_raw
              tx_text.gsub!("@#{to_raw}", '').strip!
            end

            Meshtastic::MQTT.send_text(
              mqtt_obj: mqtt_obj,
              from: from,
              to: to,
              region: region,
              topic: topic,
              channel: channel_num,
              text: tx_text,
              psks: psks
            )
          end
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::REPL.enable_autocomplete(
      #   enabled: 'optional - Boolean (default true). false reverts to single-line cycling.'
      # )
      #
      # IRB-style suggest-as-you-type for the pwn REPL.
      #
      # Replaces Pry's default input (rb-readline — single-candidate TAB
      # cycling) with Reline and turns on Reline.autocompletion, which
      # renders a live dropdown of candidates below the cursor as you
      # type (the same widget IRB uses).  Pry already wires
      # Reline.completion_proc → @pry.complete (Pry::InputCompleter) when
      # input == Reline, so the menu is fed by the full Ruby/PWN object
      # graph: constants (PWN::Plugins::Nm<TAB>), instance methods,
      # local/global variables, and Pry slash-commands.
      #
      # Navigate with ↑/↓ or TAB, accept with → or ENTER, dismiss with ESC.
      #
      # Scope: this drives the MAIN pwn REPL (Ruby).  pwn-ai / pwn-asm
      # swap to PWNMultiLineInput, which bypasses Pry's Reline path on purpose
      # (natural-language / opcode input — Ruby completion isn't useful
      # there); SHIFT+ENTER multi-line continues to work in those modes.

      public_class_method def self.enable_autocomplete(opts = {})
        enabled = opts.fetch(:enabled, true)

        require 'reline'
        Pry.config.input     = Reline
        Pry.config.completer = Pry::InputCompleter
        Reline.autocompletion = enabled

        if enabled && defined?(Reline::Face) && Reline::Face.respond_to?(:config)
          # Readable dropdown on dark terminals (matches the pwn red/cyan PS1).
          Reline::Face.config(:completion_dialog) do |face|
            face.define :default,        foreground: :bright_white, background: :black
            face.define :enhanced,       foreground: :black,        background: :bright_cyan
            face.define :scrollbar,      foreground: :bright_red,   background: :black
          end
        end

        enabled
      rescue StandardError => e
        warn "[pwn] autocomplete unavailable (#{e.class}: #{e.message}); falling back to default input."
        false
      end

      # Supported Method Parameters::
      # PWN::Plugins::REPL.start

      public_class_method def self.start
        opts = PWN::Env[:driver_opts]

        # Monkey Patch Pry, add commands, && hooks
        PWN::Plugins::MonkeyPatch.pry
        pwn_env_root = "#{Dir.home}/.pwn"
        Pry.config.history_file = "#{pwn_env_root}/pwn_history"

        add_commands
        add_hooks

        # IRB-style suggest-as-you-type dropdown (off via
        # PWN::Env[:driver_opts][:autocomplete] = false in pwn.yaml).
        ac = opts.key?(:autocomplete) ? opts[:autocomplete] : true
        enable_autocomplete(enabled: ac)

        # Define PS1 Prompt
        Pry.config.pwn_repl_line = 0
        Pry.config.prompt_name = :pwn
        arrow_ps1_proc = refresh_ps1_proc(opts)

        opts[:mode] = :splat
        splat_ps1_proc = refresh_ps1_proc(opts)

        ps1 = [arrow_ps1_proc, splat_ps1_proc]
        prompt = Pry::Prompt.new(:pwn, 'PWN Prototyping REPL', ps1)

        # Start PWN REPL
        # Pry.start(self, prompt: prompt)
        Pry.start(Pry.main, prompt: prompt)
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.refresh_ps1_proc(
            mode: 'required - :splat or nil'
          )

          #{self}.add_commands

          #{self}.add_hooks

          #{self}.start

          #{self}.authors
        "
      end
    end
  end
end
