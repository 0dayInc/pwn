# frozen_string_literal: true

require 'curses'
require 'pry'
require 'reline'
require 'tty-cursor'
require 'tty-prompt'
require 'unicode/display_width'
require 'yaml'

module PWN
  module Plugins
    # This module contains methods related to the pwn REPL Driver.
    module REPL
      # Custom input handler for pwn-ai and pwn-asm to support multi-line
      # submissions. Plain ENTER submits the full (possibly multi-line)
      # buffer; a newline is inserted (keep editing) by ANY of:
      #
      #   - SHIFT+ENTER   on capable terminals (kitty, wezterm, foot,
      #                   alacritty, xterm, Konsole, iTerm2, Windows
      #                   Terminal; and Terminator via `pwn setup --terminal`)
      #   - ALT+ENTER     terminal-agnostic fallback — every emulator,
      #                   including bare VTE, sends `\e\r` for this.
      #   - trailing `\`  bash/zsh/irb/psql-style continuation: end a line
      #                   with backslash + ENTER to keep composing. The
      #                   backslashes are stripped before submit.
      #
      # Multi-line pastes work (Reline holds \n in the buffer; ENTER submits).
      # See documentation/pwn-REPL.md § Multi-line input for the terminal
      # support matrix and `pwn setup --terminal` for the opt-in VTE fix.
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
          [27, 13],                                  # \e\r  ALT+ENTER — universal fallback (all emulators, incl. VTE)
          [27, 10],                                  # \e\n  ALT+ENTER (LF variant)
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
          ensure_vte_shift_enter
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

        # VTE-based emulators (Terminator, GNOME Terminal, Tilix, xfce4-terminal,
        # Guake, Ptyxis, MATE Terminal, ...) do *not* implement xterm
        # modifyOtherKeys (CSI >4;Nm) nor the kitty keyboard protocol
        # (CSI >1u) — see GNOME/vte issues #2601 and #2607. The
        # ENABLE_EXTENDED_KEYS request we emit (and that tmux emits to the
        # outer terminal via Eneks) is silently ignored, so a physical
        # Shift+Enter reaches us as an indistinguishable plain 0x0D. No
        # tmux/Reline configuration can fix that — the modifier was lost at
        # the outer terminal.
        #
        # This method therefore ONLY detects and hints. It never mutates the
        # user's host. Terminal-agnostic fallbacks (Alt+Enter, trailing `\`)
        # already work; for real Shift+Enter under Terminator the user can
        # opt in with `pwn setup --terminal`, which installs
        # third_party/terminator/pwn_shift_enter.py into
        # ~/.config/terminator/plugins/ after asking permission.
        def ensure_vte_shift_enter
          return if self.class.instance_variable_get(:@vte_shift_enter_checked)

          self.class.instance_variable_set(:@vte_shift_enter_checked, true)
          vte_ver = ENV['VTE_VERSION'].to_s
          return if vte_ver.empty?

          in_terminator = !ENV['TERMINATOR_UUID'].to_s.empty? || !ENV['TERMINATOR_DBUS_NAME'].to_s.empty?
          # If the plugin is already installed & enabled, stay silent.
          if in_terminator
            cfg = File.join(Dir.home, '.config', 'terminator', 'config')
            return if File.exist?(cfg) && File.read(cfg).include?('PWNShiftEnter')
          end

          host = if in_terminator then 'Terminator'
                 elsif ENV['GNOME_TERMINAL_SCREEN'] || ENV['GNOME_TERMINAL_SERVICE'] then 'GNOME Terminal'
                 elsif ENV['TILIX_ID'] then 'Tilix'
                 else "a VTE-#{vte_ver} terminal"
                 end

          warn "[pwn] #{host} (libvte) can't distinguish SHIFT+ENTER from ENTER — the modifier is dropped at the emulator."
          warn '[pwn] Multi-line input still works: use ALT+ENTER, or end the line with `\` then ENTER.'
          if in_terminator
            warn '[pwn] For real SHIFT+ENTER support here, run: `pwn setup --terminal` (installs a Terminator plugin — opt-in, one-time).'
          else
            warn '[pwn] For native SHIFT+ENTER, use kitty / wezterm / foot / alacritty / xterm / Konsole / iTerm2 / Terminator.'
          end
        rescue StandardError => e
          warn "[pwn] ensure_vte_shift_enter: #{e.class}: #{e.message}"
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
          PWN::Plugins::REPL.ready_tty!
          # Ask the terminal to encode Shift+Enter distinctly from Enter for
          # the duration of this read. Without this, most emulators send 0x0D
          # for both and SHIFT_ENTER_SEQS can never match. Reset in `ensure`.
          tty = $stdout.respond_to?(:tty?) && $stdout.tty?
          if tty
            $stdout.write(ENABLE_EXTENDED_KEYS)
            $stdout.flush
          end

          begin
            # Plain ENTER submits UNLESS the last non-whitespace char on the
            # last line is `\` (bash/irb/psql-style continuation) — that is
            # the terminal-agnostic fallback for emulators that can't send a
            # distinct SHIFT+ENTER (all VTE hosts). SHIFT+ENTER / ALT+ENTER
            # (matched via SHIFT_ENTER_SEQS) trigger :key_newline directly.
            # Reline handles multi-line pastes by splitting on \n in-buffer.
            @line_buffer = Reline.readmultiline(prompt, true) do |buffer|
              !buffer.split("\n", -1).last.to_s.rstrip.end_with?('\\')
            end || ''
            # Strip the continuation markers before handing off to the caller.
            @line_buffer = @line_buffer.gsub(/\\[ \t]*\n/, "\n")
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

      # Restore the TTY after a spinner / agent turn so Pry/Reline prints
      # the next PS1 immediately. hide_cursor + a background worker leave
      # the cursor hidden on $stdout (Reline's stream) even after
      # TTY::Spinner#stop writes show-cursor to $stderr. Reline then
      # waits for a key without redrawing the prompt.
      public_class_method def self.ready_tty!(opts = {})
        return nil if opts[:skip]

        PWN::Plugins::TTYSpinner.halt_all! if defined?(PWN::Plugins::TTYSpinner)
        out = opts[:io] || $stdout
        return nil unless out.respond_to?(:write)

        show = defined?(TTY::Cursor) ? TTY::Cursor.show : "\e[?25h"
        out.write("\e[0m#{show}")
        $stderr.write("\e[0m#{show}") if $stderr.respond_to?(:write) && $stderr != out
        out.flush if out.respond_to?(:flush)
        reset_reline_editor
        nil
      rescue StandardError
        nil
      end

      private_class_method def self.reset_reline_editor(opts = {})
        return unless opts.is_a?(Hash)
        return unless defined?(Reline)
        return unless Reline.respond_to?(:core)

        editor = Reline.core.instance_variable_get(:@line_editor)
        return unless editor

        editor.instance_variable_set(:@finished, false) if editor.instance_variable_defined?(:@finished)
        nil
      rescue StandardError
        nil
      end

      # Compact token-count formatter for the pwn.ai PS1 (e.g. 0, 843, 12K, 250K, 1M).
      public_class_method def self.compact_context_tokens(opts = {})
        n = opts[:tokens].to_i
        return n.to_s if n < 1_000

        if n >= 1_000_000
          v = n / 1_000_000.0
          s = v >= 10 ? v.round.to_s : format('%.1f', v).sub(/\.0$/, '')
          "#{s}M"
        else
          v = n / 1_000.0
          s = v >= 10 ? v.round.to_s : format('%.1f', v).sub(/\.0$/, '')
          "#{s}K"
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

            # Context-window fill indicator (e.g. "250K/1M") sourced from the last
            # response's usage.total_tokens vs the engine's max_prompt_length.
            used_tokens = PWN::Env[:ai][engine].dig(:response_history, :usage, :total_tokens).to_i
            max_context = PWN::Env[:ai][engine][:max_prompt_length].to_i
            current_context_length = "#{PWN::Plugins::REPL.compact_context_tokens(tokens: used_tokens)}:" \
                                     "#{PWN::Plugins::REPL.compact_context_tokens(tokens: max_context)}"

            pname = "pwn.ai:#{engine}"
            pname = "pwn.ai:#{engine}/#{model}/#{current_context_length}" if model
            pname = "pwn.ai:#{engine}/#{model}/#{current_context_length}.SPEAK" if pi.config.pwn_ai_speak
            pi.config.prompt_name = pname

            name = "\001\e[1m\002\001\e[33m\002#{pi.config.prompt_name}\001\e[0m\002"
            dchars = "\001\e[32m\002>>>\001\e[33m\002"
            dchars = "\001\e[33m\002***\001\e[33m\002" if mode == :splat
            if pi.config.pwn_ai_trace
              dchars = "\001\e[31m\002(TRACE) >>>\001\e[33m\002"
              dchars = "\001\e[31m\002(TRACE) ***\001\e[33m\002" if mode == :splat
            elsif pi.config.pwn_ai_debug
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

            puts '[*] MULTILINE in pwn-asm: SHIFT+ENTER (or ALT+ENTER, or trailing `\\`) inserts a newline; ENTER submits.'
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
              PWN::Sessions.create(title: "pwn-ai #{Time.now.strftime('%Y-%m-%d %H:%M')}", source: 'pwn-ai')
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
            puts "[*] Type 'back' to exit pwn-ai mode."
            puts '[*] MULTILINE in pwn-ai: SHIFT+ENTER (or ALT+ENTER, or trailing `\\`) inserts a newline; ENTER submits to the AI.'
            puts '[*] TAB menus: leading `/` = commands (/cron /skills /sessions …); `/` later = host paths; otherwise Ruby completion (same as the pwn REPL).'
            puts "[*] tmux + terminator users: Ensure ~/.tmux.conf has 'set -s extended-keys on' and 'set -g xterm-keys on', then restart tmux. Use TERM=xterm-256color."
            tag = pi.config.pwn_ai_session_id.to_s.empty? ? '<SESSION_ID>' : pi.config.pwn_ai_session_id
            puts "\n\n\npwn-ai debug ON → /tmp/pwn-ai-DEBUG-#{tag}-R<REQUEST_NUMBER>.log"
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
            # meshtastic is a *setup-managed* gem (see pwn.gemspec / PWN::Setup):
            # its rubygems.org releases carry `required_ruby_version >= 4.0`, so
            # it cannot be a hard runtime dependency while pwn supports ruby 3.3+.
            begin
              require 'meshtastic'
            rescue LoadError => e
              output.puts "pwn-mesh unavailable: #{e.message}"
              output.puts "  meshtastic requires ruby >= 4.0 (running #{RUBY_VERSION})." if Gem::Version.new(RUBY_VERSION) < Gem::Version.new('4.0.0')
              output.puts '  Run: `pwn setup --profile full` (or `gem install meshtastic`) on ruby >= 4.0.'
              return
            end

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
            pwn_env_path = PWN::Env[:driver_opts][:pwn_env_path] ||= "#{Dir.home}/.pwn/pwn.yaml"
            unless File.exist?(pwn_env_path)
              puts "ERROR: pwn environment file not found: #{pwn_env_path}"
              return
            end

            # Prefer driver_opts (set by Config.refresh_env); fall back to the
            # canonical sidecar path Config uses: <pwn.yaml>.decryptor
            pwn_dec_path = PWN::Env[:driver_opts][:pwn_dec_path] ||= "#{pwn_env_path}.decryptor"
            unless File.exist?(pwn_dec_path)
              puts "ERROR: pwn decryptor file not found: #{pwn_dec_path}"
              return
            end

            decryptor = YAML.load_file(pwn_dec_path, symbolize_names: true)
            key = decryptor[:key]
            iv = decryptor[:iv]

            # Vault.edit decrypts -> opens editor -> encrypts and only sets
            # Pry.config.refresh_pwn_env = true. PWN::Config.refresh_env (which
            # raises RuntimeError on invalid pwn.yaml) historically ran later in
            # the PS1 hook, OUTSIDE this command - so the old rescue/retry never
            # saw Config errors. Validate here: on RuntimeError print the error,
            # prompt "Press Enter to Resolve", wait on $stdin.gets, then re-open
            # the editor until the vault loads cleanly.
            loop do
              PWN::Plugins::Vault.edit(
                file: pwn_env_path,
                key: key,
                iv: iv
              )

              begin
                PWN::Config.refresh_env(
                  pwn_env_path: pwn_env_path,
                  pwn_dec_path: pwn_dec_path,
                  key: key,
                  iv: iv
                )
                break
              rescue RuntimeError => e
                # Keep the prior in-memory Env usable if the operator aborts
                # further edits; otherwise the next PS1 tick would raise again.
                Pry.config.refresh_pwn_env = false if defined?(Pry)
                print "\001\e[33m\002"
                puts e.message
                print 'Press ENTER to resolve...'
                print "\001\e[0m\002\s"
                $stdin.gets
              end
            end
          rescue StandardError => e
            raise e
          end
        end

        Pry::Commands.create_command 'toggle-debug' do
          description 'Stream pwn-ai stage log to the TUI and /tmp/pwn-ai-DEBUG-<SESSION_ID>-RN.log'

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

        Pry::Commands.create_command 'back' do
          description 'Jump back to pwn REPL when in pwn-asm || pwn-ai.'

          def process
            pi = pry_instance
            pi.config.color = true
            pi.config.pwn_asm = false if pi.config.pwn_asm
            pi.config.pwn_ai = false if pi.config.pwn_ai
            pi.config.pwn_ai_agent = false if pi.config.pwn_ai_agent
            # pi.config.pwn_ai_debug = false if pi.config.pwn_ai_debug
            pi.config.pwn_ai_speak = false if pi.config.pwn_ai_speak
            pi.config.completer = Pry::InputCompleter
            PWN::Plugins::REPL.restore_pwn_ai_completer!
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
            if PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: orig_request, pry: pi)
              request.replace('nil')
              next
            end

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
                # on_tool UI contract: Loop.run emits ONE name='task' brief
                # BEFORE each tool *collection* (TaskSummarizer.about_to with
                # tools: [...]). arg_preview is plain-English what/why for
                # executives. Task lines never show a result row — results
                # belong only to the subsequent per-tool lines (one-to-many).
                on_tool = lambda do |name, args, result|
                  # Task summaries are shown in their entirety (multi-line OK).
                  # Tool request + result are shown in full (no char cap).
                  # Raw ANSI only — PS1 SOH/STX on live stdout swallows later rows.
                  # When debug is on, the same plain text is mirrored into the
                  # open /tmp pwn-ai-DEBUG-…-RN.log for human troubleshooting.
                  mirror = lambda do |plain|
                    next unless pi.config.pwn_ai_debug && defined?(PWN::Plugins::Log)

                    PWN::Plugins::Log.mirror_tui!(msg: plain)
                  end
                  if name.to_s == 'task'
                    body = args.is_a?(String) ? args.to_s : args.inspect
                    timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
                    header = "[ #{timestamp} → pwn-ai → task ]"
                    print "\e[33m#{header}\e[0m "
                    body_out = +''
                    body.to_s.each_line do |ln|
                      puts "\e[32m  #{ln.rstrip}\e[0m"
                      body_out << "  #{ln.rstrip}\n"
                    end
                    mirror.call("#{header}\n#{body_out}")
                    next
                  end

                  argv = args.is_a?(String) ? args.to_s : args.inspect
                  timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
                  header = "[ #{timestamp} → pwn-ai → #{name} ]"
                  puts "\e[33m#{header}\e[0m"
                  argv_out = +''
                  argv.to_s.each_line do |ln|
                    puts "\e[33m  #{ln.rstrip}\e[0m"
                    argv_out << "  #{ln.rstrip}\n"
                  end

                  timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
                  res_header = "#{timestamp} → result"
                  puts "\e[36m#{res_header}\e[0m"
                  res_out = +''
                  result.to_s.each_line do |ln|
                    puts "\e[36m  #{ln.rstrip}\e[0m"
                    res_out << "  #{ln.rstrip}\n"
                  end
                  puts
                  mirror.call("#{header}\n#{argv_out}#{res_header}\n#{res_out}\n")
                end
                final = PWN::AI::Agent::Loop.run(
                  request: orig_request,
                  session_id: sess_id,
                  enabled_toolsets: PWN::Env.dig(:ai, :agent, :toolsets),
                  on_tool: on_tool,
                  debug: pi.config.pwn_ai_debug,
                  debug_tee: $stdout
                )
                $stdout.flush
                puts "\n\e[32m#{final}\e[0m\n\n"
                $stdout.flush
                PWN::Plugins::Log.mirror_tui!(msg: "\n#{final}\n\n") if pi.config.pwn_ai_debug && defined?(PWN::Plugins::Log)
                if pi.config.pwn_ai_debug && sess_id && PWN.const_defined?(:Sessions)
                  PWN::Plugins::Log.progress(
                    msg: "session=#{sess_id}",
                    which_self: PWN::Sessions
                  )
                end
                request.replace('nil')
                next
              rescue Interrupt
                Thread.current[:pwn_log_progress] = false
                PWN::Plugins::Log.note_interrupt!(where: 'CTRL+C', which_self: PWN::Plugins::REPL) if pi.config.pwn_ai_debug && defined?(PWN::Plugins::Log)
                raise
              rescue StandardError => e
                PWN::Plugins::Log.note_exception!(error: e, where: 'native agent loop', which_self: PWN::Plugins::REPL) if defined?(PWN::Plugins::Log) && PWN::Plugins::Log.respond_to?(:note_exception!)
                warn "[pwn-ai] native agent loop failed (#{e.class}: #{e.message.to_s.split("\n").first})"
                request.replace('nil')
                next
              ensure
                PWN::Plugins::REPL.ready_tty!
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
                spinner: false
              }
              chat_opts[:system_role_content] = system_role if system_role

              case engine
              when :anthropic
                response = PWN::AI::Anthropic.chat(chat_opts)
              when :gemini
                response = PWN::AI::Gemini.chat(chat_opts)
              when :grok
                response = PWN::AI::Grok.chat(chat_opts)
              when :ollama
                response = PWN::AI::Ollama.chat(chat_opts)
              when :openai
                response = PWN::AI::OpenAI.chat(chat_opts)
              when :openwebui
                response = PWN::AI::OpenWebUI.chat(chat_opts)
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
            request.replace('nil') if request.respond_to?(:replace)
            PWN::Plugins::REPL.ready_tty!
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

      PWN_AI_SLASH_COMMANDS = %w[
        /back /cron /debug /delegate /help /memory /model /sessions /skills /trace
      ].freeze

      PWN_AI_SLASH_SUBCOMMANDS = {
        '/cron' => %w[list create run remove],
        '/debug' => [],
        '/trace' => [],
        '/delegate' => [],
        '/help' => [],
        '/memory' => %w[list recall remember forget clear],
        '/model' => %w[list],
        '/sessions' => %w[list resume delete stats],
        '/skills' => %w[list recall]
      }.freeze

      # Supported Method Parameters::
      # kind = PWN::Plugins::REPL.pwn_ai_complete_kind(line: 'optional - current input buffer')
      #
      # 1. first char is '/' → :command (pwn-ai slash menu)
      # 2. '/' anywhere else → :path (host-native file nav)
      # 3. else → :ruby (same Pry::InputCompleter menu as the pwn REPL)
      public_class_method def self.pwn_ai_complete_kind(opts = {})
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
      public_class_method def self.pwn_ai_complete(opts = {})
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

      public_class_method def self.pwn_ai_complete_command(opts = {})
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
        subs = Array(PWN_AI_SLASH_SUBCOMMANDS[cmd])
        hits = subs.select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) }
        hits = [target] if hits.empty? && !target.empty?
        hits
      end

      public_class_method def self.pwn_ai_complete_path(opts = {})
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

      public_class_method def self.pwn_ai_complete_ruby(opts = {})
        target = opts[:target].to_s
        pry = opts[:pry] || Thread.current[:pwn_ai_completer_pry]
        return [] unless defined?(Pry::InputCompleter)

        return Array(pry.complete(target)) if pry.respond_to?(:complete)

        Array(Pry::InputCompleter.new(pry || Pry.new(quiet: true)).call(target))
      rescue StandardError
        []
      end

      # Install Reline dropdown for pwn-ai (commands / paths / Ruby).
      public_class_method def self.install_pwn_ai_completer!(opts = {})
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

      public_class_method def self.restore_pwn_ai_completer!(opts = {})
        return unless defined?(Reline)

        Thread.current[:pwn_ai_completer_pry] = nil
        Reline.completion_proc = @pwn_ai_prev_completion_proc if @pwn_ai_prev_completion_proc
        Reline.completer_word_break_characters = @pwn_ai_prev_word_break if @pwn_ai_prev_word_break && Reline.respond_to?(:completer_word_break_characters=)
        enable_autocomplete(enabled: opts.fetch(:enabled, true))
        Reline.completion_proc
      end

      # Run a leading-slash pwn-ai command locally. Returns true when handled
      # (caller should not send the line to Loop.run).
      public_class_method def self.pwn_ai_dispatch_slash!(opts = {})
        request = opts[:request].to_s
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
        end
        true
      rescue StandardError => e
        warn "[pwn-ai] #{cmd}: #{e.class}: #{e.message}"
        true
      end

      public_class_method def self.pwn_ai_engines(opts = {})
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

      public_class_method def self.pwn_ai_provider_class(opts = {})
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

      public_class_method def self.pwn_ai_model_ids(opts = {})
        raw = opts[:models]
        rows = case raw
               when Array then raw
               when Hash then raw[:data] || raw[:models] || raw['data'] || raw['models'] || []
               else []
               end
        Array(rows).filter_map do |row|
          if row.is_a?(Hash)
            row[:id] || row['id'] || row[:name] || row['name'] || row[:model] || row['model']
          else
            row.to_s
          end
        end.map(&:to_s).reject(&:empty?).uniq
      end

      public_class_method def self.pwn_ai_list_llms(opts = {})
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

      public_class_method def self.pwn_ai_engine_model(opts = {})
        engine = opts[:engine].to_s.downcase.to_sym
        return '' if engine.empty?
        return '' unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

        PWN::Env.dig(:ai, engine, :model).to_s
      end

      public_class_method def self.pwn_ai_run_model(opts = {})
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

      public_class_method def self.persist_ai_selection(opts = {})
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

      public_class_method def self.pwn_ai_run_cron(opts = {})
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

      public_class_method def self.pwn_ai_run_sessions(opts = {})
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

      public_class_method def self.pwn_ai_run_memory(opts = {})
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

      public_class_method def self.pwn_ai_run_skills(opts = {})
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
      # Scope: this drives the MAIN pwn REPL (Ruby).  pwn-ai swaps
      # PWNMultiLineInput onto Reline.readmultiline and installs
      # install_pwn_ai_completer! so TAB is command / path / Ruby menus.
      # pwn-asm keeps opcode input without those menus.

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
          # Restore the TTY after a spinner / agent turn so Pry/Reline prints
          #{self}.ready_tty!(
            skip: 'optional - skip value consumed by #ready_tty!',
            io: 'optional - io value consumed by #ready_tty!'
          )

          # Compact token-count formatter for the pwn.ai PS1 (e.g. 0, 843, 12K, 250K, 1M)
          #{self}.compact_context_tokens(
            tokens: 'optional - tokens value consumed by #compact_context_tokens'
          )

          # Run refresh ps1 proc and return its result
          #{self}.refresh_ps1_proc(
            mode: 'optional - mode value consumed by #refresh_ps1_proc'
          )

          # Run add commands and return its result
          #{self}.add_commands

          # Run add hooks and return its result
          #{self}.add_hooks

          # Run pwn ai complete kind and return its result
          #{self}.pwn_ai_complete_kind(
            line: 'optional - line value consumed by #pwn_ai_complete_kind'
          )

          # Run pwn ai complete and return its result
          #{self}.pwn_ai_complete(
            target: 'required - token Reline is completing',
            line: 'optional - full line buffer',
            pry: 'optional - Pry instance for Ruby completion'
          )

          # Run pwn ai complete command and return its result
          #{self}.pwn_ai_complete_command(
            line: 'optional - line value consumed by #pwn_ai_complete_command',
            target: 'required - hostname, IP, or CIDR to scan'
          )

          # Run pwn ai complete path and return its result
          #{self}.pwn_ai_complete_path(
            target: 'required - hostname, IP, or CIDR to scan',
            line: 'optional - line value consumed by #pwn_ai_complete_path'
          )

          # Run pwn ai complete ruby and return its result
          #{self}.pwn_ai_complete_ruby(
            target: 'optional - hostname, IP, or CIDR to scan',
            pry: 'optional - pry value consumed by #pwn_ai_complete_ruby (defaults to Thread.current[:pwn_ai_completer_pry])'
          )

          # Install Reline dropdown for pwn-ai (commands / paths / Ruby)
          #{self}.install_pwn_ai_completer!(
            pry: 'optional - pry value consumed by #install_pwn_ai_completer!'
          )

          # Run restore pwn ai completer and return its result
          #{self}.restore_pwn_ai_completer!

          # Run a leading-slash pwn-ai command locally. Returns true when handled
          #{self}.pwn_ai_dispatch_slash!(
            request: 'optional - request value consumed by #pwn_ai_dispatch_slash!',
            pry: 'optional - pry value consumed by #pwn_ai_dispatch_slash!'
          )

          # Run pwn ai engines and return its result
          #{self}.pwn_ai_engines

          # Run pwn ai provider class and return its result
          #{self}.pwn_ai_provider_class(
            engine: 'optional - engine value consumed by #pwn_ai_provider_class'
          )

          # Run pwn ai model ids and return its result
          #{self}.pwn_ai_model_ids(
            models: 'optional - models value consumed by #pwn_ai_model_ids'
          )

          # Run pwn ai list llms and return its result
          #{self}.pwn_ai_list_llms(
            engine: 'required - engine value consumed by #pwn_ai_list_llms'
          )

          # Run pwn ai engine model and return its result
          #{self}.pwn_ai_engine_model(
            engine: 'required - engine value consumed by #pwn_ai_engine_model'
          )

          # Run pwn ai run model and return its result
          #{self}.pwn_ai_run_model(
            args: 'optional - Array args value consumed by #pwn_ai_run_model'
          )

          # Run persist ai selection and return its result
          #{self}.persist_ai_selection(
            engine: 'required - engine value consumed by #persist_ai_selection',
            model: 'required - model value consumed by #persist_ai_selection'
          )

          # Run pwn ai run cron and return its result
          #{self}.pwn_ai_run_cron(
            args: 'optional - Array args value consumed by #pwn_ai_run_cron'
          )

          # Run pwn ai run sessions and return its result
          #{self}.pwn_ai_run_sessions(
            args: 'optional - Array args value consumed by #pwn_ai_run_sessions'
          )

          # Run pwn ai run memory and return its result
          #{self}.pwn_ai_run_memory(
            args: 'optional - Array args value consumed by #pwn_ai_run_memory'
          )

          # Run pwn ai run skills and return its result
          #{self}.pwn_ai_run_skills(
            args: 'optional - Array args value consumed by #pwn_ai_run_skills'
          )

          # IRB-style suggest-as-you-type for the pwn REPL
          #{self}.enable_autocomplete(
            enabled: 'optional - Boolean (default true). false reverts to single-line cycling.',
            graph: 'optional - constants (PWN::Plugins::Nm<TAB>), instance methods'
          )

          # Run start and return its result
          #{self}.start

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
