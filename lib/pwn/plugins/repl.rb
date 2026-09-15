# frozen_string_literal: true

require 'curses'
require 'pry'
require 'reline'
require 'tty-cursor'
require 'tty-prompt'
require 'unicode/display_width'
require 'yaml'
require 'json'
require 'base64'

module PWN
  module Plugins
    # This module contains methods related to the pwn REPL Driver.
    module REPL
      autoload :ASM, 'pwn/plugins/repl/asm'
      autoload :AI, 'pwn/plugins/repl/ai'
      autoload :Mesh, 'pwn/plugins/repl/mesh'
      autoload :Vault, 'pwn/plugins/repl/vault'

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
            end
            return nil if @line_buffer.nil?

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

        PWN::Plugins::REPL::ASM.add_commands
        PWN::Plugins::REPL::AI.add_commands
        PWN::Plugins::REPL::Mesh.add_commands
        PWN::Plugins::REPL::Vault.add_commands

        Pry::Commands.create_command 'back' do
          description 'Jump back to pwn REPL when in pwn-asm || pwn-ai. CTRL+D does the same in those modes.'

          def process
            PWN::Plugins::REPL.leave_special_mode!(pry: pry_instance)
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
                  # open ~/.pwn/logs/pwn-ai-DEBUG-…-RN.log for human troubleshooting.
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
            orig_request = request.to_s.chomp
            if PWN::Plugins::REPL.pwn_mesh_dispatch_slash!(request: orig_request, pry: pi)
              PWN::Plugins::REPL.mesh_reset_input!(pry: pi, submitted: orig_request)
              request.replace('nil') if request.respond_to?(:replace)
              next
            end

            mqtt_obj = PWN.const_get(:MeshObj)
            mesh_env = PWN::Env[:plugins][:meshtastic]
            PWN::Plugins::REPL.send(:mesh_compose_send, env: mesh_env, obj: mqtt_obj, text: orig_request)
            PWN::Plugins::REPL.mesh_reset_input!(pry: pi, submitted: orig_request)
            request.replace('nil') if request.respond_to?(:replace)
          end
        end
      rescue StandardError => e
        raise e
      end

      # Leave pwn-ai / pwn-asm / pwn-mesh and restore the host REPL (also CTRL+D).
      public_class_method def self.leave_special_mode!(opts = {})
        pi = opts[:pry]
        return nil unless pi.respond_to?(:config)

        pi.config.color = true
        pi.config.pwn_asm = false if pi.config.pwn_asm
        pi.config.pwn_ai = false if pi.config.pwn_ai
        pi.config.pwn_ai_agent = false if pi.config.pwn_ai_agent
        pi.config.pwn_ai_speak = false if pi.config.pwn_ai_speak
        pi.config.completer = Pry::InputCompleter
        restore_pwn_ai_completer!
        if pi.config.pwn_ai_original_input
          pi.config.input = pi.config.pwn_ai_original_input
          pi.config.pwn_ai_original_input = nil
        end
        return pi unless pi.config.pwn_mesh

        pi.config.pwn_mesh = false
        if PWN.const_defined?(:MeshTxEchoThread)
          PWN.const_get(:MeshTxEchoThread).kill
          PWN.send(:remove_const, :MeshTxEchoThread)
        end
        if PWN.const_defined?(:MeshObj)
          PWN::Plugins::REPL.send(
            :mesh_disconnect,
            env: (defined?(PWN::Env) && PWN::Env.dig(:plugins, :meshtastic)) || {},
            obj: PWN.const_get(:MeshObj)
          )
          PWN.send(:remove_const, :MeshObj)
        end
        PWN.send(:remove_const, :MqttObj) if PWN.const_defined?(:MqttObj)
        if PWN.const_defined?(:MeshSubThread)
          thr = PWN.const_get(:MeshSubThread)
          thr.kill if thr.respond_to?(:alive?) && thr.alive?
          PWN.send(:remove_const, :MeshSubThread)
        end
        PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
        PWN.send(:remove_const, :MeshTxPrompt) if PWN.const_defined?(:MeshTxPrompt)
        PWN.send(:remove_const, :MeshTxEpoch) if PWN.const_defined?(:MeshTxEpoch)
        PWN.send(:remove_const, :MeshTxBlank) if PWN.const_defined?(:MeshTxBlank)
        PWN.send(:remove_const, :MeshLastSubmit) if PWN.const_defined?(:MeshLastSubmit)
        PWN.send(:remove_const, :MeshRxState) if PWN.const_defined?(:MeshRxState)
        if PWN.const_defined?(:MeshRxHeaderWin)
          PWN.const_get(:MeshRxHeaderWin).close
          PWN.send(:remove_const, :MeshRxHeaderWin)
        end
        if PWN.const_defined?(:MeshRxFrameWin)
          PWN::MeshRxFrameWin.close
          PWN.send(:remove_const, :MeshRxFrameWin)
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
        PWN.send(:remove_const, :MeshEvents) if PWN.const_defined?(:MeshEvents)
        Curses.close_screen
        pi
      end

      # Consume a CLI-prepared session once; ordinary activation creates one.
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

      public_class_method def self.start(opts = {})
        ai_session_id = opts[:ai_session_id]
        settings = PWN::Env[:driver_opts]

        # Monkey Patch Pry, add commands, && hooks
        PWN::Plugins::MonkeyPatch.pry
        pwn_env_root = "#{Dir.home}/.pwn"
        Pry.config.history_file = "#{pwn_env_root}/pwn_history"

        add_commands
        add_hooks

        # IRB-style suggest-as-you-type dropdown (off via
        # PWN::Env[:driver_opts][:autocomplete] = false in pwn.yaml).
        ac = settings.key?(:autocomplete) ? settings[:autocomplete] : true
        enable_autocomplete(enabled: ac)

        # Define PS1 Prompt
        Pry.config.pwn_repl_line = 0
        Pry.config.prompt_name = :pwn
        arrow_ps1_proc = refresh_ps1_proc(settings)

        settings[:mode] = :splat
        splat_ps1_proc = refresh_ps1_proc(settings)

        ps1 = [arrow_ps1_proc, splat_ps1_proc]
        prompt = Pry::Prompt.new(:pwn, 'PWN Prototyping REPL', ps1)

        # Start PWN REPL
        # Pry.start(self, prompt: prompt)
        if ai_session_id
          hooks = Pry.config.hooks.dup
          hooks.add_hook(:before_session, :pwn_ai_cli) do |_output, _binding, pi|
            pi.config.pwn_ai_startup_session_id = ai_session_id
            pi.run_command('pwn-ai')
          end
          Pry.start(Pry.main, prompt: prompt, hooks: hooks)
        else
          Pry.start(Pry.main, prompt: prompt)
        end
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

          # Leave pwn-ai, pwn-asm, or pwn-mesh (also invoked by CTRL+D).
          #{self}.leave_special_mode!(
            pry: 'required - Pry instance whose special mode should end'
          )

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

          # List or requeue conflicted learning outcomes.
          #{self}.pwn_ai_run_learning(
            args: 'optional - list [--conflicted] or requeue'
          )

          # Run pwn ai run skills and return its result
          #{self}.pwn_ai_run_skills(
            args: 'optional - Array args value consumed by #pwn_ai_run_skills'
          )

          # Run pwn-ai /mcp locally without Loop.run
          #{self}.pwn_ai_run_mcp(
            args: 'optional - slash tokens after /mcp such as list tools or call menu_catalog'
          )

          # Curses arrow-key picker for pwn-mesh channel, transport, and device lists
          #{self}.mesh_menu_pick(
            title: 'optional - window title drawn on the boxed curses menu',
            items: 'required - Array of selectable strings such as channel names',
            current: 'optional - currently selected item to highlight',
            getch: 'optional - proc returning the next key so specs can drive the menu without a TTY'
          )

          # Clear the pwn-mesh TX buffer after a slash command or sent mesh line
          #{self}.mesh_reset_input!(
            pry: 'optional - Pry instance whose Reline/line_buffer should be emptied',
            submitted: 'optional - the line that was just accepted so the TX pane can hide it'
          )

          # Curses overlay rows for the pwn-mesh slash menu while typing a leading slash
          #{self}.pwn_mesh_menu_rows(
            line: 'optional - current TX buffer; leading slash lists matching mesh commands'
          )

          # TAB hits for pwn-mesh slash menus (commands, named channels, transports, devices)
          #{self}.pwn_mesh_complete(
            target: 'required - token Reline is completing in pwn-mesh',
            line: 'optional - full line buffer so /channel P<TAB> can list named channels'
          )

          # Install Reline dropdown for pwn-mesh slash commands
          #{self}.install_pwn_mesh_completer!(
            pry: 'optional - Pry instance stored for mesh TAB completion'
          )

          # Run a leading-slash pwn-mesh command locally instead of sending it as mesh text
          #{self}.pwn_mesh_dispatch_slash!(
            request: 'optional - full line such as /channel list or /transport serial',
            pry: 'optional - Pry instance used by /back to leave pwn-mesh'
          )

          # Write plugins.meshtastic from the live Env into the encrypted pwn.yaml vault
          #{self}.persist_mesh_env(
            mesh: 'optional - meshtastic Hash to persist (defaults to PWN::Env plugins.meshtastic)'
          )

          # IRB-style suggest-as-you-type for the pwn REPL
          #{self}.enable_autocomplete(
            enabled: 'optional - Boolean (default true). false reverts to single-line cycling.',
            graph: 'optional - constants (PWN::Plugins::Nm<TAB>), instance methods'
          )

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

          # Run start and return its result
          #{self}.start(ai_session_id: 'optional - prepared CLI session id')

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end

require_relative 'repl/asm'
require_relative 'repl/ai'
require_relative 'repl/mesh'
require_relative 'repl/vault'
