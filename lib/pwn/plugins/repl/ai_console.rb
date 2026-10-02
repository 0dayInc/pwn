# frozen_string_literal: true

require 'curses'
require 'io/console'
require 'io/wait'
require 'fcntl'
require 'unicode/display_width'

module PWN
  module Plugins
    module REPL
      # Single-owner fullscreen agent console. Workers never paint the terminal.
      module AIConsole
        public_class_method def self.run(opts = {})
          input = opts[:input] || $stdin
          output = opts[:output] || $stdout
          return :unavailable unless input.tty? && output.tty? && ENV['TERM'] != 'dumb'

          Console.new(pry: opts[:pry], input: input, curses: opts[:curses] || Curses, getch: opts[:getch]).run
        end

        # Ruby output is queued, never written across the curses screen.
        class EventIO
          attr_accessor :sync

          def initialize(queue)
            @queue = queue
            @buffer = +''
            @lock = Mutex.new
          end

          def write(value)
            text = value.to_s
            @lock.synchronize do
              @buffer << text
              while (line = @buffer.slice!(/.*?\n/m))
                @queue << [:notice, line]
              end
              if @buffer.bytesize > 16_384
                @queue << [:notice, '[output withheld: unterminated stream exceeds 16 KiB]']
                @buffer.clear
              end
            end
            text.bytesize
          end

          def puts(*values)
            values = [''] if values.empty?
            values.each { |value| write("#{value.to_s.chomp}\n") }
            nil
          end

          def print(*values)
            values.each { |value| write(value) }
            nil
          end

          def flush
            @lock.synchronize do
              unless @buffer.empty?
                @queue << [:notice, @buffer.dup]
                @buffer.clear
              end
            end
            self
          end

          def tty?
            false
          end
          alias isatty tty?

          def close
            nil
          end

          def closed?
            false
          end
        end

        # Reuse the model-window interrupt protection and evidence checkpoints.
        # Cancellation never raises asynchronously into a tool.
        class Control < PWN::AI::Agent::Loop::Steering
          class Stopped < Exception; end # rubocop:disable Lint/InheritException

          def stop
            @stopping = true
            submit('Stop the active request.')
          end

          def checkpoint(messages:, phase: :boundary, &block)
            if @stopping
              block&.call
              raise Stopped, 'Request cancelled at a safe boundary; completed work is not undone.'
            end
            super
          end

          def phase
            @mutex.synchronize { @pending.empty? ? @phase : "steering queued · #{@phase}" }
          end
        end

        # Read a duplicated terminal rather than stdin, which belongs to tools.
        class Keyboard
          KEYS = {
            "\e[A" => :up, "\e[B" => :down, "\e[C" => :right, "\e[D" => :left,
            "\eOA" => :up, "\eOB" => :down, "\eOC" => :right, "\eOD" => :left,
            "\e[H" => :home, "\e[F" => :end, "\eOH" => :home, "\eOF" => :end,
            "\e[1~" => :home, "\e[4~" => :end, "\e[3~" => :delete,
            "\e[5~" => :page_up, "\e[6~" => :page_down,
            "\e[13;2u" => :newline, "\e[27;2;13~" => :newline, "\e[200~" => :paste_start, "\e[201~" => :paste_end
          }.freeze

          def initialize(source)
            @source = source
            @buffer = +''.b
          end

          def call
            if @source.wait_readable(@buffer.empty? ? 0.04 : 0)
              chunk = @source.read_nonblock(4096, exception: false)
              return :eof if chunk.nil? && @buffer.empty?

              @buffer << chunk if chunk.is_a?(String)
            end
            return if @buffer.empty?

            match = KEYS.keys.find { |key| @buffer.start_with?(key) }
            return KEYS.fetch(@buffer.slice!(0, match.bytesize)) if match

            cursor = cursor_key
            return cursor unless cursor == :pending
            return if KEYS.keys.any? { |key| key.start_with?(@buffer) } && @source.wait_readable(0.04)

            decode_character
          end

          def cursor_key
            match = @buffer.match(/\A\e\[([0-9;]*)([ABCDHF])/)
            return :pending unless match
            return :pending if KEYS.keys.any? { |key| key.start_with?(match[0]) && key != match[0] }

            @buffer.slice!(0, match[0].bytesize)
            modifier = match[1].split(';')[1].to_i
            return if modifier > 1

            { 'A' => :up, 'B' => :down, 'C' => :right, 'D' => :left, 'H' => :home, 'F' => :end }[match[2]]
          end

          def decode_character
            lead = @buffer.getbyte(0)
            size = case lead
                   when 0..127 then 1
                   when 194..223 then 2
                   when 224..239 then 3
                   when 240..244 then 4
                   else 0
                   end
            prefix = @buffer.bytes.take(size)
            valid = size.positive? && prefix.drop(1).all? { |byte| byte.between?(128, 191) }
            second = prefix[1]
            valid &&= !(second && ((lead == 224 && second < 160) || (lead == 237 && second > 159) ||
                                  (lead == 240 && second < 144) || (lead == 244 && second > 143)))
            if valid
              return if @buffer.bytesize < size

              return @buffer.slice!(0, size).force_encoding(Encoding::UTF_8)
            end
            @buffer.slice!(0, 1)
            '�'
          end
        end

        # Unicode grapheme editing and request recall from shared Pry history.
        class Editor
          attr_reader :text, :cursor, :search

          def initialize
            @text = +''
            @cursor = 0
            @history = []
            @index = 0
          end

          def preload(lines)
            Array(lines).each do |line|
              next if line.to_s.strip.empty? || line.match?(%r{\A\s*/input(?:\s|\z)}) || @history.last == line

              @history << line.dup
            end
            @index = @history.length
          end

          def insert(text)
            chars = @text.scan(/\X/)
            prefix = chars.take(@cursor).join + text
            @text = prefix + chars.drop(@cursor).join
            @cursor = prefix.scan(/\X/).length
          end

          def replace(text)
            @text = text.dup
            @cursor = @text.scan(/\X/).length
          end

          def edit(key)
            chars = @text.scan(/\X/)
            case key
            when :left then @cursor = [@cursor - 1, 0].max
            when :right then @cursor = [@cursor + 1, chars.length].min
            when :home, "\u0001" then @cursor = 0
            when :end, "\u0005" then @cursor = chars.length
            when :delete then chars.delete_at(@cursor)
            when "\u007f", "\b"
              chars.delete_at(@cursor -= 1) if @cursor.positive?
            when "\u0015" then chars.clear
                               @cursor = 0
            end
            @text = chars.join
          end

          def recall(direction)
            return if @history.empty?
            return if direction == :up && @index.zero?
            return if direction == :down && @index == @history.length

            @draft = [@text.dup, @cursor] if @index == @history.length
            @index += direction == :up ? -1 : 1
            if @index == @history.length
              @text, @cursor = @draft
              @text = @text.dup
            else
              replace(@history[@index])
            end
          end

          def search_history(query = '', older: false)
            start = older && @search ? @search[:index] : @history.length
            index = (start - 1).downto(0).find { |position| @history[position].include?(query) }
            @search = { query: query, index: index || start, match: index ? @history[index].dup : nil }
          end

          def finish_search(accept: false)
            if accept && @search&.dig(:match)
              replace(@search[:match])
              @index = @history.length
            end
            @search = nil
          end

          def place(text, cursor)
            replace(text)
            @cursor = cursor.to_i.clamp(0, @text.scan(/\X/).length)
          end

          def submit
            line = @text.dup
            @history << line.dup unless line.strip.empty? || @history.last == line || line.match?(%r{\A\s*/input(?:\s|\z)})
            @index = @history.length
            replace('')
            line
          end
        end

        # Own the terminal, event pump and the lifetime of exactly one request.
        class Console # rubocop:disable Metrics/ClassLength -- cohesive single-owner terminal state machine
          COLORS = { operator: :operator, task: :task, thinking: :notice, tool: :tool, result: :result, assistant: :assistant, notice: :notice, warning: :warning }.freeze
          PALETTE = %w[cyan green yellow red white blue magenta black].freeze

          def initialize(pry:, input:, curses:, getch:)
            @pry = pry
            @input = input
            @curses = curses
            @getch = getch
            @events = Queue.new
            @output = EventIO.new(@events)
            @editor = Editor.new
            @timeline = []
            @scroll = nil
            @focus = :mission
            @event_count = @completed_tools = @unseen = 0
            @verbose = true
            @usage = AIConsoleUsage::Tracker.new
          end

          def run
            previous = [$stdin, $stdout, PWN::Plugins::Log.raw_stderr, @pry.config.output]
            flags = @input.fcntl(Fcntl::F_GETFL)
            source = @input.dup
            @source = source
            source.raw do
              enable_shift_enter
              @swarm = AISwarm::Controller.new(session_id: @pry.config.pwn_ai_session_id)
              @screen = @curses.init_screen
              @curses.raw
              @curses.noecho
              @curses.curs_set(1)
              setup_colors
              # Curses only paints; Keyboard owns the duplicated terminal.
              forwarded, @tool_input = IO.pipe
              @input.reopen(forwarded)
              forwarded.close
              $stdin = @input
              $stdout = $stderr = @output
              @pry.config.output = @output
              if PWN::Plugins::Log.debug_enabled?
                PWN::Plugins::Log.send(:remove_stderr_tee!)
                PWN::Plugins::Log.send(:install_stderr_tee!)
                PWN::Plugins::Log.start_debug(tee: @output, session_id: @pry.config.pwn_ai_session_id)
              end
              @getch ||= Keyboard.new(source)
              seed_request_history
              add(:notice, 'Ready. Submit a task · / or Tab opens commands · /steer redirects while busy.')
              add(:notice, 'Tool prompts: /input TEXT forwards one line. Raw/fullscreen tools and direct /dev/tty readers are unsupported.')
              event_loop
            ensure
              begin
                stop_worker
              ensure
                begin
                  @input.reopen(source)
                  @input.fcntl(Fcntl::F_SETFL, flags)
                  @tool_input&.close unless @tool_input&.closed?
                ensure
                  @curses.close_screen if @screen
                end
              end
            end
            :closed
          ensure
            restore_streams(previous) if previous
            disable_shift_enter
            source&.close
          end

          def enable_shift_enter
            return unless $stdout.tty?

            system('tmux', 'set', '-s', 'extended-keys', 'on', out: File::NULL, err: File::NULL) unless ENV['TMUX'].to_s.empty?
            $stdout.write("\e[>4;1m\e[>1u")
            $stdout.flush
            @shift_enter = true
          rescue StandardError
            nil
          end

          def disable_shift_enter
            return unless @shift_enter && $stdout.tty?

            $stdout.write("\e[<u\e[>4;0m")
            $stdout.flush
          rescue StandardError
            nil
          end

          def restore_streams(previous)
            log = PWN::Plugins::Log
            rebind_stderr = log.debug_enabled? && log.raw_stderr.equal?(@output)
            # Keep the open RN file and trace state, but never leave a logger
            # referencing the now-closed console's event queue.
            log.send(:remove_stderr_tee!) if rebind_stderr
            $stdin, $stdout, $stderr, @pry.config.output = previous
            return unless log.debug_enabled?

            log.start_debug(tee: previous[1], session_id: @pry.config.pwn_ai_session_id)
            log.send(:install_stderr_tee!) if rebind_stderr
          end

          def setup_colors
            @color = !ENV.key?('NO_COLOR') && @curses.has_colors?
            return unless @color

            @curses.start_color
            @curses.use_default_colors
            PALETTE.each_with_index do |name, index|
              @curses.init_pair(index + 1, Curses.const_get("COLOR_#{name.upcase}"), -1)
            end
            # Artwork owns complete foreground/background pairs, separate from
            # semantic theme colors. Never silently drop a colored background.
            @banner_colors = @curses.color_pairs > PALETTE.length * 2
            return unless @banner_colors

            PALETTE.each_with_index do |name, index|
              @curses.init_pair(PALETTE.length + index + 1, Curses.const_get("COLOR_#{name.upcase}"), Curses::COLOR_BLACK)
            end
            @banner_two_colors = @curses.color_pairs > PALETTE.length + (PALETTE.length**2)
            return unless @banner_two_colors

            PALETTE.reject { |name| name == 'black' }.each_with_index do |background, bg_index|
              PALETTE.each_with_index do |foreground, fg_index|
                @curses.init_pair(17 + (bg_index * 8) + fg_index, Curses.const_get("COLOR_#{foreground.upcase}"), Curses.const_get("COLOR_#{background.upcase}"))
              end
            end
          end

          def event_loop
            loop do
              drain
              break if @leaving && !busy?

              draw
              handle(@getch.call)
            rescue Interrupt
              cancel
            end
          end

          def busy?
            request_busy = @worker && (@worker.alive? || @running)
            request_busy || @swarm&.busy?
          end

          def drain
            200.times do
              type, text = @events.pop(true)
              if type == :model_prompt
                next if @cancelling || @leaving

                @model_prompt = text
                @model_index = text[:efforts].index(text[:default]) || 0
                @menu = nil
              elsif type == :done
                @worker.join
                finish_request_metrics
                @running = false
                @control = nil
              else
                add(type, text)
              end
            end
          rescue ThreadError
            nil
          end

          def add(type, text)
            clean = PWN::Redaction.redact(value: text.to_s)
            clean = clean.gsub(/\e\][^\a]*(?:\a|\e\\)/, '').gsub(%r{\e\[[0-?]*[ -/]*[@-~]}, '').gsub(/[\x00-\x08\x0b-\x1f\x7f]/, '')
            return if clean.strip.empty?

            @event_count += 1
            @unseen += 1 if @scroll
            if type == :tool
              @completed_tools += 1
              @last_tool = fit(clean.lines.first.to_s.strip, 80)
            end
            @timeline << [type, bounded_event(clean), Time.now.strftime('%Y-%m-%d %H:%M:%S%z'), {}]
            @rows = nil
            if @timeline.length > 2000
              removed = @timeline.shift
              @scroll = [@scroll - removed[3].fetch(:rows, []).length, 0].max if @scroll
            end
            PWN::Plugins::Log.mirror_tui!(msg: "#{type.to_s.upcase}\n#{clean}") if @pry.config.pwn_ai_debug && type != :notice
          end

          def start_request(request, command: false)
            @locals = Thread.current.keys.select { |key| key.to_s.start_with?('pwn_') }.to_h { |key| [key, Thread.current[key]] }
            @thread_variables = Thread.current.thread_variables.select { |key| key.to_s.start_with?('pwn_') }.to_h { |key| [key, Thread.current.thread_variable_get(key)] }
            # A fresh forwarding pipe prevents unread input crossing requests.
            @tool_input.close unless @tool_input.closed?
            forwarded, @tool_input = IO.pipe
            @input.reopen(forwarded)
            forwarded.close
            @cancelling = false
            @command = command
            begin_request_metrics
            add(:operator, request)
            @running = true
            ready = Queue.new
            gate = Queue.new
            @worker = Thread.new do
              @locals.each { |key, value| Thread.current[key] = value }
              @thread_variables.each { |key, value| Thread.current.thread_variable_set(key, value) }
              control = Control.new(input: @input, output: @output)
              Thread.current[:pwn_steering_input] = control
              Thread.current[:pwn_usage_observer] = @usage.method(:record)
              ready << control
              gate.pop
              on_tool = lambda do |name, args, result|
                if name.to_s == 'task'
                  @events << [:task, args.to_s]
                elsif name.to_s == 'thinking'
                  @events << [:thinking, args.to_s]
                else
                  @events << [:tool, "#{name}\n#{args.is_a?(String) ? args : args.inspect}"]
                  @events << [:result, result.to_s]
                end
              end
              if command
                control.checkpoint(messages: [], phase: :tool)
                if request.match?(%r{\A/model(?:\s|$)})
                  REPL.pwn_ai_run_model(args: request.split.drop(1), prompt: lambda { |selection|
                    control.checkpoint(messages: [])
                    @events << [:model_prompt, selection]
                    :deferred
                  })
                else
                  REPL.pwn_ai_dispatch_slash!(request: request, pry: @pry)
                end
                control.checkpoint(messages: [])
              else
                final = PWN::AI::Agent::Loop.run(
                  request: request, session_id: @pry.config.pwn_ai_session_id,
                  enabled_toolsets: PWN::Env.dig(:ai, :agent, :toolsets),
                  on_tool: on_tool, steering: control, debug: @pry.config.pwn_ai_debug, debug_tee: @output
                )
                promoted = Thread.current[:pwn_thinking_promoted] && final.to_s.strip == Thread.current[:pwn_last_thinking].to_s.strip
                @events << [:assistant, final.to_s] unless promoted
              end
            rescue Control::Stopped => e
              @events << [:warning, e.message]
            rescue StandardError, Interrupt => e
              Thread.current[:pwn_log_progress] = false
              PWN::Plugins::Log.note_exception!(error: e, where: 'curses agent', which_self: AIConsole)
              @events << [:warning, "#{e.class}: #{e.message}"]
            ensure
              @events << [:done, nil]
            end
            @worker.report_on_exception = false
            @control = ready.pop
            gate << true
          end

          def cancel
            if busy?
              return if @cancelling

              @cancelling = true
              @control&.stop
              @swarm&.cancel_all
              @tool_input.close unless @tool_input.closed?
              add(:warning, 'Cancellation requested. Waiting for the active tool to finish; work already started is not undone.')
            else
              @editor.replace('')
            end
          end

          def stop_worker
            return unless @worker&.alive? || @swarm&.busy?

            @control&.stop
            @swarm&.cancel_all
            @tool_input.close unless @tool_input.closed?
            @worker&.join
            @swarm&.close
          end

          def submit(line)
            return if line.strip.empty?

            # Pry owns the existing pwn_history format, append and deduplication.
            # Curses bypasses Pry's input evaluator, so record once here, not on recall.
            Pry.history << line unless line.match?(%r{\A\s*/input(?:\s|\z)})

            if %w[back /back].include?(line.strip)
              @leaving = true
              cancel if busy?
            elsif line.strip == '/clear'
              clear_view
            elsif line.strip == '/status'
              @details = 0
              @menu = nil
            elsif line.match?(%r{\A/verbose(?:\s|$)})
              toggle_verbose(line)
            elsif line.start_with?('/swarm')
              run_swarm(line)
            elsif ['/', '/menu'].include?(line.strip)
              @editor.replace('/')
              complete
            elsif busy?
              busy_command(line)
            elsif line.strip == '/system-role'
              open_system_role
            elsif line.match?(%r{\A/(?:mcp(?:\s|$)|cron\s+run(?:\s|$)|model(?:\s|$))})
              start_request(line, command: true)
            elsif line.start_with?('/') || line.start_with?('ai.profile ', 'ai.memory ')
              if line.start_with?('/sessions resume ')
                return add(:warning, 'Cannot switch sessions while swarm jobs are active.') if @swarm&.busy?

                sid = line.split.last
                PWN::Sessions.to_response_history(session_id: sid)
                @pry.config.pwn_ai_session_id = sid
                add(:notice, "Session resumed: #{sid}")
              elsif !REPL.pwn_ai_dispatch_slash!(request: line, pry: @pry)
                add(:warning, 'Unknown command. Use / or Tab for commands.')
              end
            else
              start_request(line)
            end
          rescue StandardError => e
            add(:warning, "#{e.class}: #{e.message}")
          end

          def busy_command(line)
            if line.match?(%r{\A/steer(?:\s|$)})
              if @control.nil?
                add(:warning, 'Choose a swarm job with Ctrl+G, then s to steer it.')
              elsif @command
                add(:warning, '/steer applies to model requests, not local commands. Use /input for a prompt or Ctrl+C to cancel after this command returns.')
              else
                @control.submit(line.sub(%r{\A/steer\s*}, ''))
              end
            elsif line.start_with?('/input ')
              send_tool_input(line)
            elsif line.strip == '/clear'
              clear_view
            elsif line.match?(%r{\A/verbose(?:\s|$)})
              toggle_verbose(line)
            elsif line.start_with?('/swarm') && %w[status tail steer cancel help roster].include?(line.split[1])
              run_swarm(line)
            else
              add(:warning, 'Request running. Settings and new requests wait until idle. Use /steer, /input, /swarm status|steer|cancel, /clear, or /verbose.')
            end
          end

          def clear_view
            @timeline = []
            @rows = nil
            @scroll = nil
            @event_count = 0
            add(:notice, 'Session view cleared. Stored conversation was not deleted.')
          end

          def toggle_verbose(line)
            argument = line.split[1]
            @verbose = argument.nil? ? !@verbose : argument == 'on'
            @rows = nil
            add(:notice, @verbose ? 'Verbose view on.' : 'Compact view on. Tool output is hidden until /verbose on.')
          end

          def run_swarm(line)
            return open_swarm if ['/swarm', '/swarm dashboard'].include?(line.strip)

            result = @swarm.execute(line: line, on_event: ->(type, text) { @events << [type, text] }, usage_observer: @usage.method(:record))
            text = result[:job_id] ? "Swarm job #{result[:job_id]} queued (#{result[:state]})." : (result[:usage] || result[:error] || result.inspect)
            add(result[:ok] == false ? :warning : :notice, text)
          end

          def send_tool_input(line)
            text = "#{line.delete_prefix('/input ')}\n"
            written = @tool_input.write_nonblock(text, exception: false)
            if text.bytesize > 4096 || written == :wait_writable
              add(:warning, 'Tool input not sent: pipe full or line exceeds 4096 bytes.')
            else
              add(:notice, 'Input sent to tool (not echoed).')
            end
          end

          def complete
            result = AIConsoleCommands.complete(line: @editor.text, cursor: @editor.cursor, pry: @pry, swarm: @swarm)
            @menu = result[:items]
            @menu_hint = result[:hint]
            @menu_index = [@menu_index.to_i, @menu.length - 1].min
            @menu_index = 0 if @menu_index.negative?
            @menu = nil if @menu.empty?
          end

          # Live view uses a nil scroll. Up from that view pins one row above the bottom.
          def scroll_session(key)
            bottom = [@total_rows.to_i - @page_size.to_i, 0].max
            case key
            when :up, "\u0010"
              @scroll = [(@scroll || bottom) - 1, 0].max
            when :down, "\u000e"
              return if @scroll.nil?

              @scroll += 1
              if @scroll >= bottom
                @scroll = nil
                @unseen = 0
              end
            when :home
              @scroll = bottom.zero? ? nil : 0
            when :end
              @scroll = nil
              @unseen = 0
            end
          end

          def handle(key)
            return if key.nil?
            return handle_system_role(key) if @role_editor && (!@too_small || ["\e", "\u0003", "\u0004", :eof].include?(key))

            return if @too_small && ![:eof, "\u0003", "\u0004"].include?(key)
            return cancel if @too_small && key == "\u0003" && !@model_prompt

            return handle_model_prompt(key) if @model_prompt

            return clear_view if key == "\u000c"

            if ["\u0007", "\u0013"].include?(key)
              @workspace ? @workspace = nil : open_swarm
              return
            end
            return handle_swarm(key) if @workspace && ![:eof, "\u0004"].include?(key)

            if key == "\u000f"
              @editor.finish_search
              @details = @details ? nil : 0
              @menu = nil
              return
            end
            return handle_details(key) if @details && ![:eof, "\u0003", "\u0004"].include?(key)
            return handle_search(key) if @editor.search && ![:eof, "\u0003", "\u0004"].include?(key)

            if key == "\u0012"
              @menu = nil
              @paste = false
              @focus = :mission
              @editor.search_history
              return
            end

            if ["\u0018", "\u0014"].include?(key)
              @menu = nil
              @focus = @focus == :session ? :mission : :session
              return
            end

            if key == "\t" && @menu
              accept_completion
              return
            end
            if @menu && key == "\e"
              @menu = nil
              return
            end
            case key
            when :eof, "\u0004"
              @leaving = true
              cancel if busy?
            when "\u0003" then cancel
            when :paste_start then @paste = true
            when :paste_end then @paste = false
            when :newline then @editor.insert("\n")
            when "\r", "\n"
              if @focus == :session && !@paste
                @focus = :mission
              elsif @paste
                @editor.insert("\n")
              elsif @editor.text.end_with?('\\')
                @editor.edit("\b")
                @editor.insert("\n")
              else
                @menu = @menu_hint = nil
                return submit(@editor.text) if @editor.text.strip == '/system-role'

                @model_draft = [@editor.text.dup, @editor.cursor] if @editor.text.match?(%r{\A/model(?:\s|$)})
                submit(@editor.submit)
              end
            when :up, :down, "\u0010", "\u000e"
              direction = [:up, "\u0010"].include?(key) ? :up : :down
              if @menu
                @menu_index = (@menu_index + (direction == :up ? -1 : 1)) % @menu.length
              elsif @focus == :session
                scroll_session(key)
              else
                @editor.recall(direction)
              end
            when :page_up then @scroll = [(@scroll || (@total_rows.to_i - @page_size.to_i)) - @page_size.to_i, 0].max
            when :page_down
              bottom = [@total_rows.to_i - @page_size.to_i, 0].max
              # nil is the live end, not row 0. Treating it as 0 jumps upward, then later presses walk back down.
              if @scroll.nil? || @scroll >= bottom
                @scroll = nil
                @unseen = 0
              else
                @scroll = [@scroll + @page_size.to_i, bottom].min
                if @scroll >= bottom
                  @scroll = nil
                  @unseen = 0
                end
              end
            when "\t" then accept_completion
            when :home, :end
              if @focus == :session
                scroll_session(key)
              else
                @editor.edit(key)
                refresh_completion
              end
            when :left, :right, :delete, "\b", "\u007f", "\u0001", "\u0005", "\u0015"
              unless @focus == :session
                @editor.edit(key)
                refresh_completion
              end
            else
              if key.is_a?(String) && key.ord >= 32
                @focus = :mission
                @editor.insert(key)
                refresh_completion
              end
            end
          end

          def open_system_role
            return add(:warning, 'System role cannot change while a request or swarm job is running.') if busy?

            @role_engine = PWN::Env.dig(:ai, :active).to_s
            raise 'Select an active engine with /model first.' unless PWN::Env.dig(:ai, @role_engine.to_sym).is_a?(Hash)

            @role_editor = Editor.new
            @role_editor.replace(PWN::Env.dig(:ai, @role_engine.to_sym, :system_role_content).to_s)
            @role_error = nil
            @role_paste = false
            @menu = nil
            @paste = false
          end

          def handle_system_role(key)
            case key
            when "\e", "\u0003", "\u0004", :eof
              @role_editor = nil
              add(:notice, 'System role cancelled; configuration unchanged.')
              @leaving = true if [:eof, "\u0004"].include?(key)
            when "\u0013"
              return if @role_paste
              raise 'System role cannot change while a request or swarm job is running.' if busy?

              REPL.pwn_ai_apply_system_role(engine: @role_engine, content: @role_editor.text)
              @role_editor = nil
              add(:notice, 'System role saved to encrypted pwn.yaml; effective for the next request.')
            when :paste_start then @role_paste = true
            when :paste_end then @role_paste = false
            when "\r", "\n", :newline then @role_editor.insert("\n")
            when :up, :down then move_role_cursor(key)
            when :left, :right, :home, :end, :delete, "\b", "\u007f", "\u0001", "\u0005", "\u0015"
              @role_editor.edit(key)
            else
              @role_editor.insert(key) if key.is_a?(String) && key.ord >= 32
            end
          rescue StandardError => e
            @role_error = "Not saved: #{e.message}"
            add(:warning, @role_error)
          end

          def move_role_cursor(direction)
            chars = @role_editor.text.scan(/\X/)
            cursor = @role_editor.cursor
            start = (chars.take(cursor).rindex("\n") || -1) + 1
            column = cursor - start
            if direction == :up
              return if start.zero?

              target = (chars.take(start - 1).rindex("\n") || -1) + 1
              position = target + [column, start - target - 1].min
            else
              finish = chars.index.with_index { |char, index| index >= cursor && char == "\n" }
              return unless finish

              target = finish + 1
              length = chars.drop(target).take_while { |char| char != "\n" }.length
              position = target + [column, length].min
            end
            @role_editor.place(@role_editor.text, position)
          end

          def draw_system_role
            height = @height - 4
            pane_width = @width - 4
            top = 2
            height.times { |row| put(top + row, 2, ' ' * pane_width) }
            box(top, 2, height, pane_width, 'SYSTEM ROLE CONTENT')
            put(top + 1, 4, fit("#{@role_engine} · edits are not saved until Ctrl+S", pane_width - 4), tone(:category))
            limit = pane_width - 6
            rows = wrap(@role_editor.text, limit, words: false)
            prefix = wrap(@role_editor.text.scan(/\X/).take(@role_editor.cursor).join, limit, words: false)
            cursor_row = prefix.length - 1
            visible = height - 5
            first = [cursor_row - visible + 1, 0].max
            rows.slice(first, visible).to_a.each_with_index { |row, index| put(top + 2 + index, 4, row, tone(:composer)) }
            put(top + height - 3, 4, fit(@role_error || 'Arrows move · Home/End · Ctrl+U clear', pane_width - 4), tone(@role_error ? :warning : :footer))
            put(top + height - 2, 4, fit('Ctrl+S Save · Esc Cancel · Enter newline', pane_width - 4), tone(:selection))
            @cursor_position = [top + 2 + cursor_row - first, [4 + width(prefix.last), @width - 5].min]
          end

          def handle_model_prompt(key)
            case key
            when :up, "\u0010", 'k'
              @model_index = (@model_index - 1) % @model_prompt[:efforts].length
            when :down, "\u000e", 'j'
              @model_index = (@model_index + 1) % @model_prompt[:efforts].length
            when "\r", "\n"
              selection = @model_prompt.merge(reasoning_effort: @model_prompt[:efforts][@model_index])
              REPL.pwn_ai_apply_model(selection: selection)
              @model_prompt = @model_draft = nil
            when "\e", "\u0003", :eof, "\u0004"
              if @model_draft
                @editor.replace(@model_draft[0])
                @editor.edit(:left) while @editor.cursor > @model_draft[1]
              end
              @model_prompt = @model_draft = nil
              add(:notice, 'Model selection cancelled; configuration unchanged.')
              @leaving = true if [:eof, "\u0004"].include?(key)
            end
          end

          def draw_model_prompt
            height = [@model_prompt[:efforts].length + 5, @height - 2].min
            menu_width = [@width - 4, 72].min
            top = [(@height - height) / 2, 0].max
            height.times { |row| put(top + row, 2, ' ' * menu_width) }
            box(top, 2, height, menu_width, 'REASONING EFFORT · SELECT')
            put(top + 1, 4, fit("#{@model_prompt[:engine]} / #{@model_prompt[:model]}", menu_width - 4))
            start = [@model_index - (height - 5), 0].max
            @model_prompt[:efforts].slice(start, height - 4).each_with_index do |effort, index|
              selected = start + index == @model_index
              text = "#{selected ? '▶ ' : '  '}#{effort}"
              text += ' (current/default)' if effort == @model_prompt[:default]
              paint = -> { put(top + 2 + index, 4, fit(text, menu_width - 4), tone(selected ? :selection : :notice)) }
              selected ? @screen.attron(Curses::A_REVERSE) { paint.call } : paint.call
            end
            put(top + height - 2, 4, fit('↑↓ select · Enter accept · Esc cancel', menu_width - 4))
          end

          def handle_search(key)
            query = @editor.search[:query]
            case key
            when "\e" then @editor.finish_search
            when "\r", "\n" then @editor.finish_search(accept: true)
            when "\u0012" then @editor.search_history(query, older: true)
            when "\b", "\u007f" then @editor.search_history(query.scan(/\X/)[0...-1].join)
            when "\u0015" then @editor.search_history
            else
              @editor.search_history(query + key) if key.is_a?(String) && key.ord >= 32
            end
          end

          def refresh_completion
            token = @editor.text.scan(/\X/).take(@editor.cursor).join[/(?:^|\s)(\S*)\z/, 1].to_s
            if @editor.text.start_with?('/') || token.start_with?('PWN') || token.match?(%r{\A(?:~|\./|\.\./|/)})
              complete
            else
              @menu = nil
            end
          end

          def handle_details(key)
            case key
            when "\e" then @details = nil
            when :page_up then @details = [@details - @details_page, 0].max
            when :page_down then @details += @details_page
            when :up then @details = [@details - 1, 0].max
            when :down then @details += 1
            when :home then @details = 0
            when :end then @details = @details_total
            end
          end

          def accept_completion
            refresh_completion if @menu.nil?
            item = @menu && @menu[@menu_index]
            return complete unless item

            @editor.place(item[:text], item[:cursor])
            complete
          end

          def width(text)
            Unicode::DisplayWidth.of(text, ambiguous: 1, emoji: :all)
          end

          def bounded_event(text)
            return text if text.bytesize <= 16_384

            clipped = +''
            text.each_grapheme_cluster do |grapheme|
              break if clipped.bytesize + grapheme.bytesize > 16_384

              clipped << grapheme
            end
            "#{clipped}\n[display truncated at 16 KiB; full event is not shown]"
          end

          def timeline_rows(limit)
            theme = AIConsole.theme
            return @rows if @rows && @rows_width == limit && @rows_verbose == @verbose && @rows_theme == theme

            @rows_width = limit
            @rows_verbose = @verbose
            @rows_theme = theme
            @rows = @timeline.flat_map do |type, text, stamp, cache|
              next [] if !@verbose && %i[tool result notice].include?(type)

              unless cache[:width] == limit && cache[:verbose] == @verbose && cache[:theme] == theme
                cache[:verbose] = @verbose
                cache[:width] = limit
                cache[:theme] = theme
                role = COLORS.fetch(type, :result)
                label_color = type == :operator ? tone(:operator) : tone(role)
                body_color = type == :operator ? tone(:request) : label_color
                cache[:rows] = [[label_color, "#{fit(type.to_s.upcase, 12)} · #{stamp}"]] +
                               wrap(text, limit).map { |row| [body_color, "  #{row}"] } + [[nil, '']]
              end
              cache[:rows]
            end
            @rows.pop if @rows.last&.last == ''
            @rows
          end

          def begin_request_metrics
            @started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            @finished_at = @last_tool = nil
            @completed_tools = 0
          end

          def finish_request_metrics
            @finished_at = Process.clock_gettime(Process::CLOCK_MONOTONIC) if @started_at
          end

          def elapsed
            return '—' unless @started_at

            format('%.1fs', (@finished_at || Process.clock_gettime(Process::CLOCK_MONOTONIC)) - @started_at)
          end

          def scroll_status
            return 'live' unless @scroll

            "#{@scroll + 1}–#{[@scroll + @page_size.to_i, @total_rows.to_i].min}/#{@total_rows} · #{@unseen} new"
          end

          def operation_lines
            usage = @usage.snapshot
            cost = usage[:estimated_cost_usd] ? format('$%.4f est.', usage[:estimated_cost_usd]) : usage[:cost_status]
            swarm = @swarm&.snapshot || {}
            active = Array(swarm[:jobs]).count { |job| %w[queued running steering cancelling].include?(job[:state]) }
            ['REQUEST', state, "Elapsed #{elapsed}", "Completed tools #{@completed_tools}",
             "Events #{@event_count}", '', 'TOKENS', "#{usage[:input_tokens]} in · #{usage[:output_tokens]} out",
             "cached #{usage[:cached_tokens]} · calls #{usage[:calls]}", "Cost #{cost}",
             '', 'SWARM', swarm[:swarm_id] || 'none', "#{active} active · ^G swarm",
             '', 'VIEW', @verbose ? 'verbose' : 'compact · /verbose', scroll_status,
             '', 'LAST TOOL', @last_tool || 'not observed']
          end

          def fit(text, limit)
            result = +''
            used = 0
            text.scan(/\X/).each do |char|
              used += width(char)
              break if used > limit

              result << char
            end
            result
          end

          def wrap(text, limit, words: true)
            return [''] if text.empty?

            text.split("\n", -1).flat_map do |line|
              rows = [+'']
              used = 0
              tokens = words ? line.scan(/\s+|\S+/) : [line]
              tokens.each do |token|
                if words && !token.match?(/\A\s/) && used.positive? && width(token) <= limit && used + width(token) > limit
                  rows << +''
                  used = 0
                end
                token.scan(/\X/).each do |char|
                  cells = width(char)
                  if used + cells > limit && !rows.last.empty?
                    rows << +''
                    used = 0
                  end
                  rows[-1] << char
                  used += cells
                end
              end
              rows
            end
          end

          def tone(role)
            name = AIConsole.theme[role].to_s
            index = PALETTE.index(name)
            index ? index + 1 : 1
          end

          def put(row, column, text, color = nil)
            return if row.negative? || row >= @height || column >= @width

            @screen.setpos(row, column)
            string = fit(text, [@width - column - 1, 0].max)
            if @color && color
              @screen.attron(@curses.color_pair(color)) { @screen.addstr(string) }
            else
              @screen.addstr(string)
            end
          end

          def box(top, left, height, box_width, title, color = nil) # rubocop:disable Metrics/ParameterLists -- screen rectangle plus appearance
            color ||= tone(:border)
            put(top, left, "╭#{'─' * (box_width - 2)}╮", color)
            (1...(height - 1)).each do |row|
              put(top + row, left, '│', color)
              put(top + row, left + box_width - 1, '│', color)
            end
            put(top + height - 1, left, "╰#{'─' * (box_width - 2)}╯", color)
            put(top, left + 2, fit(" #{title} ", box_width - 4), tone(:title)) unless title.empty?
          end

          def mark_active(top, left, box_width, title)
            return unless @screen.respond_to?(:attron)

            text = fit(" #{title} ", box_width - 4)
            @screen.attron(Curses::A_REVERSE) { put(top, left + 2, text, tone(:title)) }
          end

          def seed_request_history
            # REPL configures ~/.pwn/pwn_history and Pry loads it at startup.
            # Reuse that owner rather than loading twice or opening another writer.
            @editor.preload(Pry.history.to_a)
          rescue StandardError
            nil
          end

          def state
            return 'closing · waiting for safe boundary' if @leaving && busy?
            return 'cancelling · waiting for safe boundary' if @cancelling && busy?
            return 'idle' unless busy?
            return 'swarm running · ^G jobs / steering' unless @worker && (@worker.alive? || @running)
            return 'running · local command · /input available' if @command

            "running · #{@control&.phase || 'starting'} · /steer available"
          end

          def engine_settings
            engine = PWN::Env.dig(:ai, :active).to_s
            cfg = PWN::Env.dig(:ai, engine.to_sym)
            cfg = {} unless cfg.is_a?(Hash)
            role = cfg[:system_role_content].to_s.gsub(/\s+/, ' ').strip
            parts = []
            parts << "SYSTEM ROLE CONTENT: #{role}" unless role.empty?
            parts << "\nMAX TOKENS: #{cfg[:max_tokens]}" unless cfg[:max_tokens].nil?
            parts << " MAX PROMPT LENGTH: #{cfg[:max_prompt_length]}" unless cfg[:max_prompt_length].nil?
            parts << " REASONING EFFORT: #{cfg[:reasoning_effort]}" unless cfg[:reasoning_effort].to_s.empty?
            parts << " TEMP: #{cfg[:temp]}" unless cfg[:temp].nil?
            parts.join(' · ')
          rescue StandardError
            ''
          end

          def header_lines(engine, model, limit = [@width.to_i - 5, 1].max)
            settings = engine_settings
            # Env strings can be edited in place; cache values, not live aliases.
            key = [engine.dup, model.dup, settings, limit]
            return @header_lines if @header_key == key

            @header_key = key
            text = "PROVIDER (ENGINE): #{engine}\nMODEL: #{model}"
            text += "\n#{settings}" unless settings.empty?
            @header_spans = styled_settings(text, limit)
            @header_lines = @header_spans.map { |spans| spans.map(&:last).join }
          end

          # Mark labels before wrapping so even a split label retains its role.
          def styled_settings(text, limit)
            text.split("\n", -1).flat_map do |line|
              roles = Array.new(line.length, :header)
              line.to_enum(:scan, /(?:\A|(?<=· ))\s*(?:PROVIDER \(ENGINE\)|MODEL|SYSTEM ROLE CONTENT|TEMP|MAX TOKENS|MAX PROMPT LENGTH|REASONING EFFORT):/).each do
                match = Regexp.last_match
                roles.fill(:category, match.begin(0)...match.end(0))
              end
              offset = 0
              wrap(line, limit).map do |row|
                spans = []
                row.each_char do |char|
                  role = roles[offset]
                  offset += 1
                  if spans.last&.first == role
                    spans.last[1] << char
                  else
                    spans << [role, +char]
                  end
                end
                spans
              end
            end
          end

          def put_spans(row, column, spans)
            spans.each do |role, text|
              put(row, column, text, tone(role))
              column += width(text)
            end
          end

          # Artwork has no worker, IO, or request-progress meaning. The existing
          # event-loop repaint supplies its clock, including while requests run.
          def banner_frame(size, cells: false)
            now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            session = @pry.config.pwn_ai_session_id.to_s
            if @banner_session != session
              @banner_session = session
              @banner_name = PWN::Banner.mini_names.sample
              @banner_frame_seconds = PWN::Banner.mini_frame_seconds(name: @banner_name)
              @banner_seed = session.bytes.reduce(PWN::Banner::MINI_SEED) { |seed, byte| ((seed * 33) ^ byte) & 0xffffffff }
              @banner_started = now
            end
            cadence = cells ? @banner_frame_seconds : PWN::Banner::MINI_FRAME_SECONDS
            frame = ((now - @banner_started) / cadence).floor % PWN::Banner::MINI_FRAME_COUNT
            return PWN::Banner.mini_cells(name: @banner_name, frame: frame, width: size, height: size, seed: @banner_seed, branding: false) if cells

            art = PWN::Banner.mini_frame(name: @banner_name, frame: frame, width: size, height: size, branding: false)
            canvas = Array.new(size) { ' ' * size }
            top = (size - art.length) / 2
            art.each_with_index { |row, index| canvas[top + index] = row.center(size) }
            canvas
          end

          def draw_banner(size)
            cells = banner_frame(size, cells: true)
            top = [(size - cells.length) / 2, 0].max
            # Clear padding too when the bounded artwork is smaller than the pane.
            size.times { |row| put(row + 1, 1, ' ' * size, @banner_colors ? 16 : nil) }
            cells.first(size).each_with_index do |row, y|
              left = [(size - row.length) / 2, 0].max
              row.first(size).each_with_index do |cell, x|
                index = PALETTE.index(cell[:foreground].to_s)
                background = PALETTE.index(cell[:background].to_s)
                colors = @banner_colors && (@banner_name != :falling_blocks || @banner_two_colors)
                pair = if colors && index && background && (background == 7 || @banner_two_colors)
                         background == 7 ? 9 + index : 17 + (background * 8) + index
                       end
                # Two occupied halves must remain filled in monochrome too.
                glyph = !pair && cell[:background] != :black ? '█' : cell[:glyph]
                put(top + y + 1, left + x + 1, glyph, pair)
              end
            end
          end

          def header_layout(engine, model)
            key = [engine.dup, model.dup, engine_settings, @width, @height]
            return if @header_layout_key == key

            @header_layout_key = key
            @header_text_column = 2
            @header_text_width = @width - 5
            @header_pane_height = nil
            return if @width < 100 || @height < 26

            # A framed cell-square is as wide as the complete header is tall.
            # Solve monotonically within physical bounds, never recurse or clip
            # settings to make room for decoration. Eight interior cells is the
            # smallest useful game canvas; larger settings grow both dimensions.
            height = 10
            while height <= @height - 10 && @width - height - 5 >= 60
              limit = @width - height - 5
              needed = header_lines(engine, model, limit).length + 3
              if needed <= height
                @header_pane_height = height
                @header_text_column = height + 2
                @header_text_width = limit
                return
              end
              height = needed
            end
          end

          def header_content_limit
            compose = @compose_height || 5
            footer = @footer_height || 1
            [@height.to_i - compose - footer - 6, 1].max
          end

          def footer_text
            text = '/ menu · ^C=cancel · ^D=back · ^L=clear · ^T=toggle pane · ^S=swarm · ^R=search ^O=operations · ↑↓ history · Shift+Enter=newline · Enter=send'
            @focus == :session ? text.sub('↑↓ history', '↑↓ scroll · HOME · PGUP · PGDN · END') : text
          end

          def footer_lines
            wrap(footer_text, [@width.to_i - 2, 1].max)
          end

          def layout_chrome
            footer = footer_lines
            compose = 5
            footer_height = footer.length
            compose -= 1 while @height.to_i - 4 - compose - footer_height < 3 && compose > 3
            [footer, compose, footer_height]
          end

          def draw_header(engine, model)
            header_layout(engine, model)
            content = header_lines(engine, model, @header_text_width)
            # Reserve only the physical minimum: timeline (3), composer (6), footer (1).
            visible = @header_spans.first([header_content_limit, 1].max)
            overflow = visible.length < content.length ? ' · ^O full settings' : ''
            height = @header_pane_height || (visible.length + 3)
            left = @header_pane_height || 0
            box(0, left, height, @width - left - 1, "pwn-ai v#{PWN::VERSION}#{overflow}")
            put(1, @header_text_column, fit("#{state} · #{elapsed} · #{scroll_status}", @header_text_width), tone(:status))
            visible.each_with_index { |spans, index| put_spans(2 + index, @header_text_column, spans) }
            if @header_pane_height
              box(0, 0, height, height, '')
              draw_banner(height - 2)
            end
            height
          end

          def draw_details(engine, model)
            @screen.erase
            lines = ["Session: #{@pry.config.pwn_ai_session_id}"] + operation_lines + ['SETTINGS']
            rows = lines.flat_map do |line|
              role = ['REQUEST', 'TOKENS', 'SWARM', 'VIEW', 'LAST TOOL', 'SETTINGS'].include?(line) ? :category : :value
              wrap(line, @width - 7).map { |row| [[role, row]] }
            end
            header_lines(engine, model, @width - 7)
            rows.concat(@header_spans)
            @details_page = @height - 5
            @details_total = rows.length
            @details = @details.clamp(0, [rows.length - @details_page, 0].max)
            box(0, 0, @height - 1, @width - 1, "STATUS / SETTINGS · #{@details + 1}/#{rows.length}")
            rows.slice(@details, @details_page).each_with_index { |spans, index| put_spans(index + 1, 3, spans) }
            put(@height - 3, 3, 'PgUp/PgDn Home/End · Esc/^O close', tone(:footer))
            put(@height - 1, 1, '^C cancel  ^D back  ^O close', tone(:footer))
          end

          def draw
            if !@getch.is_a?(Proc) && @source.respond_to?(:winsize)
              rows, columns = @source.winsize
              @curses.resizeterm(rows, columns) if rows.positive? && columns.positive? && [rows, columns] != [@curses.lines, @curses.cols]
            end
            @height = @curses.lines
            @width = @curses.cols
            @screen.erase
            @too_small = @height < 14 || @width < 48
            if @too_small
              @menu = nil
              @paste = false
              put(0, 0, 'pwn-ai · terminal too small (48 × 14 minimum)', tone(:status))
              put(1, 0, state, tone(:status))
              put(2, 0, 'Ctrl+C cancel · Ctrl+D back · resize to continue')
              @screen.refresh
              return
            end
            engine = PWN::Env.dig(:ai, :active).to_s
            model = REPL.pwn_ai_engine_model(engine: engine)
            footer, compose_height, footer_height = layout_chrome
            @compose_height = compose_height
            @footer_height = footer_height
            header_height = draw_header(engine, model)
            sidebar = @width >= 100 ? 27 : 0
            pane_width = @width - sidebar - 2
            timeline_height = @height - compose_height - footer_height - header_height
            timeline_height = 3 if timeline_height < 3
            @page_size = timeline_height - 2
            rows = timeline_rows(pane_width - 6)
            @total_rows = rows.length
            @scroll = @scroll.clamp(0, [rows.length - @page_size, 0].max) if @scroll
            session_id = @pry.config.pwn_ai_session_id.to_s
            session_title = "SESSION #{session_id}"
            session_title += ' · active' if @focus == :session
            box(header_height, 0, timeline_height, pane_width, session_title)
            mark_active(header_height, 0, pane_width, session_title) if @focus == :session
            start = @scroll || [rows.length - @page_size, 0].max
            rows.slice(start, @page_size).to_a.each_with_index { |(color, row), index| put(header_height + 1 + index, 2, row, color) }
            draw_sidebar(header_height, pane_width + 1, timeline_height) if sidebar.positive?
            compose_y = @height - compose_height - footer_height
            mission_title = @focus == :session ? 'MISSION CONTROL' : 'MISSION CONTROL · active'
            box(compose_y, 0, compose_height, @width - 1, mission_title)
            mark_active(compose_y, 0, @width - 1, mission_title) if @focus != :session
            draw_composer(compose_y, height: compose_height)
            footer_top = @height - footer_height
            footer.first(footer_height).each_with_index { |line, index| put(footer_top + index, 1, line, tone(:footer)) }
            draw_menu if @menu
            draw_model_prompt if @model_prompt
            draw_details(engine, model) if @details
            draw_swarm if @workspace
            draw_system_role if @role_editor
            if @focus == :session && !(@details || @workspace || @role_editor)
              @screen.setpos(header_height + 1, 2)
            elsif @role_editor || !(@details || @workspace)
              @screen.setpos(*@cursor_position)
            end
            @screen.refresh
          end

          def draw_composer(top, height: 5)
            return draw_search(top, height: height) if @editor.search

            chars = @editor.text.scan(/\X/)
            before = chars.take(@editor.cursor).join
            rows = wrap(@editor.text, @width - 8, words: false)
            prefix = wrap(before, @width - 8, words: false)
            cursor_row = prefix.length - 1
            interior = [height - 2, 1].max
            first = [cursor_row - (interior - 1), 0].max
            put(top + 1, 2, '›', tone(:prompt)) if first.zero?
            rows.slice(first, interior).to_a.each_with_index { |row, index| put(top + 1 + index, 4, row, tone(:composer)) }
            @cursor_position = [top + 1 + cursor_row - first, [4 + width(prefix.last), @width - 3].min]
          end

          def draw_search(top, height: 5)
            search = @editor.search
            query = "reverse search: #{search[:query]}"
            query_rows = wrap(query, @width - 8, words: false)
            put(top + 1, 4, query_rows.last, tone(:category))
            match = search[:match] || '(no match)'
            interior = [height - 2, 1].max
            wrap(match, @width - 8).first([interior - 1, 1].max).each_with_index { |row, index| put(top + 2 + index, 4, row, tone(:composer)) }
            @cursor_position = [top + 1, [4 + width(query_rows.last), @width - 3].min]
          end

          def draw_sidebar(top, left, height)
            box(top, left, height, @width - left - 1, 'OPERATIONS')
            lines = operation_lines
            if height < 26
              lines = lines.select { |line| line.start_with?('Elapsed', 'Completed tools', 'Cost') || line.match?(/\A\d+ in ·/) || line == 'TOKENS' } +
                      ['LAST TOOL', @last_tool || 'not observed', '^O full status']
            end
            lines.first(height - 2).each_with_index do |line, index|
              category = ['REQUEST', 'TOKENS', 'SWARM', 'VIEW', 'LAST TOOL'].include?(line)
              put(top + 1 + index, left + 2, fit(line, @width - left - 5), category ? tone(:category) : tone(:value))
            end
          end

          # This overlay owns only navigation state; the mission editor never changes.
          def open_swarm
            @editor.finish_search
            @menu = @details = nil
            @workspace = { tab: :roster, index: 0, selected: (@swarm_selection ||= []), offset: 0 }
            refresh_swarm
          end

          def refresh_swarm
            @workspace[:roster] = @swarm.roster
            @workspace[:selected].select! { |name| @workspace[:roster].any? { |row| row[:name] == name } }
          rescue StandardError => e
            @workspace[:roster] = []
            @workspace[:notice] = "Roster unavailable: #{e.message}"
          end

          def swarm_items
            @workspace[:tab] == :roster ? @workspace[:roster] : @swarm.snapshot[:jobs].reverse
          end

          def handle_swarm(key)
            view = @workspace
            return handle_swarm_prompt(key) if view[:prompt]

            if view[:confirm]
              case key
              when "\r", "\n" then execute_swarm_action
              when "\e" then view.delete(:confirm)
              when :page_up then view[:offset] = [view[:offset] - 5, 0].max
              when :page_down then view[:offset] += 5
              when :home then view[:offset] = 0
              when :end then view[:offset] = 1_000_000
              end
              return
            end
            item = swarm_items[view[:index]]
            case key
            when "\e" then view[:detail] ? view.delete(:detail) : @workspace = nil
            when "\t"
              view[:tab] = view[:tab] == :roster ? :jobs : :roster
              view[:index] = view[:offset] = 0
              view.delete(:detail)
            when 'j', 'k'
              view[:index] = (view[:index] + (key == 'j' ? 1 : -1)).clamp(0, [swarm_items.length - 1, 0].max)
              view[:offset] = 0
            when ' '
              return unless view[:tab] == :roster && item

              view[:selected].include?(item[:name]) ? view[:selected].delete(item[:name]) : view[:selected] << item[:name]
            when "\r", "\n" then view[:detail] = true
            when :page_up then view[:offset] = [view[:offset] - 5, 0].max
            when :page_down then view[:offset] += 5
            when :home then view[:offset] = 0
            when :end then view[:offset] = 1_000_000
            when 'r' then refresh_swarm
            when 'a', 'b', 'd' then prepare_swarm_mission(key, item)
            when 'c', "\u0003"
              return unless view[:tab] == :jobs && item

              view[:confirm] = ['cancel', item[:id]]
            when 's'
              return unless view[:tab] == :jobs && item

              view[:prompt] = { action: 'steer', id: item[:id], editor: Editor.new, label: 'Steer instruction' }
            when 'n'
              view[:prompt] = { action: 'spawn', editor: Editor.new, label: 'New agent name' }
            end
          end

          def prepare_swarm_mission(key, item)
            view = @workspace
            return view[:notice] = 'Return with Esc and write a mission draft first.' if @editor.text.strip.empty?
            return view[:notice] = 'Choose agents on the roster tab first.' unless view[:tab] == :roster

            names = key == 'a' ? [item&.dig(:name)].compact : view[:selected]
            minimum = key == 'd' ? 2 : 1
            return view[:notice] = "Select at least #{minimum} agent(s) with Space." if names.length < minimum

            command = { 'a' => 'ask', 'b' => 'broadcast', 'd' => 'debate' }.fetch(key)
            view[:confirm] = case command
                             when 'ask' then [command, names.first, @editor.text]
                             when 'broadcast' then [command, '--names', names.join(','), '--', @editor.text]
                             else [command, names.join(','), '--', @editor.text]
                             end
          end

          def handle_swarm_prompt(key)
            prompt = @workspace[:prompt]
            editor = prompt[:editor]
            case key
            when "\e" then @workspace.delete(:prompt)
            when "\r", "\n"
              return if editor.text.strip.empty?

              if prompt[:action] == 'spawn' && !prompt[:name]
                prompt[:name] = editor.text.dup
                prompt[:label] = 'Agent role (engine/model inherit; /swarm spawn offers overrides)'
                editor.replace('')
              else
                @workspace[:confirm] = prompt[:action] == 'spawn' ? ['spawn', prompt[:name], '--', editor.text] : ['steer', prompt[:id], editor.text]
                @workspace.delete(:prompt)
              end
            when :left, :right, :home, :end, :delete, "\b", "\u007f", "\u0001", "\u0005", "\u0015" then editor.edit(key)
            else
              editor.insert(key) if key.is_a?(String) && key.ord >= 32
            end
          end

          def execute_swarm_action
            args = @workspace.delete(:confirm)
            result = @swarm.execute(line: Shellwords.join(['/swarm'] + args), on_event: ->(type, text) { @events << [type, text] }, usage_observer: @usage.method(:record))
            @workspace[:notice] = result[:error] || "#{args.first}: accepted#{" · job #{result[:job_id]}" if result[:job_id]}"
            add(result[:ok] == false ? :warning : :notice, @workspace[:notice])
            refresh_swarm if args.first == 'spawn'
            @workspace.merge!(tab: :jobs, index: 0, offset: 0, detail: true) if result[:ok] && %w[ask broadcast debate].include?(args.first)
          end

          def swarm_content
            view = @workspace
            if view[:confirm]
              args = view[:confirm]
              target = args.first == 'broadcast' ? args[2] : args[1]
              return [[false, "ACTION: #{args.first}\nTARGET: #{target}\n#{args.first == 'cancel' ? 'Cancel at a safe boundary; completed work is not undone.' : args.last}"]]
            end
            items = swarm_items
            item = items[view[:index]]
            rows = []
            if view[:detail] && item
              item.each { |key, value| rows << [false, "#{key.to_s.upcase}: #{value}"] }
            elsif items.empty?
              rows << [false, view[:tab] == :roster ? 'No agents. Press n to add a local persona (no model call).' : 'No jobs yet. Tab to roster; a sends your draft after confirmation.']
            else
              items.each_with_index do |entry, index|
                label = if view[:tab] == :roster
                          "#{view[:selected].include?(entry[:name]) ? '[x]' : '[ ]'} #{entry[:name]} · #{entry[:engine]} / #{entry[:model]}\n    #{entry[:role]}"
                        else
                          "#{entry[:id]} · #{entry[:state]} · #{entry[:command]} → #{entry[:agent]}"
                        end
                rows << [index == view[:index], label]
              end
            end
            rows
          end

          def draw_swarm
            @screen.erase
            view = @workspace
            box(0, 0, @height - 1, @width - 1, "SWARM WORKSPACE · #{view[:tab].to_s.upcase}")
            swarm_put(1, 'Tab roster/jobs · j/k move · Enter details', :footer)
            swarm_put(2, 'Space pick · a ask · b broadcast · d debate', :footer)
            swarm_put(3, 'n new · r refresh · s steer · c cancel', :footer)
            swarm_put(4, 'PgUp/Dn Home/End scroll · Esc back', :footer)
            rows = swarm_content.flat_map { |selected, text| wrap(swarm_safe(text), @width - 7).map { |row| [selected, row] } }
            page = @height - 10
            anchor = rows.index(&:first) || 0
            start = (anchor + view[:offset]).clamp(0, [rows.length - page, 0].max)
            view[:offset] = [start - anchor, 0].max
            rows.slice(start, page).to_a.each_with_index do |(selected, text), index|
              paint = -> { put(5 + index, 3, fit(text, @width - 7).ljust(@width - 7), tone(:value)) }
              selected ? @screen.attron(Curses::A_REVERSE) { paint.call } : paint.call
            end
            bottom = @height - 5
            message = view[:notice] || "#{view[:selected].length} selected · draft preserved · no work until confirmed"
            swarm_put(bottom, message, :notice)
            if view[:confirm]
              args = view[:confirm]
              target = args.first == 'broadcast' ? args[2] : args[1]
              swarm_put(bottom + 1, "Confirm #{args.first} → #{target}", :warning)
              swarm_put(bottom + 2, 'Enter execute · Esc abort · draft unchanged', :footer)
            elsif view[:prompt]
              prompt = view[:prompt]
              swarm_put(bottom + 1, prompt[:label], :category)
              editor = prompt[:editor]
              chars = editor.text.scan(/\X/)
              first = [editor.cursor - ((@width - 7) / 2), 0].max
              text = fit(chars.drop(first).join, @width - 7)
              put(bottom + 2, 3, text, tone(:composer))
              cursor = [bottom + 2, [3 + width(chars[first...editor.cursor].join), @width - 3].min]
            else
              swarm_put(bottom + 1, "DRAFT: #{@editor.text}", :composer)
              swarm_put(bottom + 2, 'Esc/^S/^G return to unchanged mission draft', :footer)
            end
            put(@height - 1, 1, '^D back · ^S/^G close · actions require Enter', tone(:footer))
            @screen.setpos(*(cursor || [0, 2]))
          end

          def swarm_safe(text)
            PWN::Redaction.redact(value: text.to_s).gsub(%r{\e\[[0-?]*[ -/]*[@-~]}, '').gsub(/[\x00-\x08\x0b-\x1f\x7f]/, '')
          end

          def swarm_put(row, text, role)
            put(row, 2, fit(swarm_safe(text).gsub(/\s+/, ' '), @width - 5), tone(role))
          end

          def draw_menu
            height = [@menu.length + 2, @height - 10].min
            top = @height - 7 - height
            menu_width = [@width - 5, 65].min
            height.times { |row| put(top + row, 2, ' ' * menu_width) }
            box(top, 2, height, menu_width, "COMMANDS · #{@menu_hint}")
            start = [@menu_index - height + 3, 0].max
            @menu.slice(start, height - 2).each_with_index do |item, index|
              selected = start + index == @menu_index
              prefix = selected ? '› ' : '  '
              label = item.is_a?(Hash) ? item[:label].to_s : item.to_s
              text = fit(prefix + label, menu_width - 4)
              text += ' ' * (menu_width - 4 - width(text))
              paint = -> { put(top + index + 1, 4, text, tone(:selection)) }
              selected ? @screen.attron(Curses::A_REVERSE) { paint.call } : paint.call
            end
          end
        end

        # Resolve pwn-ai TUI colors from PWN::Env[:ai][:tui][:theme].
        public_class_method def self.theme(opts = {})
          configured = opts.key?(:theme) ? opts[:theme] : PWN::Env.dig(:ai, :tui, :theme)
          defaults = PWN::Config.env_template.dig(:ai, :tui, :theme)
          merged = defaults.is_a?(Hash) ? defaults.dup : {}
          return merged unless configured.is_a?(Hash)

          configured.each do |key, value|
            role = key.to_s.to_sym
            name = value.to_s.downcase
            next unless merged.key?(role) && Console::PALETTE.include?(name)

            merged[role] = name
          end
          merged
        end

        public_class_method def self.authors
          'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
        end

        public_class_method def self.help
          puts "USAGE:
            # Ctrl+L clears only the session pane, including while busy.
            # Ctrl+T toggles the active pane between SESSION and MISSION CONTROL. Ctrl+S opens swarm.
            # Thinking from a model that returns it is a THINKING row in the session pane, above the answer.
            # Up/Down select in menus, recall ~/.pwn/pwn_history in the mission pane, and scroll the session pane when it is active.
            # Search: Enter accepts without sending; Esc restores the draft.
            # Launch the single-owner curses console; non-terminals return unavailable.
            #{self}.run(
              pry: 'required - active Pry instance with session settings',
              input: 'optional - terminal input, defaults to stdin',
              output: 'optional - terminal output, defaults to stdout',
              curses: 'optional - curses implementation for terminal testing',
              getch: 'optional - key callback for deterministic testing'
            )
            # Resolve named TUI colors from ~/.pwn/pwn.yaml ai.tui.theme.
            #{self}.theme(
              theme: 'optional - role to color-name map; unknown names keep the default'
            )
            # Return module authors.
            #{self}.authors
          "
        end
      end
    end
  end
end
