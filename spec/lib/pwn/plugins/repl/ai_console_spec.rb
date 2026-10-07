# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'pry'

describe 'pwn-ai curses launch' do # rubocop:disable Metrics/BlockLength -- public launch, terminal lifecycle and deterministic worker integration
  include_context 'pwn tmp sandbox'

  before do
    @history_path = File.join(@tmp, 'pwn_history')
    @request_history = Pry::History.new(file_path: @history_path)
    allow(Pry).to receive(:history).and_return(@request_history)
    allow(PWN::AI::Agent::PromptBuilder).to receive(:build).and_return('offline console test')
    allow(PWN::AI::Agent::TaskSummarizer).to receive(:enabled?).and_return(false)
    allow(PWN::AI::Agent::Loop).to receive(:should_auto_introspect?).and_return(false)
    allow(PWN::AI::Agent::Loop).to receive(:may_finalize?).and_return(true)
  end

  def launch(keys, startup_delay: 0, render_delay: 0, &tick)
    require 'pty'
    require 'timeout'
    master, input = PTY.open
    @paint = []
    owner = Thread.current
    window = double('screen')
    allow(window).to receive_messages(erase: nil, refresh: nil, setpos: nil)
    frame = []
    position = [0, 0]
    allow(window).to receive(:erase) { frame = [] }
    allow(window).to receive(:refresh) do
      sleep render_delay if render_delay.positive? && !keys.empty?
      @rendered = frame.dup
    end
    @positions = []
    allow(window).to receive(:setpos) do |*coords|
      position = coords
      @positions << coords
    end
    allow(window).to receive(:addstr) { |text|
      expect(Thread.current).to eq(owner)
      @paint << text
      frame << [*position, text]
    }
    allow(window).to receive(:attron) { |_attribute, &block| block.call }
    screen = double('curses', init_screen: window, raw: nil, noecho: nil, curs_set: nil, close_screen: nil,
                              lines: 30, cols: 110, stdscr: window, has_colors?: false, resizeterm: nil)
    allow(screen).to receive(:init_screen) do
      sleep startup_delay if startup_delay.positive?
      window
    end
    @pry = Pry.new
    @pry.config.pwn_ai_session_id = PWN::Sessions.create(title: 'console')[:id]
    @pry.config.pwn_ai = true
    @screen = screen
    output = double('terminal', tty?: true)
    previous = [$stdin, $stdout, $stderr]
    Timeout.timeout(25, Class.new(Exception)) do # rubocop:disable Lint/InheritException
      PWN::Plugins::REPL::AIConsole.run(pry: @pry, input: input, output: output, curses: screen,
                                        getch: -> { keys.empty? ? tick.call : keys.shift })
    end
    expect([$stdin, $stdout]).to eq(previous.take(2))
    expect(PWN::Plugins::Log.raw_stderr).to equal(previous[2])
    expect(input).to be_tty
    expect(screen).to have_received(:close_screen)
  ensure
    master&.close
    input&.close
  end

  it 'edits system role in an isolated multiline modal and preserves mission cursor on save and cancel' do
    PWN::Env[:ai] = { active: 'openai', openai: { system_role_content: "first\nsecond" } }
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: Curses, getch: nil)
    editor = console.instance_variable_get(:@editor)
    editor.place('mission draft', 4)
    console.submit('/system-role')
    expect(console.instance_variable_get(:@role_editor).text).to eq("first\nsecond")
    console.handle("\u0015")
    "new\nrole".chars.each { |key| console.handle(key) }
    ["\u0012", "\u0007", "\u000f", "\u000c"].each { |key| console.handle(key) }
    expect(editor.text).to eq('mission draft')
    expect(editor.cursor).to eq(4)
    expect(PWN::Plugins::REPL).to receive(:pwn_ai_apply_system_role).with(engine: 'openai', content: "new\nrole").and_return(:saved)
    console.handle("\u0013")
    expect(console.instance_variable_get(:@role_editor)).to be_nil
    console.submit('/system-role')
    console.handle('x')
    console.handle("\e")
    expect(editor.text).to eq('mission draft')
    expect(editor.cursor).to eq(4)
    expect(PWN::Env.dig(:ai, :openai, :system_role_content)).to eq("first\nsecond")
  end

  it 'saves system role from curses to an encrypted vault and the next provider payload' do
    previous_driver_opts = PWN::Env[:driver_opts]
    path = File.join(@tmp, 'role.yaml')
    key = Base64.strict_encode64('k' * 32)
    iv = Base64.strict_encode64('i' * 16)
    PWN::Env[:ai] = { active: 'openai', openai: { model: 'gpt-4o', system_role_content: 'original role' } }
    File.write(path, YAML.dump(ai: PWN::Env[:ai]))
    File.write("#{path}.decryptor", YAML.dump(key: key, iv: iv))
    PWN::Plugins::Vault.encrypt(file: path, key: key, iv: iv)
    ciphertext = File.binread(path)
    PWN::Env[:driver_opts] = { pwn_env_path: path, pwn_dec_path: "#{path}.decryptor" }
    allow(PWN::AI::Agent::PromptBuilder).to receive(:build).and_wrap_original do |method, opts|
      method.call(opts.merge(thin: true))
    end
    expect(PWN::AI::OpenAI).to receive(:open_ai_rest_call) do |opts|
      expect(opts[:http_body][:messages].find { |message| message[:role] == 'system' }[:content]).to start_with("Saved role\nsecond line")
      { choices: [{ message: { role: 'assistant', content: 'Role forwarded.', tool_calls: [] } }] }.to_json
    end
    keys = "/system-role\n".chars
    phase = :cancel
    launch(keys) do
      case phase
      when :cancel
        expect(@paint.join).to include('SYSTEM ROLE CONTENT', 'original role', 'Ctrl+S Save', 'Esc Cancel')
        keys.concat("\u0015discarded\e".chars)
        phase = :reopen
        nil
      when :reopen
        expect(File.binread(path)).to eq(ciphertext)
        expect(PWN::Env.dig(:ai, :openai, :system_role_content)).to eq('original role')
        keys.concat("\n\u0015Saved role\nsecond line\u0013".chars)
        phase = :request
        nil
      when :request
        expect(rendered_header).to include('Saved role second line')
        keys.concat("\u0015what color is a lemon?\n".chars)
        phase = :done
        nil
      else
        @paint.any? { |row| row.include?('Role forwarded.') } ? "\u0004" : Thread.pass && nil
      end
    end
    expect(File.binread(path)).not_to include('Saved role')
    PWN::Plugins::Vault.decrypt(file: path, key: key, iv: iv)
    expect(YAML.load_file(path, symbolize_names: true).dig(:ai, :openai, :system_role_content)).to eq("Saved role\nsecond line")
  ensure
    PWN::Env[:driver_opts] = previous_driver_opts
  end

  it 'keeps failed system role edits open and blocks request and swarm context mutation' do
    PWN::Env[:ai] = { active: 'openai', openai: { system_role_content: 'original' } }
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: Curses, getch: nil)
    console.instance_variable_set(:@worker, double(alive?: true))
    console.submit('/system-role')
    expect(console.instance_variable_get(:@role_editor)).to be_nil
    console.instance_variable_set(:@worker, nil)
    console.instance_variable_set(:@swarm, double(busy?: true))
    console.submit('/system-role')
    expect(console.instance_variable_get(:@role_editor)).to be_nil
    console.instance_variable_set(:@swarm, nil)
    console.submit('/system-role')
    allow(PWN::Plugins::REPL).to receive(:persist_ai_selection).and_return(false)
    console.handle('x')
    console.handle("\u0013")
    expect(console.instance_variable_get(:@role_editor).text).to eq('originalx')
    expect(console.instance_variable_get(:@role_error)).to include('Not saved')
    expect(PWN::Env.dig(:ai, :openai, :system_role_content)).to eq('original')
  end

  it 'moves the role cursor between multiline grapheme columns without history recall' do
    PWN::Env[:ai] = { active: 'openai', openai: { system_role_content: "αβ\nx\nlast" } }
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: Curses, getch: nil)
    console.submit('/system-role')
    role = console.instance_variable_get(:@role_editor)
    console.handle(:up)
    expect(role.cursor).to eq(4)
    console.handle(:up)
    expect(role.cursor).to eq(1)
    console.handle(:down)
    expect(role.cursor).to eq(4)
    console.handle(:left)
    console.handle(:delete)
    console.handle('新')
    expect(role.text).to eq("αβ\n新\nlast")
  end

  it 'runs the real Loop from the public launch, steering a blocked model without a second input reader' do
    loop_module = PWN::AI::Agent::Loop
    entered = Queue.new
    calls = []
    Thread.current[:pwn_console_probe] = :copied
    allow(loop_module).to receive(:call_engine) do |opts|
      expect(Thread.current[:pwn_console_probe]).to eq(:copied)
      expect(Thread.current[:pwn_steering_input].reader).to be_nil
      calls << opts[:messages].map(&:dup)
      if calls.length == 1
        entered << true
        Queue.new.pop
      end
      { role: 'assistant', content: 'Yellow.', tool_calls: [] }
    end
    keys = "what color is a passion fruit?\n".chars
    steered = false
    launch(keys) do
      if !steered && !entered.empty?
        entered.pop
        steered = true
        keys.concat("/steer what color is a lemon?\n".chars)
      elsif @paint.any? { |row| row.include?('Yellow.') }
        "\u0004"
      else
        Thread.pass
        nil
      end
    end
    expect(calls.length).to eq(2)
    expect(calls.last.select { |row| row[:role] == 'user' }.map { |row| row[:content] }).to include('what color is a lemon?')
    expect(@paint.join).to include('pwn-ai', 'ASSISTANT', 'MISSION', 'steering')
  ensure
    Thread.current[:pwn_console_probe] = nil
  end

  it 'opens a draft-preserving swarm workspace and sends only after explicit confirmation' do
    allow(PWN::AI::Agent::Swarm).to receive(:personas).and_return(scout: { role: 'Inspect evidence', engine: 'ollama', model: 'fixture' })
    allow(PWN::AI::Agent::Swarm).to receive(:create).and_return(swarm_id: 'fixture')
    allow(PWN::AI::Agent::Swarm).to receive(:ask).and_return(reply: 'Workspace result')
    keys = "mission draft\u0007a".chars
    stage = 0
    launch(keys) do
      case stage
      when 0
        expect(PWN::AI::Agent::Swarm).not_to have_received(:ask)
        expect(@paint.join).to include('SWARM WORKSPACE', 'Inspect evidence', 'fixture', 'Confirm')
        stage = 1
        "\r"
      when 1
        if @paint.join.include?('Workspace result')
          stage = 2
          "\e"
        end
      when 2
        expect(@paint.last(100).join).to include('mission draft')
        "\u0004"
      end
    end
    expect(PWN::AI::Agent::Swarm).to have_received(:ask).with(include(name: 'scout', request: 'mission draft')).once
  end

  it 'cancels a blocked model on Ctrl+C, returns idle, and does not kill another worker' do
    entered = Queue.new
    foreign = Thread.new { sleep }
    allow(PWN::AI::Agent::Loop).to receive(:call_engine) {
      entered << true
      Queue.new.pop
    }
    keys = "what color is a lemon?\n".chars
    cancelled = false
    launch(keys) do
      if !cancelled && !entered.empty?
        cancelled = true
        "\u0003"
      elsif @paint.any? { |row| row.include?('Request cancelled at a safe boundary') }
        "\u0004"
      else
        Thread.pass
        nil
      end
    end
    expect(foreign).to be_alive
  ensure
    foreign&.kill
    foreign&.join
  end

  [0, 3.1].each do |startup_delay|
    it "leaves a provider blocked in native IO without waiting for that read to return (startup #{startup_delay}s)" do
      entered = Queue.new
      returned = Queue.new
      provider = nil
      started = nil
      allow(PWN::AI::Agent::Loop).to receive(:call_engine) do
        Thread.handle_interrupt(Exception => :never) do
          entered << Thread.current
          sleep 8
          returned << true
        end
      end
      keys = "what color is a lemon?\n".chars
      launched = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      launch(keys, startup_delay: startup_delay, render_delay: startup_delay.positive? ? 0.02 : 0) do
        provider ||= entered.pop unless entered.empty?
        if !started && provider&.status == 'sleep'
          # Elapsed is painted before call_engine: it is not a provider barrier.
          # Time from delivered Ctrl+C, excluding startup and per-key rendering.
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          "\u0003"
        elsif @paint.any? { |row| row.include?('Request cancelled at a safe boundary') }
          "\u0004"
        else
          Thread.pass
          nil
        end
      end
      expect(started).not_to be_nil
      expect(started - launched).to be >= startup_delay
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 3
      expect(returned).to be_empty
    ensure
      # Cancellation deliberately abandons masked IO. Release this fixture only
      # after measuring return, then reap it before RSpec removes its mocks.
      provider ||= entered.pop unless entered.empty?
      begin
        provider&.wakeup if provider&.alive?
      rescue ThreadError
        nil # The provider exited between alive? and wakeup.
      end
      provider&.join(2)
      expect(provider).not_to be_alive if provider
    end
  end

  it 'forwards tool input, preserves completed evidence before steering, and locks settings while running' do
    entered = Queue.new
    calls = 0
    observed = nil
    allow(PWN::AI::Agent::Loop).to receive(:call_engine) do
      calls += 1
      if calls == 1
        { role: 'assistant', tool_calls: %w[first stale].map { |id| { id: id, type: 'function', function: { name: 'shell', arguments: '{}' } } } }
      else
        { role: 'assistant', content: 'Yellow.', tool_calls: [] }
      end
    end
    expect(PWN::AI::Agent::Dispatch).to receive(:call).once do
      entered << true
      observed = $stdin.gets
      JSON.generate(success: true, result: { stdout: observed, exitstatus: 0 })
    end
    expect(PWN::Plugins::REPL).not_to receive(:pwn_ai_run_model)
    keys = "what color is a passion fruit?\n".chars
    sent = false
    launch(keys) do
      if !sent && !entered.empty?
        sent = true
        keys.concat("/model openai wrong\n/steer what color is a lemon?\n/input tool answer\n".chars)
        nil
      elsif @paint.any? { |row| row.include?('Yellow.') }
        "\u0004"
      else
        Thread.pass
        nil
      end
    end
    expect(observed).to eq("tool answer\n")
    expect(@paint.join).to include('TOOL', 'RESULT', 'tool answer', 'Settings and new requests wait')
    expect(@paint.join).to include('tools 1')
  end

  it 'closes the tool prompt pipe on busy exit and joins rather than orphaning the active request' do
    entered = Queue.new
    finished = Queue.new
    allow(PWN::AI::Agent::Loop).to receive(:call_engine).and_return(
      { role: 'assistant', tool_calls: [{ id: 'prompt', type: 'function', function: { name: 'shell', arguments: '{}' } }] }
    )
    allow(PWN::AI::Agent::Dispatch).to receive(:call) do
      entered << true
      answer = $stdin.gets
      finished << answer
      JSON.generate(success: true, result: { stdout: 'prompt completed', exitstatus: 0 })
    end
    keys = "what color is a lemon?\n".chars
    launch(keys) { entered.empty? ? nil : "\u0004" }
    expect(finished.pop).to be_nil
  end

  it 'wraps menu selection without changing the draft or persistent history, then recalls after Escape' do
    stored = "first request\nsecond request\n"
    File.write(@history_path, stored)
    @request_history.load
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    editor = console.instance_variable_get(:@editor)
    console.seed_request_history
    '/verbose '.each_char { |key| console.handle(key) }
    menu = console.instance_variable_get(:@menu)
    expect(menu.map { |item| item[:label] }).to eq(%w[off on])
    draft = [editor.text.dup, editor.cursor]
    console.handle(:up)
    expect(console.instance_variable_get(:@menu_index)).to eq(1)
    console.handle(:down)
    expect(console.instance_variable_get(:@menu_index)).to eq(0)
    console.handle("\u0010")
    expect(console.instance_variable_get(:@menu_index)).to eq(1)
    console.handle("\u000e")
    expect(console.instance_variable_get(:@menu_index)).to eq(0)
    expect(console.instance_variable_get(:@menu)).to eq(menu)
    expect([editor.text, editor.cursor]).to eq(draft)
    expect(File.read(@history_path)).to eq(stored)
    console.handle("\e")
    expect(console.instance_variable_get(:@menu)).to be_nil
    console.handle(:up)
    expect(editor.text).to eq('second request')
    console.handle(:up)
    expect(editor.text).to eq('first request')
    console.handle(:down)
    expect(editor.text).to eq('second request')
    console.handle(:down)
    expect([editor.text, editor.cursor]).to eq(draft)
    expect(File.read(@history_path)).to eq(stored)
  end

  it 'keeps typing filters live after arrow selection and accepts the selected completion with Tab' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    editor = console.instance_variable_get(:@editor)
    '/verbose '.each_char { |key| console.handle(key) }
    console.handle(:down)
    console.handle("\t")
    expect(editor.text.strip).to eq('/verbose on')
    console.handle("\u0015")
    '/verbose '.each_char { |key| console.handle(key) }
    console.handle(:up)
    'on'.each_char { |key| console.handle(key) }
    expect(console.instance_variable_get(:@menu).map { |item| item[:label] }).to eq(['on'])
    expect(console.instance_variable_get(:@menu_index)).to eq(0)
    console.handle("\t")
    expect(editor.text.strip).to eq('/verbose on')
  end

  it 'loads prior operator requests and keeps session event colors distinct' do
    pry = Pry.new
    pry.config.pwn_ai_session_id = 'color-history'
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: nil, getch: nil)
    @request_history << 'prior mission'
    expect(PWN::Sessions).not_to receive(:load)
    console.send(:seed_request_history)
    console.handle(:up)
    expect(console.instance_variable_get(:@editor).text).to eq('prior mission')
    console.add(:operator, 'look here')
    console.add(:assistant, 'answer')
    console.add(:task, 'plan')
    console.add(:tool, 'shell')
    console.add(:result, 'evidence')
    colors = console.timeline_rows(40).each_with_object({}) do |(color, text), found|
      found[:operator_label] = color if text.start_with?('OPERATOR')
      found[:operator_body] = color if text.include?('look here')
      found[:assistant] = color if text.include?('answer')
      found[:task] = color if text.include?('plan')
      found[:tool] = color if text.include?('shell')
      found[:result] = color if text.include?('evidence')
    end
    expect(colors).to eq(operator_label: 4, operator_body: 5, assistant: 5, task: 2, tool: 1, result: 3)
  end

  it 'shows model thinking in the session pane even when compact' do
    pry = Pry.new
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@verbose, false)
    console.add(:thinking, 'The lemon is yellow because of carotenoids.')
    console.add(:assistant, 'Yellow.')
    text = console.timeline_rows(60).map { |_color, row| row }.join("\n")
    expect(text).to include('THINKING')
    expect(text).to include('The lemon is yellow because of carotenoids.')
    expect(text).to include('ASSISTANT')
    expect(text).to include('Yellow.')
  end

  it 'uses template colors for every unconfigured role without mutating defaults or overrides' do
    defaults = PWN::Config.env_template.dig(:ai, :tui, :theme)
    [nil, {}, 'invalid'].each do |configured|
      expect(PWN::Plugins::REPL::AIConsole.theme(theme: configured)).to eq(defaults)
    end
    overrides = defaults.transform_values { 'blue' }.freeze
    expect(PWN::Plugins::REPL::AIConsole.theme(theme: overrides)).to eq(overrides)
    expect(overrides.values.uniq).to eq(['blue'])
    PWN::Env[:ai] = {}
    expect(PWN::Plugins::REPL::AIConsole.theme).to eq(defaults)
    expect(PWN::Config.env_template.dig(:ai, :tui, :theme)).to eq(defaults)
  end

  it 'applies ai.tui.theme and ignores unknown color names' do
    previous = PWN::Env[:ai]
    PWN::Env[:ai] = { tui: { theme: { assistant: 'blue', border: 'nope' } } }
    theme = PWN::Plugins::REPL::AIConsole.theme
    expect(theme[:assistant]).to eq('blue')
    expect(theme[:border]).to eq('black')
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.add(:assistant, 'themed answer')
    color = console.timeline_rows(40).find { |_pair, text| text.include?('themed answer') }&.first
    expect(color).to eq(6)
    console.instance_variable_set(:@height, 20)
    console.instance_variable_set(:@width, 80)
    painted = []
    allow(console).to receive(:put) { |row, column, text, pair| painted << [row, column, text, pair] }
    console.box(0, 0, 4, 24, 'MISSION')
    expect(painted.first[3]).to eq(console.tone(:border))
    title = painted.find { |row, _column, text, _pair| row.zero? && text.include?('MISSION') }
    expect(title[3]).to eq(console.tone(:title))
    expect(title[3]).not_to eq(painted.first[3])
  ensure
    PWN::Env[:ai] = previous
  end

  it 'draws every game without wordmark glyphs in color, monochrome and tiny panes' do
    PWN::Banner.mini_names.product([1, 3, 5, 8, 16, 20], [true, false]).each do |name, size, colors|
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
      allow(PWN::Banner).to receive(:mini_names).and_return([name])
      now = 100.0
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { now }
      console.instance_variable_set(:@banner_colors, colors)
      console.instance_variable_set(:@banner_two_colors, colors)
      calls = []
      allow(console).to receive(:put) { |*args| calls << args }
      console.draw_banner(size)
      now += 10.0
      console.draw_banner(size)
      expect(calls.map { |_, _, text| text }.join).not_to match(/[PWN]/)
      expect(calls).to all(satisfy { |y, x, text| y.between?(1, size) && x >= 1 && x + text.length <= size + 1 })
      expect(console.banner_frame(size).join).not_to match(/[PWN]/)
    end
  end

  it 'selects one mini-banner per session and advances only from monotonic elapsed time' do
    pry = Pry.new
    pry.config.pwn_ai_session_id = 'banner-one'
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@banner_activated, true)
    choices = PWN::Banner.mini_names.first(2)
    allow(PWN::Banner).to receive(:mini_names).and_return(choices)
    allow(choices).to receive(:sample).and_return(*choices)
    now = 100.0
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { now }
    first = console.banner_frame(8)
    expect(first).to eq(PWN::Banner.mini_frame(name: choices.first, frame: 0, width: 8, height: 8, branding: false))
    now += PWN::Banner::MINI_FRAME_SECONDS / 2
    expect(console.banner_frame(8)).to eq(first)
    now += PWN::Banner::MINI_FRAME_SECONDS * 0.75
    expect(console.banner_frame(8)).to eq(PWN::Banner.mini_frame(name: choices.first, frame: 1, width: 8, height: 8, branding: false))
    now += PWN::Banner::MINI_FRAME_SECONDS * PWN::Banner::MINI_FRAME_COUNT
    expect(console.banner_frame(12)).to eq(PWN::Banner.mini_frame(name: choices.first, frame: 1, width: 12, height: 12, branding: false))
    expect(choices).to have_received(:sample).once
    pry.config.pwn_ai_session_id = 'banner-two'
    expect(console.banner_frame(8)).to eq(PWN::Banner.mini_frame(name: choices.last, frame: 0, width: 8, height: 8, branding: false))
    expect(choices).to have_received(:sample).twice
  end

  it 'centers capped retro artwork inside a larger cell-square canvas' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@banner_activated, true)
    allow(PWN::Banner).to receive(:mini_names).and_return([:pacman])
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(100.0)
    size = 24
    canvas = console.banner_frame(size)
    art = PWN::Banner.mini_frame(name: :pacman, frame: 0, width: size, height: size, branding: false)
    expect(canvas.length).to eq(size)
    expect(canvas.map(&:length)).to all(eq(size))
    top = (size - art.length) / 2
    left = (size - art.first.length) / 2
    expect(canvas.slice(top, art.length).map { |row| row[left, art.first.length] }).to eq(art)
    expect(canvas.first(top)).to all(eq(' ' * size))
  end

  it 'paints falling blocks against the actual pane floor even beyond sixteen cells' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@banner_activated, true)
    allow(PWN::Banner).to receive(:mini_names).and_return([:falling_blocks])
    now = 100.0
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { now }
    console.banner_frame(20, cells: true)
    seed = console.instance_variable_get(:@banner_seed)
    frames = PWN::Banner.send(:mini_replay, name: :falling_blocks, width: 20, height: 21, seed: seed)
    tick = frames.index { |frame| frame[:event] == :lock }
    now += (tick + 0.1) * PWN::Banner::MINI_FRAME_SECONDS
    calls = []
    allow(console).to receive(:put) { |*args| calls << args }
    console.draw_banner(20)
    expect(calls.select { |y, _x, text| y == 20 && text.strip != '' }).not_to be_empty
    expect(calls.map { |_, _, text| text }.join).not_to match(/[PWN]/)
    expect(calls).to all(satisfy { |y, x, text| y.between?(1, 20) && x >= 1 && x + text.length <= 21 })
  end

  it 'carves a themed cell-square banner pane only when all settings still fit, keeping bounds and draft' do
    allow(PWN::Banner).to receive(:mini_names).and_return([:falling_blocks])
    PWN::Env[:ai] = { active: :ollama, tui: { theme: { category: 'magenta', header: 'white', border: 'blue', title: 'red' } },
                      ollama: { model: 'fixture', system_role_content: 'Complete functional settings.', reasoning_effort: 'high' } }
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil)
    curses = double(lines: 36, cols: 120)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
    console.instance_variable_set(:@screen, screen)
    console.instance_variable_get(:@editor).place('retained draft', 4)
    painted = []
    rectangles = []
    allow(console).to receive(:put) { |*args| painted << args }
    allow(console).to receive(:box).and_wrap_original do |method, *args|
      rectangles << args
      method.call(*args)
    end
    allow(PWN::Banner).to receive(:mini_cells).and_call_original
    console.draw
    expect(rectangles).to include([0, 0, 10, 10, ''])
    expect(rectangles).to include([0, 10, 10, 109, "pwn-ai v#{PWN::VERSION}"])
    expect(console.instance_variable_get(:@header_text_column)).to eq(12)
    expect(painted).to include([2, 12, 'PROVIDER (ENGINE):', console.tone(:category)])
    expect(painted.any? { |y, x, text, color| y == 0 && x == 0 && text.include?('╭') && color == console.tone(:border) }).to be(true)
    expect(painted.any? { |y, x, _text, _color| y == 0 && x == 2 }).to be(false)
    expect(painted.select { |y, x, _text, _color| y < 10 && x < 10 }.map { |_, _, text| text }.join).not_to match(/[PWN]/)
    expect(painted.select { |y, x, text, _color| y.between?(1, 8) && x == 1 && text == ' ' * 8 }.length).to eq(8)
    expect(painted.select { |y, _x, _text, _color| y < 10 }).to all(satisfy { |y, x, text, _color| y >= 0 && x >= 0 && x + console.width(text) <= 120 })
    expect(PWN::Banner).not_to have_received(:mini_cells)
    expect(console.banner_frame(8, cells: true).flatten.map { |cell| cell[:foreground] }.uniq).to eq([:white])
    [[80, 36], [120, 24]].each do |columns, rows|
      allow(curses).to receive_messages(cols: columns, lines: rows)
      rectangles.clear
      console.draw
      expect(rectangles.map(&:last)).not_to include('')
      expect(console.instance_variable_get(:@header_text_column)).to eq(2)
    end
    allow(curses).to receive_messages(cols: 120, lines: 26)
    PWN::Env[:ai][:ollama][:system_role_content] = 'operator ' * 200
    console.draw
    expect(console.instance_variable_get(:@header_text_column)).to eq(2)
    expect(console.header_lines('ollama', 'fixture', 115).length).to be > 16
    expect(PWN::Banner).not_to have_received(:mini_cells)
    expect([console.instance_variable_get(:@editor).text, console.instance_variable_get(:@editor).cursor]).to eq(['retained draft', 4])
  end

  it 'keeps a full connected maze and one-cell actors in native minimum and typical console layouts' do
    allow(PWN::Banner).to receive(:mini_names).and_return([:pacman])
    PWN::Env[:ai] = { active: :ollama, ollama: { model: 'fixture' } }
    [[100, 26], [120, 36]].each do |columns, rows|
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
      console.instance_variable_set(:@width, columns)
      console.instance_variable_set(:@height, rows)
      console.instance_variable_set(:@focus, :animation)
      allow(console).to receive(:put)
      allow(console).to receive(:box)
      allow(console).to receive(:mark_active)
      expect(console.draw_header('ollama', 'fixture')).to eq(10)
      game = console.instance_variable_get(:@banner_game)
      frame = game.step
      maze = frame[:state][:maze]
      expect(maze.length).to eq(8)
      expect(maze.map(&:length)).to all(eq(8))
      expect(maze[2...-2].map { |row| row[2...-2] }.join.count('#')).to be >= 4
      expect(game.cells(frame).flatten.count { |cell| cell[:foreground] == :red }).to eq(1)
      game.key(:right)
      expect(game.step[:state][:pacman]).to eq([2, 6])
    end
  end

  it 'grows both game canvas dimensions with the header without recursively shrinking settings' do
    allow(PWN::Banner).to receive(:mini_names).and_return([:falling_blocks])
    PWN::Env[:ai] = { active: :ollama, ollama: { model: 'fixture', system_role_content: 'operator ' * 100, reasoning_effort: 'high' } }
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@width, 120)
    console.instance_variable_set(:@height, 40)
    console.instance_variable_set(:@banner_activated, true)
    allow(console).to receive(:put)
    allow(console).to receive(:box)
    allow(PWN::Banner).to receive(:mini_cells).and_call_original
    height = console.draw_header('ollama', 'fixture')
    expect(height).to be > 10
    expect(console).to have_received(:box).with(0, 0, height, height, '')
    expect(PWN::Banner).to have_received(:mini_cells).with(hash_including(width: height - 2, height: height - 2))
    expect(console.instance_variable_get(:@header_spans).length + 3).to be <= height
    expect(console.header_lines('ollama', 'fixture', console.instance_variable_get(:@header_text_width)).join).to include('REASONING EFFORT: high')
  end

  it 'paints centered colored block cells inside the square without reusing theme pairs' do
    curses = double(has_colors?: true, start_color: nil, use_default_colors: nil, init_pair: nil, color_pairs: 256)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
    allow(ENV).to receive(:key?).with('NO_COLOR').and_return(false)
    console.setup_colors
    expect(curses).to have_received(:init_pair).with(9, Curses::COLOR_CYAN, Curses::COLOR_BLACK)
    expect(curses).to have_received(:init_pair).with(16, Curses::COLOR_BLACK, Curses::COLOR_BLACK)
    allow(console).to receive(:put)
    allow(console).to receive(:banner_frame).with(8, cells: true).and_return([[{ glyph: '█', foreground: :cyan, background: :black }]])
    console.draw_banner(8)
    expect(console).to have_received(:put).with(4, 4, '█', 9)
    expect(console).to have_received(:put).with(8, 1, ' ' * 8, 16)
    oversized = Array.new(10) { Array.new(10) { { glyph: '▀', foreground: :yellow, background: :black } } }
    allow(console).to receive(:banner_frame).with(8, cells: true).and_return(oversized)
    calls = []
    allow(console).to receive(:put) { |*args| calls << args }
    console.draw_banner(8)
    expect(calls).to all(satisfy { |y, x, text, _pair| y.between?(1, 8) && x >= 1 && x + text.length <= 9 })
  end

  it 'paints both colors of touching blocks and preserves solid occupancy without color' do
    [256, 32, 16].each do |count|
      curses = double(has_colors?: true, start_color: nil, use_default_colors: nil, init_pair: nil, color_pairs: count)
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
      allow(ENV).to receive(:key?).with('NO_COLOR').and_return(false)
      console.setup_colors
      allow(console).to receive(:put)
      allow(console).to receive(:banner_frame).with(8, cells: true).and_return([[{ glyph: '▀', foreground: :cyan, background: :red }]])
      console.draw_banner(8)
      if count == 256
        palette = PWN::Plugins::REPL::AIConsole::Console::PALETTE
        pair = 17 + (palette.reject { |color| color == 'black' }.index('red') * 8)
        expect(curses).to have_received(:init_pair).with(pair, Curses::COLOR_CYAN, Curses::COLOR_RED)
        expect(console).to have_received(:put).with(4, 4, '▀', pair)
      else
        expect(console).to have_received(:put).with(4, 4, '█', nil)
      end
    end
  end

  it 'retains block glyphs without allocating color pairs under NO_COLOR or on limited palettes' do
    [true, false].each do |no_color|
      curses = double(has_colors?: true, start_color: nil, use_default_colors: nil, init_pair: nil, color_pairs: 16)
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
      allow(ENV).to receive(:key?).with('NO_COLOR').and_return(no_color)
      console.setup_colors
      expect(curses).not_to have_received(:init_pair).with(9, anything, anything)
      allow(console).to receive(:put)
      allow(console).to receive(:banner_frame).with(8, cells: true).and_return([[{ glyph: '█', foreground: :green, background: :black }]])
      console.draw_banner(8)
      expect(console).to have_received(:put).with(4, 4, '█', nil)
    end
  end

  it 'uses the same monotonic cadence and session selection for colored frames' do
    pry = Pry.new
    pry.config.pwn_ai_session_id = 'colored-session'
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@banner_activated, true)
    names = [:snake]
    allow(PWN::Banner).to receive(:mini_names).and_return(names)
    expect(names).to receive(:sample).twice.and_return(:snake)
    now = 100.0
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { now }
    console.banner_frame(8, cells: true)
    seed = console.instance_variable_get(:@banner_seed)
    expect(seed).to be_a(Integer)
    expect(console.banner_frame(8, cells: true)).to eq(PWN::Banner.mini_cells(name: :snake, frame: 0, width: 8, height: 8, seed: seed, branding: false))
    now += 0.21
    expect(console.banner_frame(8, cells: true)).to eq(PWN::Banner.mini_cells(name: :snake, frame: 2, width: 8, height: 8, seed: seed, branding: false))
    expect(console.banner_frame(12, cells: true)).to eq(PWN::Banner.mini_cells(name: :snake, frame: 2, width: 12, height: 12, seed: seed, branding: false))
    expect(console.instance_variable_get(:@banner_seed)).to eq(seed)
    pry.config.pwn_ai_session_id = 'another-colored-session'
    console.banner_frame(8, cells: true)
    expect(console.instance_variable_get(:@banner_seed)).not_to eq(seed)
  end

  it 'samples Asteroids or Pac-Man once and caches the game-specific cadence outside the key path' do
    allow(PWN::Banner).to receive(:mini_cells).and_call_original
    %i[pacman asteroids].each do |name|
      pry = Pry.new
      pry.config.pwn_ai_session_id = 'fast-colored-session'
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: nil, getch: nil)
      console.instance_variable_set(:@banner_activated, true)
      names = PWN::Banner.mini_names
      allow(PWN::Banner).to receive(:mini_names).and_return(names)
      expect(names).to receive(:sample).once.and_return(name)
      expect(PWN::Banner).to receive(:mini_frame_seconds).with(name: name).once.and_call_original
      now = 100.0
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { now }
      console.banner_frame(8, cells: true)
      seed = console.instance_variable_get(:@banner_seed)
      now += 1.21
      if name == :pacman
        expect(console).to receive(:automatic_banner).with(8, now).twice.and_call_original
      else
        expect(PWN::Banner).to receive(:mini_cells).with(name: name, frame: 24, width: 8, height: 8, seed: seed, branding: false).twice.and_call_original
      end
      2.times { console.banner_frame(8, cells: true) }
    end
  end

  it 'wraps every header line and labels the system role' do
    previous = PWN::Env[:ai]
    PWN::Env[:ai] = { active: :ollama, ollama: { system_role_content: 'ethical operator ' * 12, temp: 0.2 } }
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@width, 36)
    lines = console.header_lines('ollama', 'qwen')
    expect(lines.length).to be > 2
    joined = lines.join(' ').gsub(/\s+/, ' ')
    expect(joined).to include('SYSTEM ROLE CONTENT: ethical operator')
    expect(joined).to include('PROVIDER (ENGINE): ollama MODEL: qwen')
    expect(joined).not_to match(/\brole ethical/)
  ensure
    PWN::Env[:ai] = previous
  end

  it 'refreshes text and banner geometry when a model string is changed in place' do
    PWN::Env[:ai] = { active: +'ollama', ollama: { model: +'before' } }
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil)
    curses = double(lines: 50, cols: 120)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
    console.instance_variable_set(:@screen, screen)
    console.draw
    old_height = console.instance_variable_get(:@header_pane_height)
    PWN::Env[:ai][:ollama][:model].replace('new-model-' * 90)
    console.draw
    expect(console.instance_variable_get(:@header_lines).join).to include('new-model-')
    expect(console.instance_variable_get(:@header_pane_height)).to be > old_height
  end

  it 'reuses wrapped settings until the width or values change' do
    PWN::Env[:ai] = { active: :ollama, ollama: { system_role_content: 'long role ' * 500 } }
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@width, 80)
    lines = console.header_lines('ollama', 'fixture')
    expect(console.header_lines('ollama', 'fixture')).to equal(lines)
    expect(console.header_lines('ollama', 'fixture', 40)).not_to equal(lines)
    PWN::Env[:ai][:ollama][:temp] = 0.3
    expect(console.header_lines('ollama', 'fixture').join).to include('TEMP: 0.3')
  end

  it 'draws the complete settings by growing the header and preserves label colors across wraps and resize' do
    PWN::Env[:ai] = { active: :ollama, tui: { theme: { category: 'magenta', header: 'white' } },
                      ollama: { system_role_content: 'operator ' * 35, temp: 0.2, max_tokens: 1024,
                                max_prompt_length: 2048, reasoning_effort: 'high' } }
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil)
    curses = double(lines: 48, cols: 80)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
    console.instance_variable_set(:@screen, screen)
    painted = []
    allow(console).to receive(:put).and_wrap_original do |method, *args|
      painted << args
      method.call(*args)
    end
    [[80, 48], [48, 60], [160, 48]].each do |columns, rows|
      allow(curses).to receive_messages(lines: rows, cols: columns)
      painted.clear
      console.draw
      lines = console.header_lines('ollama', PWN::Plugins::REPL.pwn_ai_engine_model(engine: 'ollama'), console.instance_variable_get(:@header_text_width))
      text_column = console.instance_variable_get(:@header_text_column)
      header = painted.select { |y, x, _text, _color| y >= 2 && y < lines.length + 2 && x >= text_column && x < columns - 2 }
      actual = header.group_by(&:first).values.map { |row| row.map { |entry| entry[2] }.join }
      expect(actual).to eq(lines)
      expect(header.select { |entry| entry[3] == console.tone(:category) }.map { |entry| entry[2] }.join).to include('SYSTEM ROLE CONTENT:', 'MAX PROMPT LENGTH:', 'REASONING EFFORT:')
      expect(header.select { |entry| entry[3] == console.tone(:header) }.map { |entry| entry[2] }.join).to include('operator', '1024', 'high')
      expect(console.instance_variable_get(:@page_size)).to be >= 1
    end
    console.header_lines('ollama', 'fixture', 35)
    labels = []
    console.instance_variable_get(:@header_spans).each do |row|
      row.each { |role, text| labels << text if role == :category }
    end
    expect(labels.join).to include('MAX PROMPT LENGTH:')
    expect(labels).not_to include(a_string_including('MAX PROMPT LENGTH:'))
    console.handle("\u000f")
    console.draw
    console.handle(:end)
    painted.clear
    console.draw
    expect(painted.select { |entry| entry[3] == console.tone(:category) }.map { |entry| entry[2] }.join).to include('REQUEST', 'TOKENS', 'SYSTEM ROLE CONTENT:', 'REASONING EFFORT:')
    expect(painted.select { |entry| entry[3] == console.tone(:header) }.map { |entry| entry[2] }.join).to include('1024', 'high')
  end

  it 'bounds long settings at every usable size and exposes the full text without sacrificing the draft' do
    PWN::Env[:ai] = { active: :ollama, ollama: { system_role_content: "#{'operator ' * 500}ROLE END", temp: 0.2 } }
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil)
    curses = double(lines: 24, cols: 80)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
    console.instance_variable_set(:@screen, screen)
    editor = console.instance_variable_get(:@editor)
    editor.replace('retained draft')
    rectangles = []
    allow(console).to receive(:box).and_wrap_original do |method, *args|
      rectangles << args
      method.call(*args)
    end
    [[160, 48], [80, 24], [48, 14]].each do |columns, rows|
      allow(curses).to receive_messages(lines: rows, cols: columns)
      rectangles.clear
      console.draw
      expect(console.instance_variable_get(:@page_size)).to be >= 1
      expect(rectangles).to all(satisfy { |top, _left, height| height >= 3 && top + height <= rows - 1 })
    end
    console.add(:assistant, 'latest evidence')
    expect(console.timeline_rows(40).last[1]).to include('latest evidence')
    console.handle("\u000f")
    console.draw
    expect(screen).to have_received(:addstr).with(a_string_including('STATUS'))
    console.handle(:end)
    console.draw
    expect(screen).to have_received(:addstr).with(a_string_including('ROLE END')).at_least(:once)
    console.handle('x')
    console.handle("\r")
    console.handle("\e")
    expect(editor.text).to eq('retained draft')
  end

  it 'persists requests through Pry history and searches the same file in a fresh console' do
    File.write(@history_path, "existing request\n/input legacy hidden\n")
    @request_history.load
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.seed_request_history
    allow(console).to receive(:start_request)
    console.submit('durable alpha request')
    expect(File.read(@history_path)).to include("durable alpha request\n")
    console.submit('durable alpha request')
    Pry.history << 'durable alpha request'
    console.submit('/input excluded secret')
    console.submit('  /input excluded secret')
    expected = "existing request\n/input legacy hidden\ndurable alpha request\n"
    expect(File.read(@history_path)).to eq(expected)
    reloaded = Pry::History.new(file_path: @history_path)
    reloaded.load
    allow(Pry).to receive(:history).and_return(reloaded)
    fresh = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    fresh.seed_request_history
    fresh.instance_variable_get(:@editor).place('unsent draft', 2)
    fresh.handle(:up)
    expect(fresh.instance_variable_get(:@editor).text).to eq('durable alpha request')
    fresh.handle(:up)
    expect(fresh.instance_variable_get(:@editor).text).to eq('existing request')
    fresh.handle(:down)
    fresh.handle(:down)
    expect([fresh.instance_variable_get(:@editor).text, fresh.instance_variable_get(:@editor).cursor]).to eq(['unsent draft', 2])
    fresh.handle("\u0012")
    'alpha'.each_char { |char| fresh.handle(char) }
    fresh.handle("\r")
    expect(fresh.instance_variable_get(:@editor).text).to eq('durable alpha request')
    fresh.handle("\u000c")
    expect(File.read(@history_path)).to eq(expected)
    fresh.handle("\u0012")
    'hidden'.each_char { |char| fresh.handle(char) }
    expect(fresh.instance_variable_get(:@editor).search[:match]).to be_nil
  end

  it 'selects broadcast and debate targets explicitly, escapes missions, and restores the exact draft cursor' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    swarm = PWN::Plugins::REPL::AISwarm::Controller.new(session_id: 'fixture')
    console.instance_variable_set(:@swarm, swarm)
    allow(PWN::AI::Agent::Swarm).to receive(:personas).and_return(scout: { role: 'Inspect' }, critic: { role: 'Critique' })
    allow(swarm).to receive(:execute).and_return(ok: true, job_id: 'fixture')
    editor = console.instance_variable_get(:@editor)
    editor.place("--names\nquoted 'mission'", 4)
    console.handle("\u0007")
    console.handle('d')
    expect(console.instance_variable_get(:@workspace)[:notice]).to include('at least 2')
    [' ', 'j', ' ', 'b'].each { |key| console.handle(key) }
    expect(swarm).not_to have_received(:execute)
    expect(console.swarm_content.join).to include("--names\nquoted 'mission'")
    console.handle("\r")
    expect(swarm).to have_received(:execute).with(include(line: Shellwords.join(['/swarm', 'broadcast', '--names', 'scout,critic', '--', editor.text])))
    console.handle("\t")
    console.handle('d')
    console.handle("\r")
    expect(swarm).to have_received(:execute).with(include(line: Shellwords.join(['/swarm', 'debate', 'scout,critic', '--', editor.text])))
    console.handle("\u0007")
    expect([editor.text, editor.cursor]).to eq(["--names\nquoted 'mission'", 4])
  ensure
    swarm&.close
  end

  it 'handles empty rosters, new persona prompts, errors and no-job navigation without submitting a mission' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    swarm = PWN::Plugins::REPL::AISwarm::Controller.new(session_id: 'fixture')
    console.instance_variable_set(:@swarm, swarm)
    allow(PWN::AI::Agent::Swarm).to receive(:personas).and_return({})
    allow(swarm).to receive(:execute).and_return(ok: false, error: 'fixture spawn failed')
    console.handle("\u0007")
    expect(console.swarm_content.join).to include('No agents')
    "nscout\rInspect evidence\r".each_char { |key| console.handle(key) }
    expect(swarm).not_to have_received(:execute)
    console.handle("\r")
    expect(console.instance_variable_get(:@workspace)[:notice]).to eq('fixture spawn failed')
    console.handle("\t")
    expect(console.swarm_content.join).to include('No jobs yet')
    ['s', 'c', "\r", "\e", "\e"].each { |key| console.handle(key) }
    expect(console.instance_variable_get(:@workspace)).to be_nil
    expect(swarm).to have_received(:execute).once
  ensure
    swarm&.close
  end

  it 'clears only the displayed session on Ctrl+L even while busy' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    editor = console.instance_variable_get(:@editor)
    editor.preload(['retained request'])
    editor.replace('draft')
    console.add(:assistant, 'visible evidence')
    allow(console).to receive(:busy?).and_return(true)
    allow(console).to receive(:clear_view).and_call_original
    console.instance_variable_get(:@usage).record(usage: { input_tokens: 123, output_tokens: 45 })
    usage = console.instance_variable_get(:@usage).snapshot
    expect(PWN::Sessions).not_to receive(:append)
    console.handle("\u000c")
    expect(console).to have_received(:clear_view)
    expect(console.timeline_rows(60).join).not_to include('visible evidence')
    expect(console.instance_variable_get(:@usage).snapshot).to eq(usage)
    expect(editor.text).to eq('draft')
    console.handle(:up)
    expect(editor.text).to eq('retained request')
  end

  it 'searches local request history incrementally, accepts without sending and cancels with cursor restored' do
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: double(lines: 30, cols: 100), getch: nil)
    console.instance_variable_set(:@screen, screen)
    editor = console.instance_variable_get(:@editor)
    editor.preload(['older alpha', '/input hidden alpha', 'newer alpha', 'beta'])
    editor.place('original draft', 3)
    expect(console).not_to receive(:submit)
    console.handle("\u0012")
    'alpha'.each_char { |char| console.handle(char) }
    console.draw
    expect(screen).to have_received(:addstr).with(a_string_including('alpha')).at_least(:once)
    expect(screen).to have_received(:addstr).with(a_string_including('newer alpha')).at_least(:once)
    console.handle("\u0012")
    console.handle("\r")
    expect(editor.text).to eq('older alpha')
    console.handle(:up)
    expect(editor.text).to eq('beta')
    console.handle(:down)
    expect(editor.text).to eq('older alpha')
    editor.place('original draft', 3)
    console.handle("\u0012")
    'missing'.each_char { |char| console.handle(char) }
    console.draw
    expect(screen).to have_received(:addstr).with(a_string_including('no match')).at_least(:once)
    console.handle("\u007f")
    console.handle("\e")
    expect([editor.text, editor.cursor]).to eq(['original draft', 3])
  end

  it 'reads application and kitty arrow sequences as history keys' do
    reader, writer = IO.pipe
    writer.write("\eOA\e[1;1B")
    writer.close
    keyboard = PWN::Plugins::REPL::AIConsole::Keyboard.new(reader)
    expect(keyboard.call).to eq(:up)
    expect(keyboard.call).to eq(:down)
  ensure
    reader&.close
  end

  it 'does not retain tool input in recall history' do
    editor = PWN::Plugins::REPL::AIConsole::Editor.new
    editor.replace('previous task')
    editor.submit
    editor.replace('/input secret tool response')
    editor.submit
    editor.recall(:up)
    expect(editor.text).to eq('previous task')
  end

  it 'flushes an unterminated dependency prompt through the event queue without terminal control bytes' do
    queue = Queue.new
    output = PWN::Plugins::REPL::AIConsole::EventIO.new(queue)
    output.write('Tool asks: value? ')
    output.flush
    expect(queue.size).to eq(1)
  end

  it 'pages above the current viewport on the first PgUp and pins that position for incoming output' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@total_rows, 100)
    console.instance_variable_set(:@page_size, 20)
    console.handle(:page_up)
    expect(console.instance_variable_get(:@scroll)).to eq(60)
    console.add(:notice, 'new output')
    expect(console.instance_variable_get(:@scroll)).to eq(60)
    console.handle(:page_down)
    expect(console.instance_variable_get(:@scroll)).to be_nil
  end

  it 'toggles the active pane so session arrows, Home and End scroll without changing the draft' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    editor = console.instance_variable_get(:@editor)
    editor.place('kept draft', 4)
    console.instance_variable_set(:@total_rows, 100)
    console.instance_variable_set(:@page_size, 20)
    console.instance_variable_set(:@unseen, 3)
    console.handle(:up)
    expect(editor.text).to eq('kept draft')
    expect(console.instance_variable_get(:@scroll)).to be_nil
    console.handle("\u0018")
    expect(console.instance_variable_get(:@focus)).to eq(:session)
    console.handle(:up)
    expect(console.instance_variable_get(:@scroll)).to eq(79)
    console.handle("\u0010")
    expect(console.instance_variable_get(:@scroll)).to eq(78)
    console.handle(:home)
    expect(console.instance_variable_get(:@scroll)).to eq(0)
    console.handle(:end)
    expect(console.instance_variable_get(:@scroll)).to be_nil
    console.handle(:page_up)
    expect(console.instance_variable_get(:@scroll)).to eq(60)
    console.handle(:page_down)
    expect(console.instance_variable_get(:@scroll)).to be_nil
    console.handle(:page_down)
    expect(console.instance_variable_get(:@scroll)).to be_nil
    console.handle(:home)
    expect(console.instance_variable_get(:@scroll)).to eq(0)
    console.handle(:page_up)
    expect(console.instance_variable_get(:@scroll)).to eq(0)
    expect(console.instance_variable_get(:@unseen)).to eq(0)
    console.handle(:end)
    console.handle(:up)
    console.handle(:down)
    expect(console.instance_variable_get(:@scroll)).to be_nil
    expect([editor.text, editor.cursor]).to eq(['kept draft', 4])
    console.handle("\n")
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
    expect(editor.text).to eq('kept draft')
    console.handle("\u0018")
    console.handle('x')
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
    expect(editor.text).to eq('keptx draft')
    console.handle(:up)
    expect(console.instance_variable_get(:@scroll)).to be_nil
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
  end

  it 'marks the active pane and parks the cursor in the session when that pane is selected' do
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil, attron: nil)
    allow(screen).to receive(:attron).and_yield
    curses = double(lines: 36, cols: 120)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
    console.instance_variable_set(:@screen, screen)
    painted = []
    allow(console).to receive(:put) { |*args| painted << args }
    console.draw
    expect(painted.map { |row| row[2] }.join).to include('MISSION CONTROL · active')
    expect(painted.map { |row| row[2] }.join).not_to include('SESSION  · active')
    expect(screen).to have_received(:attron).with(Curses::A_REVERSE).at_least(:once)
    console.handle("\u0018")
    painted.clear
    console.draw
    expect(painted.map { |row| row[2] }.join).to include('SESSION  · active')
    expect(screen).to have_received(:setpos).with(a_kind_of(Integer), 2)
    console.handle("\u0014")
    painted.clear
    console.draw
    expect(painted.map { |row| row[2] }.join).to include(' PLAY ')
    expect(painted.map { |row| row[2] }.join).not_to include('MISSION CONTROL · active')
    expect(screen).to have_received(:setpos).with(1, 1)
    allow(curses).to receive_messages(lines: 24, cols: 80)
    console.draw
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
  end

  it 'shows only the white rabbit before the first animation focus without computing games' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    expect(PWN::Banner).not_to receive(:mini_cells)
    expect(PWN::Banner).not_to receive(:mini_frame)
    expect(PWN::Banner::MiniGame).not_to receive(:new)
    first = console.banner_frame(8, cells: true)
    expect(first.flatten.map { |cell| cell[:foreground] }.uniq).to eq([:white])
    expect(first.flatten.count { |cell| cell[:glyph] != ' ' }).to be > 16
    console.instance_variable_set(:@header_pane_height, 10)
    console.handle("\u0014")
    expect(console.banner_frame(8, cells: true)).to eq(first)
    expect(console.banner_frame(8).join).not_to match(/[PWN]/)
  end

  it 'uses fine two by four text dots without terminal image output' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    [8, 12, 16, 18].each do |size|
      glyphs = console.banner_frame(size, cells: true).flatten.map { |cell| cell[:glyph] }
      expect(glyphs).to all(match(/\A[ \u2801-\u28ff]\z/))
      expect(glyphs.uniq.length).to be > 4
    end
    source = File.read(File.expand_path('../../../../../lib/pwn/plugins/repl/ai_console.rb', __dir__))
    expect(source).not_to include('graphics_response?', '\\e_G')
  end

  it 'area-filters fractional source pixels instead of losing a bend to point sampling' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    expect(console.rabbit_coverage([0b10, 0b01], 2, [0, 0, 1, 1])).to eq(0.5)
    expect(console.rabbit_coverage([0b10, 0b01], 2, [0.25, 0, 0.75, 0.5])).to eq(0.5)
    expect(console.rabbit_coverage([0b10, 0b01], 2, [0, 0, 0.5, 0.5])).to eq(1.0)
    expect(console.rabbit_coverage([0b10, 0b01], 2, [0.5, 0, 1, 0.5])).to eq(0.0)
  end

  it 'derives every source row from WhiteRabbit.get and preserves the native art without labels' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    source = PWN::Banner::WhiteRabbit.get.uncolorize
    expect(PWN::Banner::WhiteRabbit).to receive(:get).once.and_return(source)
    rows = source.lines.map { |row| row.sub('R.I.P. Houdini', '').sub('pwn', '').rstrip }.reject(&:empty?).map { |row| row[8..] }
    expect(console.rabbit_source).to eq(rows)
    expect(rows.join.chars.uniq - PWN::Plugins::REPL::AIConsole::Console::RABBIT_STROKES.keys).to be_empty
    [22, 34, 64].each do |size|
      art = console.banner_frame(size)
      top = (size - rows.length) / 2
      left = (size - rows.map(&:length).max) / 2
      rows.each_with_index { |row, y| expect(art[top + y][left, row.length]).to eq(row) }
      expect(art.join).not_to match(/pwn|Houdini|\e/)
    end
  end

  it 'contains the rabbit with centered aspect-correct padding across tiny resizes' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    expect(PWN::Banner::MiniGame).not_to receive(:new)
    expect(console.banner_frame(0, cells: true)).to eq([])
    [1, 2, 3, 5, 8, 12, 13, 14, 16, 18, 8].each do |size|
      cells = console.banner_frame(size, cells: true)
      expect(cells.length).to eq(size)
      expect(cells.map(&:length)).to all(eq(size))
      expect(cells.flatten.map { |cell| [cell[:foreground], cell[:background]] }.uniq).to eq([%i[white black]])
      points = []
      cells.each_with_index do |row, y|
        row.each_with_index do |cell, x|
          next if cell[:glyph] == ' '

          mask = cell[:glyph] == ' ' ? 0 : cell[:glyph].ord - 0x2800
          expect(mask).not_to be_nil
          [[0, 0, 1], [0, 1, 2], [0, 2, 4], [0, 3, 64], [1, 0, 8], [1, 1, 16], [1, 2, 32], [1, 3, 128]].each do |dx, dy, bit|
            points << [(x * 2) + dx, (y * 4) + dy] if mask.anybits?(bit)
          end
        end
      end
      expect(points).not_to be_empty
      next if size < 8

      xs, ys = points.transpose
      ratio = console.rabbit_source.map(&:length).max.fdiv(console.rabbit_source.length * 2)
      expect((xs.max - xs.min + 1).fdiv(ys.max - ys.min + 1)).to be_within(0.1).of(ratio)
      expect((xs.min - ((size * 2) - 1 - xs.max)).abs).to be <= 2
      expect((ys.min - ((size * 4) - 1 - ys.max)).abs).to be <= 2
      expect(points.length).to be > size * 3
      expect(cells.flatten.map { |cell| cell[:glyph] }.uniq.length).to be > 4
      expect(console.banner_frame(size, cells: true)).to equal(cells)
    end
  end

  it 'paints only white with a 64-pair palette and keeps rabbit geometry in monochrome' do
    [false, true].each do |no_color|
      curses = double(has_colors?: true, start_color: nil, use_default_colors: nil, init_pair: nil, color_pairs: 64)
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
      allow(ENV).to receive(:key?).with('NO_COLOR').and_return(no_color)
      allow(PWN::Banner).to receive(:mini_names).and_return([:falling_blocks])
      console.setup_colors
      painted = []
      allow(console).to receive(:put) { |*args| painted << args }
      console.draw_banner(8)
      ink = painted.reject { |_, _, glyph, _| glyph.strip.empty? }
      expect(ink).not_to be_empty
      white = 9 + PWN::Plugins::REPL::AIConsole::Console::PALETTE.index('white')
      expect(ink.map(&:last).uniq).to eq([no_color ? nil : white])
      expect(ink.map { |_, _, glyph, _| glyph }).to all(match(/[\u2801-\u28ff]/))
    end
  end

  it 'activates once on actual focus, cycles games and never restores the splash on return' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    allow(PWN::Banner).to receive(:mini_names).and_return(%i[snake pacman])
    allow(Process).to receive(:clock_gettime).and_return(10.0)
    splash = console.banner_frame(8, cells: true)
    console.instance_variable_set(:@header_pane_height, 10)
    2.times { console.handle("\u0014") }
    console.banner_frame(8, cells: true)
    game = console.instance_variable_get(:@banner_game)
    expect(game).to be_a(PWN::Banner::MiniGame)
    console.handle("\e")
    expect(console.banner_frame(8, cells: true)).not_to eq(splash)
    2.times { console.handle("\u0018") }
    console.banner_frame(8, cells: true)
    expect(console.instance_variable_get(:@banner_game)).to equal(game)
    name = console.instance_variable_get(:@banner_name)
    console.handle("\u0007")
    console.banner_frame(8, cells: true)
    expect(console.instance_variable_get(:@banner_name)).not_to eq(name)
    expect(console.instance_variable_get(:@banner_game)).not_to equal(game)
    console.handle("\e")
    expect(console.banner_frame(12, cells: true)).not_to eq(console.rabbit_cells(12))
  end

  it 'does not activate games when the pane is hidden or focus keys belong to a modal' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    expect(PWN::Banner::MiniGame).not_to receive(:new)
    4.times { console.handle("\u0014") }
    expect(console.instance_variable_get(:@banner_activated)).to be_nil
    console.instance_variable_set(:@header_pane_height, 10)
    console.instance_variable_set(:@details, 0)
    expect(console).to receive(:handle_details).with("\u0018")
    console.handle("\u0018")
    expect(console.banner_frame(8, cells: true)).to eq(console.rabbit_cells(8))
  end

  it 'cycles mission, session and visible animation with both shortcuts without changing the draft' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    editor = console.instance_variable_get(:@editor)
    editor.place('kept draft', 4)
    console.instance_variable_set(:@header_pane_height, 10)
    console.banner_frame(8, cells: true)
    console.handle("\u0014")
    console.handle("\u0018")
    expect(console.instance_variable_get(:@focus)).to eq(:animation)
    console.banner_frame(8, cells: true)
    game = console.instance_variable_get(:@banner_game)
    expect(game).to receive(:key).with(:up)
    expect(game).to receive(:key).with(' ')
    console.handle(:up)
    console.handle(' ')
    expect([editor.text, editor.cursor]).to eq(['kept draft', 4])
    console.handle("\u0014")
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
    expect([editor.text, editor.cursor]).to eq(['kept draft', 4])
  end

  it 'paints an Asteroids turn on the next draw without waiting for its physics tick' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.banner_frame(8, cells: true)
    console.instance_variable_set(:@banner_name, :asteroids)
    console.instance_variable_set(:@banner_frame_seconds, 0.05)
    console.instance_variable_set(:@focus, :animation)
    first = console.playable_banner(8, 10.001)
    console.handle(:left)
    expect(console.playable_banner(8, 10.002)).not_to eq(first)
    expect(console.playable_banner(8, 10.003)).to eq(console.playable_banner(8, 10.002))
    console.instance_variable_set(:@banner_game_frame, { state: { explosion: 12 } })
    game = console.instance_variable_get(:@banner_game)
    expect(game).not_to receive(:step)
    16.times { console.handle(:up) }
    console.playable_banner(8, 10.004)
  end

  it 'waits for Snake input and routes timed turns across the full pane instead of restarting' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.banner_frame(8, cells: true)
    console.instance_variable_set(:@banner_name, :snake)
    console.instance_variable_set(:@banner_frame_seconds, 0.1)
    console.instance_variable_set(:@focus, :animation)
    first = console.playable_banner(8, 10.0)
    40.times { |tick| expect(console.playable_banner(8, 10.05 + (tick * 0.1))).to eq(first) }
    game = console.instance_variable_get(:@banner_game)
    frames = []
    allow(game).to(receive(:step).and_wrap_original { |method| method.call.tap { |frame| frames << frame } })
    console.handle(:right)
    console.playable_banner(8, 15.0)
    head = frames.last[:state][:body].first
    console.handle(:up)
    console.playable_banner(8, 15.05)
    expect(frames.length).to eq(1)
    console.playable_banner(8, 15.21)
    expect(frames.last[:state][:body].first).to eq([head[0], head[1] - 1])
    console.handle(:right)
    console.playable_banner(8, 15.41)
    expect(frames.last[:state][:body].first).to eq([head[0] + 1, head[1] - 1])
    expect(game.instance_variable_get(:@width)).to eq(8)
    expect(frames.last[:rows].drop(1).map(&:length)).to all(eq(16))
    expect(console.instance_variable_get(:@editor).text).to eq('')
  end

  it 'cycles games with Ctrl+G only in animation focus and preserves swarm and modal priorities' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.banner_frame(8, cells: true)
    console.instance_variable_set(:@banner_name, :falling_blocks)
    console.instance_variable_set(:@focus, :animation)
    editor = console.instance_variable_get(:@editor)
    editor.place('kept draft', 4)
    %i[snake pacman asteroids galaga frogger falling_blocks].each do |name|
      console.handle("\u0007")
      expect(console.instance_variable_get(:@banner_name)).to eq(name)
      expect(console.instance_variable_get(:@workspace)).to be_nil
      console.banner_frame(8, cells: true)
      expect(console.instance_variable_get(:@banner_game).instance_variable_get(:@name)).to eq(name.to_s)
      expect(console.footer_text).to include('^G=next game')
      expect(console.footer_text).to include('↑↓←→ start/steer · ● power') if name == :pacman
      expect(console.footer_text).to include('↑↓←→ move · Space=fire') if name == :galaga
      expect(console.footer_text).to include('↑↓←→ hop · logs → goals') if name == :frogger
      expect(console.operation_lines.join).to include('^S swarm')
    end
    console.instance_variable_set(:@details, 0)
    expect(console).to receive(:handle_details).with("\u0007")
    console.handle("\u0007")
    console.instance_variable_set(:@details, nil)
    editor.search_history
    expect(console).to receive(:handle_search).with("\u0007")
    console.handle("\u0007")
    editor.finish_search
    console.handle("\u0013")
    expect(console.instance_variable_get(:@workspace)).to be_a(Hash)
    console.handle("\u0007")
    expect(console.instance_variable_get(:@workspace)).to be_nil
    expect(console.instance_variable_get(:@banner_name)).to eq(:falling_blocks)
    console.handle("\e")
    console.handle("\u0007")
    expect(console.instance_variable_get(:@workspace)).to be_a(Hash)
    expect([editor.text, editor.cursor]).to eq(['kept draft', 4])
  end

  it 'delivers timed Pac-Man buffered arrows without consuming the mission draft or speeding up on repeats' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.banner_frame(8, cells: true)
    console.instance_variable_set(:@banner_name, :pacman)
    console.instance_variable_set(:@banner_seed, 9)
    console.instance_variable_set(:@banner_frame_seconds, 0.1)
    console.instance_variable_set(:@focus, :animation)
    editor = console.instance_variable_get(:@editor)
    editor.place('kept draft', 4)
    console.playable_banner(7, 10.01)
    console.handle(:right)
    console.playable_banner(7, 10.11)
    expect(console.instance_variable_get(:@banner_game_frame)[:state][:pacman]).to eq([2, 5])
    console.handle(:up)
    10.times { console.playable_banner(7, 10.12) }
    expect(console.instance_variable_get(:@banner_game_frame)[:state][:pacman]).to eq([2, 5])
    [10.21, 10.31, 10.41, 10.51, 10.61, 10.71].each { |time| console.playable_banner(7, time) }
    expect(console.instance_variable_get(:@banner_game_frame)[:state][:pacman]).to eq([3, 4])
    console.handle("\e")
    expect([editor.text, editor.cursor]).to eq(['kept draft', 4])
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
  end

  it 'returns to the unchanged automatic animation when focus leaves the game' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    allow(Process).to receive(:clock_gettime).and_return(10.0)
    console.instance_variable_set(:@banner_activated, true)
    automatic = console.banner_frame(8, cells: true)
    console.instance_variable_set(:@header_pane_height, 10)
    2.times { console.handle("\u0014") }
    expect(console.banner_frame(8, cells: true)).not_to eq(automatic)
    console.handle("\u0018")
    expect(console.banner_frame(8, cells: true)).to eq(automatic)
    console.instance_variable_set(:@header_pane_height, nil)
    2.times { console.handle("\u0014") }
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
  end

  it 'streams the new arcade demos on the UI owner without a synchronous full replay build' do
    %i[pacman galaga frogger].each do |name|
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
      console.instance_variable_set(:@banner_activated, true)
      allow(PWN::Banner).to receive(:mini_names).and_return([name])
      allow(Process).to receive(:clock_gettime).and_return(10.0)
      expect(PWN::Banner).not_to receive(:mini_cells)
      first = console.banner_frame(32, cells: true)
      demo = console.instance_variable_get(:@banner_demo)
      expect(demo).to be_a(PWN::Banner::MiniGame)
      expect(console.instance_variable_get(:@banner_demo_frame)[:state][:started]).to be true
      expect(first.map(&:length)).to all(eq(32))
      expect(console.banner_frame(32, cells: true)).to eq(first)
      allow(Process).to receive(:clock_gettime).and_return(10.2)
      console.banner_frame(32, cells: true)
      expect(console.instance_variable_get(:@banner_demo)).to equal(demo)
      console.instance_variable_set(:@focus, :animation)
      console.banner_frame(32, cells: true)
      expect(console.instance_variable_get(:@banner_game)).not_to equal(demo)
      expect(console.instance_variable_get(:@banner_game_frame)[:state][:started]).to be false
    end
  end

  it 'keeps modal, search and cancellation priority above animation controls' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@focus, :animation)
    editor = console.instance_variable_get(:@editor)
    editor.place('draft', 2)
    game = double(key: nil)
    console.instance_variable_set(:@banner_game, game)
    console.instance_variable_set(:@details, 0)
    expect(console).to receive(:handle_details).with(:up)
    console.handle(:up)
    console.instance_variable_set(:@details, nil)
    console.instance_variable_set(:@model_prompt, {})
    expect(console).to receive(:handle_model_prompt).with(' ')
    console.handle(' ')
    console.instance_variable_set(:@model_prompt, nil)
    allow(console).to receive(:busy?).and_return(true)
    expect(console).to receive(:cancel)
    console.handle("\u0003")
    console.handle("\u0012")
    expect(editor.search).not_to be_nil
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
    expect(game).not_to have_received(:key)
    expect([editor.text, editor.cursor]).to eq(['draft', 2])
  end

  it 'preserves bracketed paste and the mission cursor when leaving animation focus' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    editor = console.instance_variable_get(:@editor)
    editor.place('draft', 2)
    console.instance_variable_set(:@focus, :animation)
    [:paste_start, ' ', "\n", 'x', :paste_end].each { |key| console.handle(key) }
    expect(editor.text).to eq("dr \nxaft")
    expect(editor.cursor).to eq(5)
    expect(console.instance_variable_get(:@focus)).to eq(:mission)
  end

  it 'toggles the pane with Ctrl+T and opens swarm with Ctrl+S' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.handle("\u0014")
    expect(console.instance_variable_get(:@focus)).to eq(:session)
    console.handle("\u0013")
    expect(console.instance_variable_get(:@workspace)).to be_a(Hash)
    console.handle("\u0013")
    expect(console.instance_variable_get(:@workspace)).to be_nil
  end

  it 'wraps the footer inside the window and omits the composer hint line' do
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil)
    curses = double(lines: 24, cols: 48)
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: curses, getch: nil)
    console.instance_variable_set(:@screen, screen)
    painted = []
    allow(console).to receive(:put) { |*args| painted << args }
    console.draw
    text = painted.map { |row| row[2].to_s }.join("\n")
    expect(text).not_to include('^X pane')
    expect(text).to include('^T=toggle pane', '^S=swarm', 'Shift+Enter=newline', 'Enter=send')
    footer = painted.select { |row| row[2].to_s.include?('^T=toggle pane') || row[2].to_s.include?('Enter=send') || row[2].to_s.include?('/ menu') }
    expect(footer.length).to be > 1
    expect(footer).to all(satisfy { |_y, _x, line, _color| console.width(line) <= 46 })
    console.handle("\u0014")
    painted.clear
    console.draw
    session = painted.map { |row| row[2].to_s }.join
    expect(session).to include('↑↓ scroll · HOME · PGUP · PGDN · END')
    expect(session).not_to include('↑↓ history')
  end

  it 'wraps at words without discarding code whitespace or splitting graphemes' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    expect(console.wrap('some evidence', 12)).to eq(['some ', 'evidence'])
    text = "  code  evidence\n界e\u0301🙂abcdef  "
    rows = console.wrap(text, 8)
    expect(rows.join).to eq(text.delete("\n"))
    expect(rows).to all(satisfy { |row| console.width(row) <= 8 })
    expect(rows.join.scan(/\X/)).to eq(text.delete("\n").scan(/\X/))
    expect(console.wrap('abcdefghij', 4)).to eq(%w[abcd efgh ij])
    expect(console.wrap("a\n\n", 4)).to eq(['a', '', ''])
    expect(console.wrap('👩‍💻界', 2)).to eq(['👩‍💻', '界'])
    expect(console.width('👩‍💻')).to eq(2)
  end

  it 'shows observed elapsed time, completed tools, event timestamps and pinned new output' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(10.0, 12.5, 14.0)
    allow(Time).to receive(:now).and_return(Time.utc(2026, 1, 2, 3, 4, 5))
    console.begin_request_metrics
    console.add(:task, 'task summary, not a completed tool')
    console.add(:tool, "shell\n{}")
    console.add(:result, 'observed result')
    expect(console.elapsed).to eq('2.5s')
    expect(console.operation_lines.join(' ')).to include('Completed tools 1', 'Events 3', 'LAST TOOL', 'shell')
    expect(console.timeline_rows(40).map(&:last).join).to include('03:04:05', 'TOOL')
    console.instance_variable_set(:@total_rows, 100)
    console.instance_variable_set(:@page_size, 20)
    console.handle(:page_up)
    console.add(:notice, 'incoming')
    expect(console.scroll_status).to include('61–80/100', '1 new')
    console.handle(:page_down)
    expect(console.scroll_status).to eq('live')
    console.finish_request_metrics
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(100.0)
    expect(console.elapsed).to eq('4.0s')
    console.begin_request_metrics
    expect(console.operation_lines.join(' ')).to include('Completed tools 0', 'not observed')
  end

  it 'keeps tokens, cost and last tool in a short operations sidebar' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@width, 120)
    console.instance_variable_set(:@last_tool, 'shell')
    allow(console).to receive(:box)
    painted = []
    allow(console).to receive(:put) { |_row, _column, text, _color| painted << text }
    console.draw_sidebar(6, 94, 11)
    expect(painted.join(' ')).to include('TOKENS', 'Cost', 'LAST TOOL', 'shell')
  end

  it 'bounds giant timeline events explicitly and caches wrapping until width or events change' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.add(:result, 'evidence ' * 20_000)
    expect(console.instance_variable_get(:@timeline).first[1].bytesize).to be < 17_000
    rows = console.timeline_rows(40)
    expect(rows.map(&:last).join).to include('[display truncated')
    expect(console).not_to receive(:wrap)
    expect(console.timeline_rows(40)).to equal(rows)
  end

  it 'edits graphemes and restores the full-history draft and cursor' do
    editor = PWN::Plugins::REPL::AIConsole::Editor.new
    105.times do |index|
      editor.replace("task #{index}")
      editor.submit
    end
    editor.replace("界e\u0301🙂 draft")
    editor.edit(:left)
    cursor = editor.cursor
    editor.recall(:up)
    editor.edit("\b")
    editor.recall(:down)
    expect(editor.text).to eq("界e\u0301🙂 draft")
    expect(editor.cursor).to eq(cursor)
    110.times { editor.recall(:up) }
    expect(editor.text).to eq('task 0')
    editor.replace("界e\u0301🙂")
    editor.edit(:home)
    editor.edit(:right)
    editor.edit(:delete)
    expect(editor.text).to eq('界🙂')
  end

  it 'restores IO and terminal state if rendering fails' do
    original = [$stdin, $stdout, $stderr]
    keys = []
    expect do
      launch(keys) do
        allow(@screen.stdscr).to receive(:addstr).and_raise(IOError, 'paint failed')
        nil
      end
    end.to raise_error(IOError, 'paint failed')
    expect([$stdin, $stdout, $stderr]).to eq(original)
    expect(@screen).to have_received(:close_screen)
  end

  it 'keeps cancellation and exit hints visible at the minimum supported width' do
    resized = false
    launch([]) do
      if resized
        footer = @paint.select { |line| (line.include?('^C=cancel') || line.include?('Enter=send')) && Unicode::DisplayWidth.of(line) <= 46 }
        expect(footer.join).to include('^C=cancel', '^D=back')
        expect(footer.length).to be > 1
        "\u0004"
      else
        allow(@screen).to receive_messages(lines: 14, cols: 48)
        resized = true
        nil
      end
    end
  end

  it 'renders a visible slash menu and safely handles a tiny resize' do
    keys = "/\n".chars
    stage = 0
    launch(keys) do
      if stage.zero? && @paint.any? { |row| row.include?('COMMANDS') }
        stage = 1
        allow(@screen).to receive_messages(lines: 7, cols: 35)
        "\e"
      elsif stage == 1 && @paint.any? { |row| row.include?('terminal too small') }
        stage = 2
        allow(@screen).to receive_messages(lines: 30, cols: 125)
        nil
      elsif stage == 2 && @paint.any? { |row| row.include?('OPERATIONS') }
        "\u0004"
      end
    end
    expect(@paint.join).to include('/model', 'terminal too small', 'OPERATIONS')
  end

  it 'blocks hidden composer input during tiny resize, keeps its draft and still accepts cancellation and exit' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: double(lines: 7, cols: 35), getch: nil)
    screen = double(erase: nil, refresh: nil, setpos: nil, addstr: nil)
    console.instance_variable_set(:@screen, screen)
    editor = console.instance_variable_get(:@editor)
    editor.replace('saved draft')
    console.draw
    expect(console).not_to receive(:submit)
    ['x', "\r", :paste_start, :newline, :up, "\t", :paste_end].each { |key| console.handle(key) }
    expect(editor.text).to eq('saved draft')
    expect(console).to receive(:cancel).once
    console.handle("\u0003")
    console.handle("\u0004")
    expect(console.instance_variable_get(:@leaving)).to be true
    expect(editor.text).to eq('saved draft')
  end

  it 'adds console-only commands to completion without changing the global dispatcher' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    allow(PWN::Plugins::REPL).to receive(:pwn_ai_complete).and_return(['/model'])
    console.instance_variable_get(:@editor).replace('/')
    console.complete
    expect(console.instance_variable_get(:@menu).map { |item| item[:label] }).to include('/input', '/menu', '/model')
    console.instance_variable_get(:@editor).replace('/in')
    console.complete
    expect(console.instance_variable_get(:@menu).map { |item| item[:label] }).to include('/input')
    expect(console.instance_variable_get(:@menu).map { |item| item[:label] }).not_to include('/menu')
    console.instance_variable_get(:@editor).replace('/menu')
    console.complete
    console.instance_variable_set(:@menu_index, console.instance_variable_get(:@menu).index { |item| item[:label] == '/menu' })
    console.handle("\r")
    expect(PWN::Plugins::REPL).not_to receive(:pwn_ai_dispatch_slash!)
    console.handle("\r")
    expect(console.instance_variable_get(:@menu).map { |item| item[:label] }).to include('/menu', '/input')
  end

  it 'keeps slash parameter completion live across spaces and clears stale menus on submit' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    '/verbose '.chars.each { |key| console.handle(key) }
    expect(console.instance_variable_get(:@menu).map { |item| item[:label] }).to eq(%w[off on])
    console.handle('o')
    console.handle('f')
    console.handle('f')
    console.handle("\r")
    expect(console.instance_variable_get(:@menu)).to be_nil
  end

  it 'clears every cell behind the completion popup and reverses the selected row even without colors' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    screen = double('popup screen')
    paint = []
    position = nil
    reversed = false
    allow(screen).to receive(:setpos) { |*pos| position = pos }
    allow(screen).to receive(:addstr) { |text| paint << [position, text, reversed] }
    allow(screen).to receive(:attron) do |attribute, &block|
      expect(attribute).to eq(Curses::A_REVERSE)
      reversed = true
      block.call(0) # ncurses yields the wattron result
      reversed = false
    end
    console.instance_variable_set(:@screen, screen)
    console.instance_variable_set(:@width, 80)
    console.instance_variable_set(:@height, 30)
    console.instance_variable_set(:@menu, ['/界', '/menu'])
    console.instance_variable_set(:@menu_index, 0)
    console.draw_menu
    expect(paint.take(4).map { |position_and_text| position_and_text[1] }).to eq([' ' * 65] * 4)
    selected = paint.find { |_pos, text, reverse| reverse && text.include?('/界') }
    expect(selected).not_to be_nil
    expect(console.width(selected[1])).to eq(61)
  end

  it 'keeps the terminal cursor inside the multiline composer after painting the footer' do
    launch(['界', :newline, 'é']) { "\u0004" }
    expect(@positions.last).to eq([25, 5])
  end

  it 'keeps the editing cursor in the composer while completion is open' do
    launch(['/']) { "\u0004" }
    expect(@positions.last).to eq([24, 5])
  end

  it 'keeps debug output queued and restores the debug tee after leaving curses' do
    log = PWN::Plugins::Log
    allow(log).to receive(:debug_dir).and_return(File.join(@tmp, 'debug'))
    previous = $stdout
    allow(PWN::AI::Agent::Loop).to receive(:call_engine).and_return(role: 'assistant', content: 'Debug final.', tool_calls: [])
    PWN::Plugins::REPL.add_commands
    keys = "/debug\nwhat color is a lemon?\n".chars
    launch(keys) { @paint.any? { |row| row.include?('Debug final.') } ? "\u0004" : nil }
    expect(log.instance_variable_get(:@debug_tee)).to equal(previous)
    expect(log.raw_stderr).not_to be_a(PWN::Plugins::REPL::AIConsole::EventIO)
    path = log.debug_log_path
    expect(File.read(path)).to include('Debug final.', 'footer iter=') if path
  ensure
    log&.stop_debug
  end

  it 'cancels the reasoning overlay with the original draft and cursor intact' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    editor = console.instance_variable_get(:@editor)
    selection = { engine: 'grok', model: 'grok-4.6', efforts: %w[low medium high], default: 'medium' }
    original = Marshal.dump(PWN::Env[:ai])
    console.instance_variable_set(:@model_prompt, selection)
    console.instance_variable_set(:@model_index, 1)
    console.instance_variable_set(:@model_draft, ['/model grok grok-4.6', 7])
    expect(PWN::Plugins::REPL).not_to receive(:persist_ai_selection)
    console.handle(:down)
    expect(console.instance_variable_get(:@model_index)).to eq(2)
    console.handle("\e")
    expect(editor.text).to eq('/model grok grok-4.6')
    expect(editor.cursor).to eq(7)
    expect(Marshal.dump(PWN::Env[:ai])).to eq(original)
    expect(console.instance_variable_get(:@model_prompt)).to be_nil
  end

  def rendered_header
    boundary = @rendered.find { |_row, _column, text| text.start_with?(' SESSION ') }&.first || 0
    @rendered.select { |row, _column, _text| row < boundary }.map(&:last).join
  end

  it 'repaints an asynchronous model command with all active settings before another key' do
    PWN::Env[:ai][:openai] = { model: 'old', system_role_content: 'new operator role', temp: 0.37,
                               max_tokens: 1234, max_prompt_length: 5678, reasoning_effort: 'fixture-effort' }
    allow(PWN::Plugins::REPL).to receive(:persist_ai_selection).and_return(false)
    keys = "/model openai header-fixture\n".chars
    launch(keys) do
      header = rendered_header
      if header.include?('header-fixture')
        expect(header).to include('openai', 'new operator role', '0.37', '1234', '5678', 'fixture-effort')
        "\u0004"
      else
        Thread.pass
        nil
      end
    end
  end

  it 'repaints settings and theme changed by a command worker without worker drawing or a wakeup key' do
    PWN::Env[:ai] = { active: :ollama, ollama: { model: 'settings-fixture' } }
    owner = Thread.current
    painted = []
    allow_any_instance_of(PWN::Plugins::REPL::AIConsole::Console).to receive(:put).and_wrap_original do |method, *args|
      painted << args
      method.call(*args)
    end
    allow(PWN::Cron).to receive(:run) do
      expect(Thread.current).not_to eq(owner)
      slot = PWN::Env[:ai][PWN::Env[:ai][:active].to_sym]
      slot[:system_role_content] = 'worker settings role'
      slot[:temp] = 0.42
      slot[:max_tokens] = 4321
      slot[:max_prompt_length] = 8765
      slot[:reasoning_effort] = 'worker-effort'
      PWN::Env[:ai][:tui] = { theme: { category: 'magenta', header: 'blue' } }
      'offline settings fixture completed'
    end
    keys = "/cron run settings-fixture\n".chars
    launch(keys) do
      if rendered_header.include?('worker-effort')
        expect(rendered_header).to include('worker settings role', '0.42', '4321', '8765')
        expect(painted).to include([a_kind_of(Integer), a_kind_of(Integer), 'MODEL:', 7])
        value = painted.find { |_y, _x, text, color| color == 6 && text.to_s.include?('worker-effort') }
        expect(value).not_to be_nil
        expect(value[2]).not_to include('REASONING EFFORT:')
        "\u0004"
      else
        Thread.pass
        nil
      end
    end
  end

  it 'repaints accepted reasoning before another key even when persistence is session only' do
    PWN::Env[:ai][:openai] = { model: 'old', reasoning_effort: 'medium' }
    allow(PWN::Plugins::REPL).to receive(:persist_ai_selection).and_return(false)
    allow(PWN::AI::OpenAI).to receive(:get_models).and_return(data: [{ id: 'gpt-6-astra', supported_reasoning_levels: [{ effort: 'medium' }, { effort: 'high' }] }])
    keys = "/model openai gpt-6-astra\n".chars
    accepted = false
    launch(keys) do
      if !accepted && @rendered.any? { |row| row.last.include?('REASONING EFFORT · SELECT') }
        accepted = true
        keys.push(:down, "\n")
        nil
      elsif accepted && rendered_header.include?('gpt-6-astra')
        expect(rendered_header).to include('REASONING EFFORT:', 'high')
        "\u0004"
      else
        Thread.pass
        nil
      end
    end
  end

  ["\e", "\u0003"].each do |cancel_key|
    it "keeps the rendered header and banner unchanged after reasoning cancellation #{cancel_key.inspect}" do
      allow(PWN::Banner).to receive(:mini_names).and_return([:falling_blocks])
      allow(PWN::Plugins::REPL).to receive(:persist_ai_selection).and_return(false)
      expect(PWN::Plugins::REPL).not_to receive(:pwn_ai_apply_model)
      original = Marshal.dump(PWN::Env[:ai])
      keys = "/model grok grok-4.6\n".chars
      cancelled = false
      baseline = nil
      allow(PWN::Banner).to receive(:mini_frame).and_return(['stable artwork'])
      allow(PWN::Banner).to receive(:mini_cells).and_return([[{ glyph: '█', foreground: :cyan, background: :black }]])
      launch(keys) do
        if !cancelled && @rendered.any? { |row| row.last.include?('REASONING EFFORT · SELECT') }
          baseline = rendered_header
          cancelled = true
          cancel_key
        elsif cancelled
          expect(Marshal.dump(PWN::Env[:ai])).to eq(original)
          expect(rendered_header).to eq(baseline)
          "\u0004"
        else
          Thread.pass
          nil
        end
      end
    end
  end

  it 'renders a resumed session and reselects artwork only for an actual session change' do
    sid = PWN::Sessions.create(title: 'header resume')[:id]
    names = PWN::Banner.mini_names
    allow(PWN::Banner).to receive(:mini_names).and_return(names)
    expect(names).to receive(:sample).twice.and_return(names.first)
    keys = "/sessions resume #{sid}\n".chars
    repeated = false
    launch(keys) do
      if @rendered.any? { |row| row.last.include?("SESSION #{sid}") }
        if repeated
          "\u0004"
        else
          repeated = true
          keys.concat("/sessions resume #{sid}\n".chars)
          nil
        end
      end
    end
  end

  it 'prompts in curses and forwards the accepted effort to the next provider request' do
    PWN::Env[:ai][:openai] = { model: 'old', reasoning_effort: 'medium' }
    allow(PWN::Plugins::REPL).to receive(:persist_ai_selection).and_return(false)
    allow(PWN::AI::OpenAI).to receive(:get_models).and_return(data: [{ id: 'gpt-6-astra', supported_reasoning_levels: [{ effort: 'low' }, { effort: 'medium' }, { effort: 'high' }] }])
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).with(hash_including(reasoning_effort: 'high')) do
      { choices: [{ message: { role: 'assistant', content: 'Effort accepted.', tool_calls: [] } }] }
    end
    keys = "/model openai gpt-6-astra\n".chars
    accepted = false
    launch(keys) do
      if !accepted && @paint.any? { |row| row.include?('REASONING EFFORT · SELECT') }
        accepted = true
        keys.concat([:down, "\n"] + "what color is a lemon?\n".chars)
        nil
      elsif @paint.any? { |row| row.include?('Effort accepted.') }
        "\u0004"
      else
        Thread.pass
        nil
      end
    end
    expect(PWN::Env.dig(:ai, :openai, :reasoning_effort)).to eq('high')
  end

  it 'honors locally selected model and resumed session in the actual provider call' do
    sid = PWN::Sessions.create(title: 'resumed console')[:id]
    allow(PWN::Plugins::REPL).to receive(:persist_ai_selection).and_return(false)
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools) do
      expect(PWN::Env.dig(:ai, :openai, :model)).to eq('console-fixture')
      { choices: [{ message: { role: 'assistant', content: 'Selected route.', tool_calls: [] } }] }
    end
    keys = "/model openai console-fixture\n/sessions resume #{sid}\nwhat color is a lemon?\n".chars
    launch(keys) { @paint.any? { |row| row.include?('Selected route.') } ? "\u0004" : nil }
    expect(@pry.config.pwn_ai_session_id).to eq(sid)
    expect(PWN::Sessions.load(session_id: sid).map { |row| row[:content] }.join).to include('Selected route.')
  end

  it 'strips spinner controls, redacts queued secrets, and accepts binary dependency warnings' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.add(:notice, "\e[?25h\e[0m")
    expect(console.instance_variable_get(:@timeline)).to be_empty
    console.add(:warning, "api_key=super-secret-fixture\n\e[31mwarning\e[0m")
    expect(console.instance_variable_get(:@timeline).inspect).not_to include('super-secret-fixture', "\e")
    expect { console.add(:warning, "warning\xff".b) }.not_to raise_error
  end

  it 'decodes terminal keys and Unicode without a competing stdin reader' do
    require 'pty'
    master, slave = PTY.open
    slave.raw do
      reader = PWN::Plugins::REPL::AIConsole::Keyboard.new(slave)
      master.write("界\e[D\e[13;2u\e[3~\e[5~")
      expect(Array.new(5) { reader.call }).to eq(['界', :left, :newline, :delete, :page_up])
    end
  ensure
    master&.close
    slave&.close
  end

  it 'consumes valid UTF-8 prefixes immediately and recovers from malformed bytes' do
    source = double('incremental terminal', wait_readable: false)
    reader = PWN::Plugins::REPL::AIConsole::Keyboard.new(source)
    buffer = reader.instance_variable_get(:@buffer)
    buffer << "a\xe7".b
    expect(reader.call).to eq('a')
    expect(reader.call).to be_nil
    buffer << "\x95\x8c".b
    expect(reader.call).to eq('界')
    buffer << "\xff\xe0\x80b\xe7c".b
    expect(Array.new(6) { reader.call }).to eq(['�', '�', '�', 'b', '�', 'c'])
    buffer << "\xf0\x9f".b
    expect(reader.call).to be_nil
    buffer << "\x99\x82".b
    expect(reader.call).to eq('🙂')
  end

  it 'keeps the grapheme cursor valid when combining characters arrive as separate terminal keys' do
    editor = PWN::Plugins::REPL::AIConsole::Editor.new
    editor.insert('e')
    editor.insert("\u0301")
    expect(editor.cursor).to eq(1)
    editor.edit("\b")
    expect(editor.text).to eq('')
  end

  it 'exposes steering and cancellation as operational states rather than simulated progress' do
    control = PWN::Plugins::REPL::AIConsole::Control.new(input: StringIO.new, output: StringIO.new)
    control.submit('revised task')
    expect(control.phase.to_s).to include('steering')
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@worker, Thread.current)
    console.instance_variable_set(:@cancelling, true)
    expect(console.state).to include('cancelling')
  end

  it 'keeps network slash commands off the event thread so tool prompts can receive explicit input' do
    entered = Queue.new
    expect(PWN::AI::Agent::Loop).not_to receive(:run)
    expect(PWN::Plugins::REPL).to receive(:pwn_ai_dispatch_slash!).with(request: '/mcp call fixture', pry: anything) do
      entered << true
      puts "local command received: #{$stdin.gets}"
      true
    end
    keys = "/mcp call fixture\n".chars
    sent = false
    launch(keys) do
      if !sent && !entered.empty?
        sent = true
        keys.concat("/input ready\n".chars)
        nil
      elsif @paint.any? { |row| row.include?('local command received: ready') }
        "\u0004"
      end
    end
  end

  it 'routes the actual pwn-ai command into the default fullscreen console and leaves the mode on return' do
    repl = PWN::Plugins::REPL
    repl.add_commands
    pi = Pry.new
    pi.config.pwn_ai_startup_session_id = 'prepared-console-session'
    allow(PWN::ModuleSkills).to receive(:install)
    allow(PWN::Config).to receive(:load_skills)
    allow(PWN::Config).to receive(:load_memory)
    allow(PWN::Memory).to receive(:load).and_return({})
    allow(PWN::Cron).to receive(:list).and_return({})
    expect(PWN::Plugins::REPL::AIConsole).to receive(:run).with(pry: pi).and_return(:closed)
    expect(repl).to receive(:leave_special_mode!).with(pry: pi)
    Pry::Commands.find_command('pwn-ai').new(pry_instance: pi, output: StringIO.new).process
    expect(pi.config.pwn_ai_session_id).to eq('prepared-console-session')
  end

  it 'provides a public curses console with an honest non-terminal fallback' do
    expect(PWN::Plugins::REPL.const_defined?(:AIConsole)).to be true
    expect(PWN::Plugins::REPL::AIConsole.run(pry: Pry.new, input: StringIO.new, output: StringIO.new)).to eq(:unavailable)
  end
end
