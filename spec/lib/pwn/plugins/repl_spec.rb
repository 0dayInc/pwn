# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::REPL
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::REPL
    expect(help_response).to respond_to :help
  end

  it 'does not append plan usage to the pwn.ai PS1' do
    src = File.read(described_class.method(:refresh_ps1_proc).source_location.first)
    expect(src).not_to include('plan_usage_glyph')
    expect(src).not_to include('PWN::AI.plan_usage')
    expect(src).to include('current_context_length')
  end

  it 'paints (TRACE) in red on the PS1 when toggle-trace is on, not green (DEBUG)' do
    src = File.read(described_class.method(:refresh_ps1_proc).source_location.first)
    expect(src).to include('pwn_ai_trace')
    expect(src).to include('(TRACE)')
    expect(src).to match(/\\e\[31m.*\(TRACE\)/)
    expect(src).to match(/pwn_ai_trace.*\(TRACE\)/m)
    expect(src).to match(/pwn_ai_debug.*\(DEBUG\)/m)
  end

  it 'formats compact token counts for the PS1 budget' do
    expect(described_class.compact_context_tokens(tokens: 0)).to eq('0')
    expect(described_class.compact_context_tokens(tokens: 26_000)).to eq('26K')
    expect(described_class.compact_context_tokens(tokens: 500_000)).to eq('500K')
  end

  it 'ready_tty! exists and the pwn-ai path resets the TTY before the next PS1' do
    expect(described_class).to respond_to :ready_tty!
    hook = File.read(described_class.method(:add_hooks).source_location.first)
    expect(hook).to match(/ready_tty!/)
    expect(hook).to match(/request\.replace\('nil'\)/)
    reader = File.read(described_class.const_get(:PWNMultiLineInput).instance_method(:readline).source_location.first)
    expect(reader).to match(/ready_tty!/)
  end

  it 'reinstalls generated module skills into ~/.pwn/skills before load_skills on pwn-ai start' do
    src = File.read(described_class.method(:add_commands).source_location.first)
    expect(src).to match(/ModuleSkills\.install/)
    expect(src).to match(/ModuleSkills\.install.*load_skills|install_default_skills.*load_skills/m)
  end

  it 'ready_tty! halts leftover spinner workers so PS1 can redraw without Enter' do
    src = File.read(described_class.method(:ready_tty!).source_location.first)
    expect(src).to match(/halt_all!/)
    expect(described_class.method(:add_hooks).source_location).not_to be_nil
    hook = File.read(described_class.method(:add_hooks).source_location.first)
    expect(hook).to match(/ensure/)
    expect(hook).to match(/ready_tty!/)
    io = StringIO.new
    spin = PWN::Plugins::TTYSpinner.start(output: io, format: :dots)
    worker = spin.pwn_worker_thread
    expect(worker).to be_a(Thread)
    expect(worker.alive?).to eq true
    described_class.ready_tty!(io: io)
    expect(worker.alive?).to eq false
    expect(spin.done?).to eq true
  end

  describe 'pwn-ai completion menus' do
    it 'classifies leading slash as command, other slash as path, else ruby' do
      expect(described_class).to respond_to(:pwn_ai_complete_kind)
      expect(described_class.pwn_ai_complete_kind(line: '/cron')).to eq(:command)
      expect(described_class.pwn_ai_complete_kind(line: '/skills rec')).to eq(:command)
      expect(described_class.pwn_ai_complete_kind(line: 'open /opt/pwn')).to eq(:path)
      expect(described_class.pwn_ai_complete_kind(line: '~/src/foo')).to eq(:path)
      expect(described_class.pwn_ai_complete_kind(line: 'PWN::Plugins::Nmap')).to eq(:ruby)
      expect(described_class.pwn_ai_complete_kind(line: '')).to eq(:ruby)
    end

    it 'completes slash commands including cron/skills/sessions' do
      hits = described_class.pwn_ai_complete(target: '/sk', line: '/sk')
      expect(hits).to include('/skills')
      hits = described_class.pwn_ai_complete(target: '/', line: '/')
      %w[/cron /skills /sessions /memory /debug /trace /back /help /model /learning].each do |cmd|
        expect(hits).to include(cmd)
      end
      hits = described_class.pwn_ai_complete(target: 'li', line: '/cron li')
      expect(hits).to include('list')
      hits = described_class.pwn_ai_complete(target: 'li', line: '/model li')
      expect(hits).to include('list')
      hits = described_class.pwn_ai_complete(target: 'll', line: '/model list ll')
      expect(hits).to include('llms')
    end

    it 'completes host-native paths when slash is not the first character' do
      Dir.mktmpdir('pwn-ai-path') do |dir|
        FileUtils.mkdir_p(File.join(dir, 'alpha'))
        File.write(File.join(dir, 'alpha', 'readme.md'), 'x')
        File.write(File.join(dir, 'bravo.txt'), 'y')
        prefix = File.join(dir, 'a')
        hits = described_class.pwn_ai_complete(
          target: prefix,
          line: "read #{prefix}"
        )
        expect(hits.any? { |h| h.end_with?('/alpha/') || h.end_with?('/alpha') }).to eq true
      end
    end

    it 'installs the completer from pwn-ai and restores Pry Ruby completion on back' do
      src = File.read(described_class.method(:add_commands).source_location.first)
      expect(src).to match(/install_pwn_ai_completer!/)
      expect(src).to match(/restore_pwn_ai_completer!/)
      expect(src).to include("Pry::Commands.create_command 'pwn-ai'")
      expect(src).to include("Pry::Commands.create_command 'back'")
    end

    it 'dispatches matching leading-slash commands locally instead of Loop.run' do
      hook = File.read(described_class.method(:add_hooks).source_location.first)
      expect(hook).to match(/pwn_ai_dispatch_slash!/)
      expect(described_class).to respond_to(:pwn_ai_dispatch_slash!)
    end

    it 'switches the live engine and model via /model without Loop.run' do
      expect(described_class).to respond_to(:pwn_ai_run_model)
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:grok] ||= {}
      prev_active = PWN::Env[:ai][:active]
      prev_model = PWN::Env[:ai][:grok][:model]
      allow(described_class).to receive(:persist_ai_selection).and_return(false)
      out = described_class.pwn_ai_run_model(args: %w[grok pwn-ai-test-model])
      expect(PWN::Env[:ai][:active].to_s).to eq('grok')
      expect(PWN::Env[:ai][:grok][:model]).to eq('pwn-ai-test-model')
      expect(out.to_s).to match(/grok/i)
    ensure
      if PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash)
        PWN::Env[:ai][:active] = prev_active if defined?(prev_active)
        PWN::Env[:ai][:grok][:model] = prev_model if defined?(prev_model) && PWN::Env[:ai][:grok].is_a?(Hash)
      end
    end

    it 'lists llm ids from the active provider via /model list llms' do
      expect(described_class).to respond_to(:pwn_ai_list_llms)
      PWN::Env[:ai] ||= {}
      prev_active = PWN::Env[:ai][:active]
      PWN::Env[:ai][:active] = 'grok'
      allow(PWN::AI::Grok).to receive(:get_models).and_return(
        [{ id: 'grok-test-a' }, { id: 'grok-test-b' }]
      )
      ids = described_class.pwn_ai_run_model(args: %w[list llms])
      expect(ids).to eq(%w[grok-test-a grok-test-b])
    ensure
      PWN::Env[:ai][:active] = prev_active if PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash)
    end
  end
end
