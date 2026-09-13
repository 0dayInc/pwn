# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL do # rubocop:disable Metrics/BlockLength
  def command_src
    [
      described_class,
      described_class::ASM,
      described_class::AI,
      described_class::IRC,
      described_class::Mesh,
      described_class::Vault
    ].map { |mod| File.read(mod.method(:add_commands).source_location.first) }.uniq.join("\n")
  end

  describe 'ai.memory pinned engagement block' do
    it 'handles dotted commands locally in AI mode and registers the Pry command' do
      described_class.add_commands
      expect(Pry::Commands.find_command('ai.memory')).not_to be_nil
      expect(described_class).to receive(:pwn_ai_memory_command).with(pry: :fixture, args: %w[edit notes])
      expect(described_class.pwn_ai_dispatch_slash!(request: 'ai.memory edit notes', pry: :fixture)).to be(true)
    end

    it 'edits and reloads session notes without changing the original goal' do
      require 'tmpdir'
      require 'pwn/ai/agent/engagement_memory'
      pi = Struct.new(:config).new(Struct.new(:pwn_ai_session_id).new('memory-fixture'))
      allow(PWN::Sessions).to receive(:load).with(session_id: 'memory-fixture').and_return([{ role: 'user', content: 'original goal' }])
      Dir.mktmpdir do |root|
        out = StringIO.new
        described_class.pwn_ai_memory_command(pry: pi, args: ['edit', 'verified evidence'], root: root, output: out)
        described_class.pwn_ai_memory_command(pry: pi, args: [], root: root, output: out)
        expect(out.string).to include('original goal', 'verified evidence')
        expect(JSON.parse(File.read(File.join(root, 'memory-fixture', 'engagement-memory.json')))['notes']).to eq('verified evidence')
      end
    end
  end

  describe 'ai.profile routing selection' do
    it 'validates and selects a profile without mutating provider defaults' do
      pi = Struct.new(:config).new(Struct.new(:pwn_ai_profile).new)
      env = { ai_profiles: { local: { provider: 'ollama', model: 'fixture' } }, ai: { active: 'openai' } }
      output = StringIO.new
      route = described_class.pwn_ai_profile_command(pry: pi, args: ['local'], env: env, output: output)
      expect(route).to include(provider: :ollama, model: 'fixture')
      expect(pi.config.pwn_ai_profile).to eq('local')
      expect(env[:ai]).to eq(active: 'openai')
      expect { described_class.pwn_ai_profile_command(pry: pi, args: ['missing'], env: env, output: output) }.to raise_error(ArgumentError)
      expect(pi.config.pwn_ai_profile).to eq('local')
    end

    it 'registers and dispatches ai.profile locally' do
      described_class.add_commands
      expect(Pry::Commands.find_command('ai.profile')).not_to be_nil
      expect(described_class).to receive(:pwn_ai_profile_command).with(pry: :fixture, args: ['local'])
      expect(described_class.pwn_ai_dispatch_slash!(request: 'ai.profile local', pry: :fixture)).to be(true)
    end
  end

  it 'launches pwn-ai from a local startup hook without changing ordinary start' do
    stub_const('PWN::Env', { driver_opts: {} })
    allow(PWN::Plugins::MonkeyPatch).to receive(:pry)
    allow(described_class).to receive(:add_commands)
    allow(described_class).to receive(:add_hooks)
    allow(described_class).to receive(:enable_autocomplete)
    allow(described_class).to receive(:refresh_ps1_proc).and_return(proc { '' })
    allow(Pry.config).to receive(:hooks).and_return(Pry::Hooks.new)
    pi = double('pry', config: Pry::Config.new)
    expect(pi).to receive(:run_command).with('pwn-ai')
    expect(Pry).to receive(:start) do |_main, options|
      options.fetch(:hooks).exec_hook(:before_session, StringIO.new, TOPLEVEL_BINDING, pi)
      expect(pi.config.pwn_ai_startup_session_id).to eq('prepared-session')
    end
    described_class.start(ai_session_id: 'prepared-session')
  end

  it 'uses the prepared CLI session rather than creating a second session on activation' do
    described_class.add_commands
    config = Pry::Config.new
    config.pwn_ai_startup_session_id = 'ingested-session'
    pi = double('pry', config: config)
    allow(described_class).to receive(:install_pwn_ai_completer!)
    allow(PWN::ModuleSkills).to receive(:install)
    allow(PWN::Config).to receive(:load_skills)
    allow(PWN::Config).to receive(:load_memory)
    allow(PWN::Memory).to receive(:load).and_return({})
    allow(PWN::Cron).to receive(:list).and_return({})
    expect(PWN::Sessions).not_to receive(:create)
    command = Pry::Commands.find_command('pwn-ai').new(pry_instance: pi, output: StringIO.new)
    command.process
    expect(config.pwn_ai_session_id).to eq('ingested-session')
    expect(config.pwn_ai_startup_session_id).to be_nil
  end

  it 'documents session activation and the profile and pinned memory helpers' do
    expect { described_class.help }.to output(/pwn_ai_activation_session.*pwn_ai_profile_command.*pwn_ai_memory_command/m).to_stdout
  end

  it 'treats CTRL+D as back when pwn-ai is active instead of exiting Pry' do
    described_class.add_commands
    config = Pry::Config.new
    config.pwn_ai = true
    config.pwn_ai_agent = true
    config.pwn_ai_speak = true
    config.color = false
    pi = double('pry', config: config)
    allow(described_class).to receive(:restore_pwn_ai_completer!)
    described_class.leave_special_mode!(pry: pi)
    expect(config.pwn_ai).to eq(false)
    expect(config.pwn_ai_agent).to eq(false)
    expect(config.pwn_ai_speak).to eq(false)
    expect(config.color).to eq(true)
    expect(Pry::Commands.find_command('back')).not_to be_nil
  end

  it 'returns nil from pwn-ai input on EOF so Pry can run the CTRL+D handler' do
    pi = double('pry', config: Pry::Config.new)
    allow(Reline).to receive(:readmultiline).and_return(nil)
    input = described_class::PWNMultiLineInput.new(pi)
    allow(input).to receive(:ensure_tmux_extended_keys)
    expect(input.readline('> ')).to be_nil
  end

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
    src = command_src
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
      %w[/cron /skills /sessions /memory /debug /trace /back /help /model /learning /mcp].each do |cmd|
        expect(hits).to include(cmd)
      end
      hits = described_class.pwn_ai_complete(target: 'li', line: '/cron li')
      expect(hits).to include('list')
      hits = described_class.pwn_ai_complete(target: 'li', line: '/model li')
      expect(hits).to include('list')
      hits = described_class.pwn_ai_complete(target: 'll', line: '/model list ll')
      expect(hits).to include('llms')
      hits = described_class.pwn_ai_complete(target: '/m', line: '/m')
      expect(hits).to include('/mcp')
      hits = described_class.pwn_ai_complete(target: 'co', line: '/mcp co')
      expect(hits).to include('connect')
      hits = described_class.pwn_ai_complete(target: 'to', line: '/mcp list to')
      expect(hits).to include('tools')
      hits = described_class.pwn_ai_complete(target: 'com', line: '/mcp connect com')
      expect(hits).to include('combo_nation')
      hits = described_class.pwn_ai_complete(target: 'use', line: '/mcp us')
      expect(hits).to include('use')
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
      src = command_src
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

    it 'lists OpenAI Codex catalog slugs via /model list llms' do
      PWN::Env[:ai] ||= {}
      prev_active = PWN::Env[:ai][:active]
      PWN::Env[:ai][:active] = 'openai'
      allow(PWN::AI::OpenAI).to receive(:get_models).and_return(
        { models: [{ slug: 'gpt-5.5' }, { slug: 'gpt-6-astra', display_name: 'GPT-6-Astra' }] }
      )
      ids = described_class.pwn_ai_run_model(args: %w[list llms])
      expect(ids).to eq(%w[gpt-5.5 gpt-6-astra])
    ensure
      PWN::Env[:ai][:active] = prev_active if PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash)
    end

    it 'lists MCP backends via /mcp without Loop.run or hardware' do
      expect(described_class.pwn_ai_dispatch_slash!(request: '/mcp backends', pry: :fixture)).to eq(true)
      result = described_class.pwn_ai_run_mcp(args: %w[list])
      expect(result[:backends].map { |row| row[:name] }).to include('combo_nation')
      call = described_class.send(:pwn_ai_mcp_call_args, tokens: %w[msg=hi option=5.10])
      expect(call[:arguments]).to include('msg' => 'hi', 'option' => '5.10')
      expect(call[:option]).to be_nil
    end

    it 'routes /mcp use and /mcp <backend> call to a non-ComboNation client' do
      probe = Module.new do
        def self.connect(opts = {})
          { connected: true, allow_hardware: opts[:allow_hardware] }
        end

        def self.disconnect(opts = {})
          opts[:session]
          { disconnected: true }
        end

        def self.list_tools(opts = {})
          opts[:session]
          [{ 'name' => 'echo' }]
        end

        def self.call_tool(opts = {})
          { parsed: { 'name' => opts[:name], 'arguments' => opts[:arguments] }, is_error: false }
        end
      end
      probe.const_set(:TOOLS, %w[echo])
      PWN::AI::MCP.const_set(:Probe, probe)
      PWN::AI::MCP.reset!
      expect(described_class.pwn_ai_run_mcp(args: %w[use probe])).to include(backend: 'probe')
      hits = described_class.pwn_ai_complete(target: 'e', line: '/mcp call e')
      expect(hits).to include('echo')
      expect(hits).not_to include('menu_catalog')
      result = described_class.pwn_ai_run_mcp(args: %w[probe call echo msg=hi])
      expect(result[:backend]).to eq('probe')
      expect(result[:parsed]).to include('name' => 'echo', 'arguments' => { 'msg' => 'hi' })
    ensure
      PWN::AI::MCP.send(:remove_const, :Probe) if PWN::AI::MCP.const_defined?(:Probe, false)
      PWN::AI::MCP.reset!
    end
  end

  describe 'pwn-mesh transports' do
    it 'selects mqtt serial bluetooth or tcp from config' do
      expect(described_class.send(:mesh_transport, env: {})).to eq(:auto)
      expect(described_class.send(:mesh_transport, env: { transport: 'auto' })).to eq(:auto)
      expect(described_class.send(:mesh_transport, env: { transport: 'serial' })).to eq(:serial)
      expect(described_class.send(:mesh_transport, env: { transport: 'bluetooth' })).to eq(:bluetooth)
      expect(described_class.send(:mesh_transport, env: { transport: 'tcp' })).to eq(:tcp)
      expect(described_class.send(:mesh_transport, env: { transport: 'mqtt' })).to eq(:mqtt)
    end

    it 'probes serial then bluetooth then tcp then mqtt unless /transport pinned' do
      require 'meshtastic'
      env = {
        transport: 'auto',
        serial: { port: '/dev/ttyUSB0', baud: 115_200, bits: 8, stop: 1, parity: :none },
        bluetooth: { address: 'AA:BB:CC:DD:EE:FF' },
        tcp: { host: '127.0.0.1', port: 4403 },
        mqtt: { host: 'mqtt.example', port: 1883, tls: false, user: 'u', pass: 'p' }
      }
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
      expect(Meshtastic::Serial).to receive(:connect).and_raise(IOError, 'no serial')
      expect(Meshtastic::Bluetooth).to receive(:connect).and_raise(IOError, 'no ble')
      expect(Meshtastic::TCP).to receive(:connect).and_raise(IOError, 'no tcp')
      expect(Meshtastic::MQTT).to receive(:connect).and_return(:mqtt_obj)
      expect(described_class.send(:mesh_connect, env: env)).to eq(:mqtt_obj)
      expect(PWN.const_get(:MeshTransport)).to eq(:mqtt)
    ensure
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
    end

    it 'passes MQTT connect a hash and does not treat string false as TLS' do
      require 'meshtastic'
      env = {
        mqtt: { host: 'mqtt.example', port: 1883, tls: 'false', user: 'u', pass: 'p' }
      }
      expect(Meshtastic::MQTT).to receive(:connect).with(
        hash_including(host: 'mqtt.example', port: 1883, tls: false, username: 'u', password: 'p')
      ).and_return(:mqtt_obj)
      expect(described_class.send(:mesh_connect_one, env: env, transport: :mqtt)).to eq(:mqtt_obj)
    end

    it 'lists every auto-probe failure instead of only the MQTT TLS error' do
      require 'openssl'
      require 'meshtastic'
      env = {
        transport: 'auto',
        serial: { port: '/dev/ttyUSB0', baud: 115_200, bits: 8, stop: 1, parity: :none },
        bluetooth: { address: 'AA:BB:CC:DD:EE:FF' },
        tcp: { host: '127.0.0.1', port: 4403 },
        mqtt: { host: 'mqtt.example', port: 1883, tls: true, user: 'u', pass: 'p' }
      }
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
      expect(Meshtastic::Serial).to receive(:connect).and_raise(IOError, 'no serial')
      expect(Meshtastic::Bluetooth).to receive(:connect).and_raise(IOError, 'no ble')
      expect(Meshtastic::TCP).to receive(:connect).and_raise(IOError, 'no tcp')
      expect(Meshtastic::MQTT).to receive(:connect).and_raise(
        OpenSSL::SSL::SSLError, 'SSL_connect unexpected eof while reading'
      )
      expect { described_class.send(:mesh_connect, env: env) }.to raise_error(
        IOError, /serial: IOError: no serial.*mqtt: OpenSSL::SSL::SSLError: SSL_connect unexpected eof/m
      )
    ensure
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
    end

    it 'stops auto-probe on the first transport that connects' do
      require 'meshtastic'
      env = { transport: 'auto', serial: { port: '/dev/ttyUSB0', baud: 115_200, bits: 8, stop: 1, parity: :none } }
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
      expect(Meshtastic::Serial).to receive(:connect).and_return(:serial_obj)
      expect(Meshtastic::Serial).to receive(:wait_for_config).and_return(:serial_obj)
      expect(Meshtastic::Bluetooth).not_to receive(:connect)
      expect(Meshtastic::TCP).not_to receive(:connect)
      expect(Meshtastic::MQTT).not_to receive(:connect)
      expect(described_class.send(:mesh_connect, env: env)).to eq(:serial_obj)
      expect(PWN.const_get(:MeshTransport)).to eq(:serial)
    ensure
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
    end

    it 'connects send_text subscribe and disconnect through the configured Meshtastic module' do
      require 'meshtastic'
      env = {
        transport: 'serial',
        serial: { port: '/dev/ttyUSB0', baud: 115_200, bits: 8, stop: 1, parity: :none }
      }
      expect(Meshtastic::Serial).to receive(:connect).with(
        hash_including(block_dev: '/dev/ttyUSB0', baud: 115_200, data_bits: 8, stop_bits: 1, parity: :none)
      ).and_return(:serial_obj)
      expect(Meshtastic::Serial).to receive(:wait_for_config).with(hash_including(serial_obj: :serial_obj)).and_return(:serial_obj)
      expect(described_class.send(:mesh_connect, env: env)).to eq(:serial_obj)

      expect(Meshtastic::Serial).to receive(:send_text).with(
        hash_including(serial_obj: :serial_obj, text: 'hi', to: '!ffffffff')
      )
      described_class.send(:mesh_send_text, env: env, obj: :serial_obj, text: 'hi', from: '!abcd', channel: 8, psks: {}, to: '!ffffffff')

      expect(Meshtastic::Serial).to receive(:subscribe).with(
        hash_including(serial_obj: :serial_obj)
      )
      described_class.send(:mesh_subscribe, env: env, obj: :serial_obj, psks: {}, on_message: proc {})

      expect(Meshtastic::Serial).to receive(:disconnect).with(hash_including(serial_obj: :serial_obj))
      described_class.send(:mesh_disconnect, env: env, obj: :serial_obj)
    end

    it 'wires pwn-mesh TX/RX to mesh_connect mesh_subscribe mesh_send_text mesh_disconnect' do
      src = command_src
      expect(src).to match(/mesh_connect/)
      expect(src).to match(/mesh_subscribe/)
      expect(src).to match(/mesh_send_text/)
      leave = File.read(described_class.method(:leave_special_mode!).source_location.first)
      expect(leave).to match(/mesh_disconnect/)
    end

    it 'passes bluetooth_obj to Bluetooth subscribe and send_text' do
      require 'meshtastic'
      env = { transport: 'bluetooth', bluetooth: { address: 'AA:BB:CC:DD:EE:FF' } }
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
      PWN.const_set(:MeshTransport, :bluetooth)
      expect(Meshtastic::Bluetooth).to receive(:send_text).with(
        hash_including(bluetooth_obj: :ble, text: 'hi', to: '!ffffffff')
      )
      described_class.send(:mesh_send_text, env: env, obj: :ble, text: 'hi', to: '!ffffffff', channel: 8)
      expect(Meshtastic::Bluetooth).to receive(:subscribe).with(
        hash_including(bluetooth_obj: :ble)
      )
      described_class.send(:mesh_subscribe, env: env, obj: :ble, psks: {}, on_message: proc {})
    ensure
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
    end

    it 'preserves multi-component MQTT broker paths' do
      expect(described_class.send(:mesh_mqtt_region, region: 'US/UT')).to eq('US/UT')
      expect(described_class.send(:mesh_mqtt_region, region: 'EU_868')).to eq('EU_868')
    end

    it 'receives a real protobuf envelope on the configured regional MQTT path' do
      require 'meshtastic'
      topic = 'msh/US/UT/2/e/LongFast/!11223344'
      packet = Meshtastic::MeshPacket.new(from: 0x11223344, to: 0xffffffff,
                                          decoded: Meshtastic::Data.new(portnum: :TEXT_MESSAGE_APP, payload: 'regional fixture'))
      frame = Struct.new(:topic, :payload).new(topic, Meshtastic::ServiceEnvelope.new(packet: packet).to_proto)
      broker = double('broker')
      filter = nil
      allow(broker).to receive(:subscribe) { |path, _qos| filter = path }
      allow(broker).to receive(:get_packet) { |&block| block.call(frame) if topic.start_with?(filter.delete_suffix('#')) }
      allow(broker).to receive(:disconnect)
      received = []
      described_class.send(:mesh_subscribe, env: { transport: 'mqtt' }, obj: broker,
                                            region: 'US/UT', topic: '2/e/LongFast/#', psks: { LongFast: 'AQ==' },
                                            on_message: proc { |msg| received << msg.dig(:packet, :decoded, :payload) })
      expect(received).to eq(['regional fixture'])
    end

    it 'uses the named device channel index instead of forcing slot zero' do
      require 'meshtastic'
      obj = { proto_data: [{ channel: { index: 3, settings: { name: 'LongFast' } } }] }
      env = { transport: 'serial', channel: { active: 'LongFast', LongFast: { channel_num: 99 } } }
      expect(Meshtastic::Serial).to receive(:send_text).with(hash_including(channel: 3))
      described_class.send(:mesh_send_text, env: env, obj: obj, channel: 99, text: 'slot three')
    end

    it 'sends LongFast on the device index for that name instead of assuming slot zero' do
      require 'meshtastic'
      obj = {
        proto_data: [
          { channel: { index: 0, settings: { name: '' } } },
          { channel: { index: 2, settings: { name: 'LongFast' } } }
        ]
      }
      env = {
        transport: 'serial',
        channel: { active: 'LongFast', LongFast: { psk: 'AQ==', channel_num: 8, topic: '2/e/LongFast/#' } }
      }
      expect(Meshtastic::Serial).to receive(:send_text).with(hash_including(channel: 2, text: 'hello LongFast'))
      described_class.send(:mesh_send_text, env: env, obj: obj, text: 'hello LongFast')
    end

    it 'sends LongFast on the last radio listing even when the firmware name is blank' do
      require 'meshtastic'
      obj = {
        proto_data: [
          { channel: { index: 0, settings: { name: '' }, role: :PRIMARY } },
          { channel: { index: 1, settings: { name: '' }, role: :SECONDARY } },
          { channel: { index: 2, settings: { name: '' }, role: :SECONDARY } }
        ]
      }
      env = {
        transport: 'serial',
        channel: { active: 'LongFast', LongFast: { psk: 'AQ==', channel_num: 8 } }
      }
      expect(Meshtastic::Serial).to receive(:send_text).with(hash_including(channel: 2, text: 'hello LongFast'))
      described_class.send(:mesh_send_text, env: env, obj: obj, text: 'hello LongFast')
    end

    it 'sends MQTT on a named channel without requiring a radio slot' do
      require 'meshtastic'
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
      PWN.const_set(:MeshTransport, :mqtt)
      env = {
        transport: 'mqtt',
        channel: { active: 'LongFast', LongFast: { psk: 'cHdu', region: 'US/UT', topic: '2/e/LongFast/#', channel_num: 99 } }
      }
      expect(Meshtastic::MQTT).to receive(:send_text).with(hash_including(text: 'hello LongFast', to: '!ffffffff'))
      described_class.send(:mesh_send_text, env: env, obj: :mqtt, text: 'hello LongFast', to: '!ffffffff')
    ensure
      PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
    end

    it 'paints outbound text into the conversation pane' do
      require 'meshtastic'
      win = double('rx', maxx: 80)
      allow(win).to receive(:attron)
      allow(win).to receive(:attroff)
      allow(win).to receive(:addstr)
      allow(win).to receive(:refresh)
      allow(Curses).to receive(:color_pair).and_return(0)
      %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState].each do |c|
        PWN.send(:remove_const, c) if PWN.const_defined?(c)
      end
      PWN.const_set(:MeshRxBodyWin, win)
      PWN.const_set(:MeshMutex, Mutex.new)
      PWN.const_set(:MeshColors, [1])
      PWN.const_set(:MeshLastColor, 1)
      PWN.const_set(:MeshRxState, {})
      allow(Meshtastic::MQTT).to receive(:send_text)
      described_class.send(
        :mesh_send_text,
        env: { transport: 'mqtt', channel: { active: 'LongFast', LongFast: { psk: 'AQ==', topic: '2/e/LongFast/#' } } },
        obj: :mqtt,
        from: '!aabbccdd',
        text: 'hello from me'
      )
      expect(win).to have_received(:addstr).with(a_string_including('hello from me'))
    ensure
      %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState MeshLastTx].each do |c|
        PWN.send(:remove_const, c) if PWN.const_defined?(c)
      end
    end

    it 'merges meshtastic menu changes into pwn.yaml like persist_ai_selection' do
      Dir.mktmpdir do |dir|
        yaml = File.join(dir, 'pwn.yaml')
        dec = "#{yaml}.decryptor"
        File.write(yaml, YAML.dump({ plugins: { meshtastic: { transport: 'mqtt', channel: { active: 'LongFast' } } } }))
        File.write(dec, YAML.dump({ key: 'k' * 32, iv: 'i' * 16 }))
        allow(PWN::Plugins::Vault).to receive(:decrypt)
        allow(PWN::Plugins::Vault).to receive(:encrypt)
        prev = PWN::Env[:driver_opts]
        PWN::Env[:driver_opts] = { pwn_env_path: yaml, pwn_dec_path: dec }
        described_class.persist_mesh_env(
          mesh: { transport: 'serial', channel: { active: 'LongFast' }, serial: { port: '/dev/ttyACM0' } }
        )
        cfg = YAML.load_file(yaml, symbolize_names: true)
        expect(cfg.dig(:plugins, :meshtastic, :transport).to_s).to eq('serial')
        expect(cfg.dig(:plugins, :meshtastic, :channel, :active).to_s).to eq('LongFast')
        expect(cfg.dig(:plugins, :meshtastic, :serial, :port)).to eq('/dev/ttyACM0')
      ensure
        PWN::Env[:driver_opts] = prev if defined?(prev)
      end
    end

    it 'runs a curses-owned console rather than a Reline echo worker' do
      src = command_src
      expect(src).to include('mesh_console_loop')
      expect(src).not_to include('cursor_pos = Reline.point')
      expect(src).not_to include('cursor_pos = Readline.point')
    end
  end

  describe 'pwn-mesh slash menus' do
    it 'handles the submitted slash command without reading an editor buffer' do
      described_class.add_hooks
      pi = double('pry', config: Pry::Config.new, input: Object.new)
      pi.config.pwn_mesh = true
      request = +"/status\n"
      expect(described_class).to receive(:mesh_ui_puts).with(hash_including(text: /active channel=LongFast/))
      Pry.config.hooks.exec_hook(:after_read, request, pi)
      expect(request).to eq('nil')
    end

    it 'accepts the newline string returned by curses getch' do
      keys = [Curses::KEY_DOWN, "\n", nil]
      expect(described_class.mesh_menu_pick(items: %w[LongFast PWN], getch: proc { keys.shift })).to eq('PWN')
    end

    it 'draws continuous Unicode borders without terminal alternate-character-set assumptions' do
      win = double('window', maxx: 12, maxy: 4)
      allow(win).to receive(:setpos)
      allow(win).to receive(:addstr)
      described_class.send(:mesh_box!, win: win)
      expect(win).to have_received(:addstr).with('╭──────────╮')
      expect(win).to have_received(:addstr).with('╰──────────╯')
      expect(win).to have_received(:addstr).with('│').exactly(4).times
    end

    it 'wraps complete incoming text instead of discarding the right-hand side' do
      expect(described_class.send(:mesh_wrap_text, text: 'abcdefghijk', width: 5)).to eq(%w[abcde fghij k])
    end

    it 'queues subscription errors for visible reporting on the curses thread' do
      events = Queue.new
      stub_const('PWN::MeshEvents', events)
      allow(described_class).to receive(:mesh_subscribe).and_raise(IOError, 'fixture disconnect')
      thread = described_class.send(:mesh_start_rx!, env: mesh_env, obj: :fixture)
      expect(thread.join(2)).to eq(thread)
      expect(events.pop[:text]).to include('RX failed: IOError: fixture disconnect')
    ensure
      PWN.send(:remove_const, :MeshSubThread) if PWN.const_defined?(:MeshSubThread)
    end

    it 'reads, submits and clears commands entirely through curses input' do
      pi = double('pry', config: Pry::Config.new)
      pi.config.pwn_mesh = true
      keys = '/status'.chars + ["\n", "\u0004"]
      renders = []
      allow(described_class).to receive(:mesh_draw_input) { |opts| renders << opts[:text].dup }
      expect(Reline).not_to receive(:line_buffer)
      expect(described_class).to receive(:mesh_submit).with(request: '/status', pry: pi)
      described_class.send(:mesh_console_loop, pry: pi, getch: proc { keys.shift })
      expect(renders).to include('/status')
      expect(renders.last).to eq('')
    end

    it 'selects the active MQTT topic and its actual channel name for encryption' do
      mesh_env[:channel][:active] = 'LongFast'
      mesh_env[:channel][:LongFast] = { topic: '2/e/LongFast/#', psk: 'AQ==', channel_num: 93 }
      expect(described_class.send(:mesh_active_psks, env: mesh_env)).to eq(LongFast: 'AQ==')
      mesh_env[:channel][:active] = 'LongFast'
      expect(described_class.send(:mesh_mqtt_topic, env: mesh_env, topic: '2/e/#')).to eq('2/e/LongFast/#')
    end

    it 'shows radio text from every device slot' do
      stub_const('PWN::MeshTransport', :serial)
      mesh_env[:channel][:LongFast][:radio_index] = 3
      expect(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
      described_class.send(:mesh_handle_rx, msg: { packet: { channel: 0, decoded: { portnum: 1, payload: 'other channel' } } })
    end

    let(:mesh_env) do
      {
        transport: 'mqtt',
        serial: { port: '/dev/ttyUSB0', baud: 115_200, bits: 8, stop: 1, parity: :none },
        bluetooth: { address: 'AA:BB:CC:DD:EE:FF' },
        tcp: { host: '127.0.0.1', port: 4403 },
        mqtt: { host: 'mqtt.meshtastic.org', port: 1883 },
        channel: {
          active: 'LongFast',
          LongFast: { psk: 'AQ==', region: 'US/UT', topic: '2/e/#', channel_num: 8 }
        }
      }
    end

    before do
      PWN::Env[:plugins] ||= {}
      @prev_mesh = PWN::Env[:plugins][:meshtastic]
      PWN::Env[:plugins][:meshtastic] = mesh_env
      allow(described_class).to receive(:persist_mesh_env).and_return(false)
    end

    after do
      PWN::Env[:plugins][:meshtastic] = @prev_mesh if PWN::Env[:plugins].is_a?(Hash)
    end

    it 'intercepts leading-slash pwn-mesh lines locally instead of mesh_send_text' do
      hook = File.read(described_class.method(:add_hooks).source_location.first)
      expect(hook).to match(/pwn_mesh_dispatch_slash!/)
      expect(described_class).to respond_to(:pwn_mesh_dispatch_slash!)
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/help', pry: :fixture)).to eq(true)
      expect(described_class.pwn_mesh_dispatch_slash!(request: 'hello mesh', pry: :fixture)).to eq(false)
    end

    it 'lists and switches named channels without sending them as mesh text' do
      listed = described_class.pwn_mesh_dispatch_slash!(request: '/channel list', pry: :fixture)
      expect(listed).to eq(true)
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/channel LongFast', pry: :fixture)).to eq(true)
      expect(PWN::Env[:plugins][:meshtastic][:channel][:active].to_s).to eq('LongFast')
    end

    it 'lists and switches mqtt serial bluetooth or tcp transports' do
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/transport list', pry: :fixture)).to eq(true)
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/transport serial', pry: :fixture)).to eq(true)
      expect(PWN::Env[:plugins][:meshtastic][:transport].to_s).to eq('serial')
    end

    it 'lists serial devices and applies /device to the active transport' do
      allow(Dir).to receive(:glob).and_return(['/dev/ttyUSB0', '/dev/ttyACM0'])
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/device list', pry: :fixture)).to eq(true)
      PWN::Env[:plugins][:meshtastic][:transport] = 'serial'
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/device /dev/ttyACM0', pry: :fixture)).to eq(true)
      expect(PWN::Env[:plugins][:meshtastic][:serial][:port]).to eq('/dev/ttyACM0')
    end

    it 'completes pwn-mesh slash commands including channel transport and device' do
      hits = described_class.pwn_mesh_complete(target: '/', line: '/')
      %w[/help /back /status /channel /transport /device].each do |cmd|
        expect(hits).to include(cmd)
      end
      hits = described_class.pwn_mesh_complete(target: 'li', line: '/channel li')
      expect(hits).to include('list')
      hits = described_class.pwn_mesh_complete(target: 'Lo', line: '/channel Lo')
      expect(hits).to include('LongFast')
      hits = described_class.pwn_mesh_complete(target: 'ser', line: '/transport ser')
      expect(hits).to include('serial')
      src = command_src
      expect(src).to match(/install_pwn_mesh_completer!/)
    end

    it 'paints slash hits in the mesh TX pane because curses hides the Reline dropdown' do
      expect(described_class).to respond_to(:pwn_mesh_menu_rows)
      expect(described_class.pwn_mesh_menu_rows(line: '/')).to include('/channel', '/transport', '/device')
      expect(described_class.pwn_mesh_menu_rows(line: '/ch')).to include('/channel')
      expect(described_class.pwn_mesh_menu_rows(line: 'hello mesh')).to eq([])
      installer = File.read(described_class.method(:install_pwn_mesh_completer!).source_location.first)
      expect(installer).to match(/Reline\.autocompletion = false/)
    end

    it 'autocompletes pwn-mesh commands in COMPOSE when the line starts with /' do
      win = double('tx', maxx: 80, maxy: 5)
      allow(win).to receive(:erase)
      allow(win).to receive(:setpos)
      allow(win).to receive(:addstr)
      allow(win).to receive(:attron).and_yield
      allow(win).to receive(:attroff)
      allow(win).to receive(:refresh)
      allow(Curses).to receive(:color_pair).and_return(0)
      stub_const('PWN::MeshTxWin', win)
      described_class.send(:mesh_draw_input, text: '/', cursor: 1)
      expect(win).to have_received(:addstr).with(a_string_including('/channel')).at_least(:once)
      expect(win).to have_received(:addstr).with(a_string_including('/msg')).at_least(:once)
      described_class.send(:mesh_draw_input, text: '/ch', cursor: 3)
      expect(win).to have_received(:addstr).with(a_string_including('/channel')).at_least(:once)
    end

    it 'drives channel transport and device lists with a curses menu not a Reline overlay' do
      expect(described_class).to respond_to(:mesh_menu_pick)
      keys = [Curses::KEY_DOWN, 10]
      n = 0
      choice = described_class.mesh_menu_pick(
        title: 'channel',
        items: %w[one two],
        current: 'one',
        getch: proc { keys.fetch(n).tap { n += 1 } }
      )
      expect(choice).to eq('two')
      allow(described_class).to receive(:mesh_menu_pick).and_return('LongFast')
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/channel', pry: :fixture)).to eq(true)
      expect(PWN::Env[:plugins][:meshtastic][:channel][:active].to_s).to eq('LongFast')
      src = command_src
      expect(src).to include('MeshMenuLock')
      expect(src).to include('keypad')
      expect(src).to match(/Curses::KEY_UP/)
    end

    it 'boxes mesh panes, clears submitted input, shows /status, and refreshes the TX prompt' do
      expect(described_class).to respond_to(:mesh_reset_input!)
      described_class.mesh_reset_input!(pry: :fixture)
      expect(PWN.const_get(:MeshTxBlank)).to eq(true)
      src = command_src
      expect(src).to match(/mesh_reset_input!/)
      expect(src).to include('MeshTxBlank')
      expect(src).to include('mesh_box!')
      expect(src).not_to include('rx_header_win = Curses::Window.new(rx_height')
      expect(src).to include('MeshTxEpoch')
      expect(src).to include('mesh_ui_puts')
      expect(src).not_to include('const_set(:MeshTransport, mesh_transport')
    end

    it 'yields TEXT_MESSAGE_APP when portnum is protobuf 1 and keeps every channel PSK' do
      src = command_src
      sub = src[/def (?:self\.)?mesh_subscribe\(opts = \{\}\)(.*?)def (?:self\.)?mesh_send_text/m, 1]
      expect(sub).not_to include("include: 'TEXT_MESSAGE_APP'")
      expect(src).to include('mesh_channel_psks')
      psks = described_class.send(:mesh_channel_psks, env: mesh_env)
      expect(psks).to include(LongFast: 'AQ==')
      expect(described_class.send(:mesh_text_app?, portnum: 1)).to eq(true)
      expect(described_class.send(:mesh_text_app?, portnum: :TEXT_MESSAGE_APP)).to eq(true)
      expect(described_class.send(:mesh_text_app?, portnum: :POSITION_APP)).to eq(false)
    end

    it 'paints integer-portnum text frames into the RX pane' do
      win = double('rx', maxx: 80)
      allow(win).to receive(:attron)
      allow(win).to receive(:attroff)
      allow(win).to receive(:addstr)
      allow(win).to receive(:refresh)
      allow(Curses).to receive(:color_pair).and_return(0)
      %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState MeshDispatchLock].each do |c|
        PWN.send(:remove_const, c) if PWN.const_defined?(c)
      end
      PWN.const_set(:MeshRxBodyWin, win)
      PWN.const_set(:MeshMutex, Mutex.new)
      PWN.const_set(:MeshColors, [1])
      PWN.const_set(:MeshLastColor, 1)
      PWN.const_set(:MeshRxState, {})
      described_class.send(
        :mesh_handle_rx,
        msg: {
          packet: {
            node_id_from: '!abc',
            node_id_to: '!ffffffff',
            decoded: { portnum: 1, payload: 'hello on channel' }
          }
        }
      )
      expect(win).to have_received(:addstr).at_least(:once)
    ensure
      %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState MeshDispatchLock].each do |c|
        PWN.send(:remove_const, c) if PWN.const_defined?(c)
      end
    end

    it 'toggle-dispatch-to-pwn-ai is off by default and replies on an encrypted shared channel' do
      expect(mesh_env[:dispatch_to_pwn_ai]).to be_falsey
      hits = described_class.pwn_mesh_complete(target: '/', line: '/')
      expect(hits).to include('/toggle-dispatch-to-pwn-ai')
      expect(described_class.pwn_mesh_dispatch_slash!(request: '/toggle-dispatch-to-pwn-ai', pry: :fixture)).to eq(true)
      expect(PWN::Env[:plugins][:meshtastic][:dispatch_to_pwn_ai]).to eq(true)
      mesh_env[:channel][:LongFast][:psk] = 'cHdu'
      mesh_env[:ai_whitelist] = ['LongFast']
      allow(PWN::AI::Agent::Loop).to receive(:run).and_return('ai says hi')
      allow(described_class).to receive(:mesh_send_text)
      allow(Thread).to receive(:new).and_yield
      described_class.send(
        :mesh_maybe_dispatch_to_pwn_ai,
        text: '@ai hello on channel',
        from: '!abc',
        to: '!ffffffff',
        channel_name: 'LongFast'
      )
      expect(PWN::AI::Agent::Loop).to have_received(:run).with(hash_including(request: 'hello on channel', nested: true))
      expect(described_class).to have_received(:mesh_send_text).with(hash_including(to: '!ffffffff', text: 'ai says hi'))
    end

    it 'paints local TX in green with self id and channel name or DM node id' do
      win = double('rx', maxx: 80)
      allow(win).to receive(:attron)
      allow(win).to receive(:attroff)
      allow(win).to receive(:addstr)
      allow(win).to receive(:refresh)
      allow(Curses).to receive(:color_pair).and_return(0)
      %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState MeshDispatchLock].each do |c|
        PWN.send(:remove_const, c) if PWN.const_defined?(c)
      end
      PWN.const_set(:MeshRxBodyWin, win)
      PWN.const_set(:MeshMutex, Mutex.new)
      PWN.const_set(:MeshColors, [1])
      PWN.const_set(:MeshLastColor, 1)
      PWN.const_set(:MeshRxState, {})
      described_class.send(
        :mesh_handle_rx,
        local: true,
        channel_name: 'LongFast',
        msg: {
          packet: {
            node_id_from: '!00000b0b',
            node_id_to: '!ffffffff',
            decoded: { portnum: 1, payload: 'hello on channel' }
          }
        }
      )
      expect(Curses).to have_received(:color_pair).with(23).at_least(:once)
      expect(win).to have_received(:addstr).with(a_string_matching(/!00000b0b \(ME\)/)).at_least(:once)
      expect(win).to have_received(:addstr).with(a_string_matching(/LongFast/)).at_least(:once)
      expect(win).not_to have_received(:addstr).with(a_string_matching(/you/))
      described_class.send(
        :mesh_handle_rx,
        local: true,
        msg: {
          packet: {
            node_id_from: '!00000b0b',
            node_id_to: '!aabbccdd',
            decoded: { portnum: 1, payload: 'hello in dm' }
          }
        }
      )
      expect(win).to have_received(:addstr).with(a_string_matching(/!aabbccdd/)).at_least(:once)
    ensure
      %i[MeshRxBodyWin MeshMutex MeshColors MeshLastColor MeshRxState MeshDispatchLock].each do |c|
        PWN.send(:remove_const, c) if PWN.const_defined?(c)
      end
    end
  end
end
