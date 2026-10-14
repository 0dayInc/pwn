# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'timeout'

describe PWN::AI::MCP::ComboNation do
  it 'rejects cyclic and overdeep arguments before stack exhaustion' do
    cycle = []
    cycle << cycle
    deep = {}
    10_000.times { deep = { nested: deep } }
    [cycle, deep].each do |value|
      expect { described_class.send(:stringify, value: value) }.to raise_error(JSON::NestingError)
    end
  end

  def start_fake_server(handler)
    from_client_r, from_client_w = IO.pipe
    to_client_r, to_client_w = IO.pipe
    [from_client_r, from_client_w, to_client_r, to_client_w].each(&:binmode)
    thread = Thread.new do
      Thread.current.report_on_exception = false
      from_client_r.each_line do |line|
        request = JSON.parse(line)
        response = handler.call(request)
        next if response.nil?

        to_client_w.write("#{JSON.generate(response)}\n")
        to_client_w.flush
      end
    rescue IOError, Errno::EPIPE
      nil
    end
    { reader: to_client_r, writer: from_client_w, thread: thread,
      close: [from_client_r, to_client_w] }
  end

  def connect_fake(handler)
    fake = start_fake_server(handler)
    session = described_class.connect(
      reader: fake[:reader],
      writer: fake[:writer],
      timeout: 2
    )
    [session, fake]
  end

  def handshake_handler(extra = nil)
    lambda do |request|
      method = request['method']
      id = request['id']
      case method
      when 'initialize'
        {
          'jsonrpc' => '2.0',
          'id' => id,
          'result' => {
            'protocolVersion' => '2024-11-05',
            'capabilities' => { 'tools' => {} },
            'serverInfo' => { 'name' => 'combo.nation', 'version' => '1.0.0' }
          }
        }
      when 'notifications/initialized'
        nil
      else
        extra ? extra.call(request) : { 'jsonrpc' => '2.0', 'id' => id, 'result' => {} }
      end
    end
  end

  after do
    described_class.disconnect(session: @session) if defined?(@session) && @session
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'negotiates MCP 2024-11-05, lists every combo.nation tool, and pings' do
    seen = []
    handler = handshake_handler(lambda do |request|
      seen << request['method']
      id = request['id']
      case request['method']
      when 'ping'
        { 'jsonrpc' => '2.0', 'id' => id, 'result' => {} }
      when 'tools/list'
        {
          'jsonrpc' => '2.0',
          'id' => id,
          'result' => {
            'tools' => described_class::TOOLS.map { |name| { 'name' => name, 'inputSchema' => { 'type' => 'object' } } }
          }
        }
      end
    end)
    @session, fake = connect_fake(handler)
    expect(@session[:server_info]).to include('name' => 'combo.nation')
    expect(@session[:protocol_version]).to eq('2024-11-05')
    expect(described_class.ping(session: @session)).to eq({})
    tools = described_class.list_tools(session: @session)
    expect(tools.map { |tool| tool['name'] }).to eq(described_class::TOOLS)
    described_class.disconnect(session: @session)
    @session = nil
    fake[:thread].join(2)
    expect(seen).to include('ping', 'tools/list')
  end

  it 'preserves string menu IDs such as 5.10 and parses tool JSON payloads' do
    handler = handshake_handler(lambda do |request|
      id = request['id']
      params = request['params']
      expect(request['method']).to eq('tools/call')
      expect(params['name']).to eq('menu_guess')
      expect(params['arguments']['option']).to eq('5.10')
      expect(params['arguments']['option']).not_to be_a(Float)
      {
        'jsonrpc' => '2.0',
        'id' => id,
        'result' => {
          'content' => [{ 'type' => 'text', 'text' => JSON.generate('title' => 'Guess Menu', 'option' => '5.10') }],
          'isError' => false
        }
      }
    end)
    @session, = connect_fake(handler)
    result = described_class.menu_guess(session: @session, option: '5.10')
    expect(result[:is_error]).to eq(false)
    expect(result[:parsed]).to include('title' => 'Guess Menu', 'option' => '5.10')
  end

  it 'wraps every application tool and surfaces protocol and tool errors' do
    calls = []
    handler = handshake_handler(lambda do |request|
      id = request['id']
      params = request.fetch('params', {})
      calls << [params['name'], params['arguments']]
      case params['name']
      when 'hardware_connect'
        {
          'jsonrpc' => '2.0',
          'id' => id,
          'result' => {
            'content' => [{ 'type' => 'text', 'text' => 'Hardware disabled: restart with --mcp --mcp-allow-hardware' }],
            'isError' => true
          }
        }
      when 'missing'
        { 'jsonrpc' => '2.0', 'id' => id, 'error' => { 'code' => -32_602, 'message' => 'Unknown tool' } }
      else
        {
          'jsonrpc' => '2.0',
          'id' => id,
          'result' => {
            'content' => [{ 'type' => 'text', 'text' => JSON.generate('ok' => true, 'name' => params['name'], 'arguments' => params['arguments']) }],
            'isError' => false
          }
        }
      end
    end)
    @session, = connect_fake(handler)
    expect(described_class.menu_catalog(session: @session)[:parsed]['name']).to eq('menu_catalog')
    expect(described_class.menu_main(session: @session, option: '0.3')[:parsed]['arguments']).to include('option' => '0.3')
    expect(described_class.menu_dial_calibration(session: @session, option: '3.99')[:parsed]['arguments']).to include('option' => '3.99')
    expect(described_class.operation_status(session: @session)[:parsed]['name']).to eq('operation_status')
    expect(described_class.operation_answer(session: @session, prompt_id: 1, value: true)[:parsed]['arguments']).to include('prompt_id' => 1, 'value' => true)
    expect(described_class.operation_cancel(session: @session)[:parsed]['name']).to eq('operation_cancel')
    expect(described_class.servo_pause(session: @session, action: 'pause')[:parsed]['arguments']).to include('action' => 'pause')
    hardware = described_class.hardware_connect(session: @session)
    expect(hardware[:is_error]).to eq(true)
    expect(hardware[:text]).to match(/Hardware disabled/)
    expect { described_class.call_tool(session: @session, name: 'missing') }.to raise_error(IOError, /Unknown tool/)
    expect(calls.map(&:first)).to include(*%w[menu_catalog menu_main menu_dial_calibration operation_status operation_answer operation_cancel servo_pause hardware_connect missing])
  end

  it 'builds discovery argv without hardware and opt-in hardware argv without launching a motor' do
    expect(described_class.argv).to eq(['/opt/combo.nation/combo.nation', '--mcp'])
    expect(described_class.argv(allow_hardware: true, command: '/tmp/combo.nation')).to eq(
      ['/tmp/combo.nation', '--mcp', '--mcp-allow-hardware']
    )
  end

  it 'polls operation_status until a terminal state without treating the first reply as completion' do
    states = %w[running waiting_input completed]
    handler = handshake_handler(lambda do |request|
      id = request['id']
      state = states.shift
      {
        'jsonrpc' => '2.0',
        'id' => id,
        'result' => {
          'content' => [{ 'type' => 'text', 'text' => JSON.generate('state' => state, 'prompt' => state == 'waiting_input' ? { 'id' => 2, 'kind' => 'ack' } : nil) }],
          'isError' => false
        }
      }
    end)
    @session, = connect_fake(handler)
    result = described_class.poll_until(session: @session, states: %w[completed failed cancelled], interval: 0)
    expect(result[:parsed]['state']).to eq('completed')
    expect(states).to be_empty
  end

  it 'executes the real combo.nation stdio server without enabling hardware', :combo_nation_mcp do
    binary = '/opt/combo.nation/combo.nation'
    expect(File.executable?(binary)).to eq(true), 'PWN_TEST_COMBO_NATION_MCP=1 requires /opt/combo.nation/combo.nation'
    @session = described_class.connect(command: binary, timeout: 5)
    tools = described_class.list_tools(session: @session)
    expect(tools.map { |tool| tool['name'] }).to match_array(described_class::TOOLS)
    catalog = described_class.menu_catalog(session: @session)
    expect(catalog[:is_error]).to eq(false)
    expect(catalog[:parsed]['guess']['values'].map { |item| item['value'] }).to include('5.10')
    submenu = described_class.menu_main(session: @session, option: '0.3')
    expect(submenu[:parsed]['title']).to eq('Dial Calibration Menu')
    denied = described_class.hardware_connect(session: @session)
    expect(denied[:is_error]).to eq(true)
    status = described_class.operation_status(session: @session)
    expect(status[:parsed]).to include('hardware_enabled' => false, 'hardware_connected' => false)
    expect(described_class.ping(session: @session)).to eq({})
  end
end
