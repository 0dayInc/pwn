# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe PWN::AI::MCP do
  it 'rejects cyclic and overdeep arguments before stack exhaustion' do
    cycle = []
    cycle << cycle
    deep = {}
    10_000.times { deep = { nested: deep } }
    [cycle, deep].each do |value|
      expect { described_class.send(:stringify, value: value) }.to raise_error(JSON::NestingError)
    end
  end

  def start_fake_server
    from_client_r, from_client_w = IO.pipe
    to_client_r, to_client_w = IO.pipe
    [from_client_r, from_client_w, to_client_r, to_client_w].each(&:binmode)
    thread = Thread.new do
      Thread.current.report_on_exception = false
      from_client_r.each_line do |line|
        request = JSON.parse(line)
        id = request['id']
        response =
          case request['method']
          when 'initialize'
            { 'jsonrpc' => '2.0', 'id' => id, 'result' => { 'protocolVersion' => '2024-11-05', 'serverInfo' => { 'name' => 'combo.nation', 'version' => '1.0.0' } } }
          when 'notifications/initialized'
            nil
          when 'tools/list'
            { 'jsonrpc' => '2.0', 'id' => id, 'result' => { 'tools' => [{ 'name' => 'menu_catalog' }] } }
          when 'tools/call'
            name = request.dig('params', 'name')
            args = request.dig('params', 'arguments')
            { 'jsonrpc' => '2.0', 'id' => id, 'result' => { 'content' => [{ 'type' => 'text', 'text' => JSON.generate('name' => name, 'arguments' => args) }], 'isError' => false } }
          else
            { 'jsonrpc' => '2.0', 'id' => id, 'result' => {} }
          end
        next if response.nil?

        to_client_w.write("#{JSON.generate(response)}\n")
        to_client_w.flush
      end
    rescue IOError, Errno::EPIPE
      nil
    end
    { reader: to_client_r, writer: from_client_w, thread: thread }
  end

  after do
    described_class.reset!
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'autoloads the combo.nation client' do
    expect(described_class::ComboNation).to eq(PWN::AI::MCP::ComboNation)
  end

  it 'lists PWN::AI::MCP::* backends that speak connect/list_tools/call_tool' do
    names = described_class.backends.map { |row| row[:name] }
    expect(names).to include('combo_nation')
    combo = described_class.backends.find { |row| row[:name] == 'combo_nation' }
    expect(combo[:constant]).to eq('PWN::AI::MCP::ComboNation')
    expect(combo[:tools]).to include('menu_catalog', 'menu_guess')
  end

  it 'connects a named backend, persists the session, and calls tools without Ruby glue' do
    fake = start_fake_server
    row = described_class.connect(backend: 'combo_nation', reader: fake[:reader], writer: fake[:writer], timeout: 2)
    expect(row[:backend]).to eq('combo_nation')
    expect(row[:session_id]).to eq('combo_nation')
    tools = described_class.list_tools(backend: 'combo_nation')
    expect(tools[:tools].map { |tool| tool['name'] }).to eq(['menu_catalog'])
    called = described_class.call_tool(backend: 'combo_nation', name: 'menu_guess', arguments: { option: '5.10' })
    expect(called[:parsed]).to include('name' => 'menu_guess')
    expect(called[:parsed]['arguments']).to include('option' => '5.10')
    described_class.disconnect(backend: 'combo_nation')
    fake[:thread].join(2)
  end

  it 'auto-connects on invoke call_tool and never enables hardware by default' do
    fake = start_fake_server
    result = described_class.invoke(action: 'call_tool', backend: 'combo_nation', name: 'menu_catalog', reader: fake[:reader], writer: fake[:writer], timeout: 2)
    expect(result[:backend]).to eq('combo_nation')
    expect(result[:parsed]['name']).to eq('menu_catalog')
    expect(result[:allow_hardware]).to eq(false)
    described_class.disconnect(session_id: result[:session_id])
    fake[:thread].join(2)
  end

  it 'selects a non-ComboNation backend for later calls' do
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
    described_class.const_set(:Probe, probe)
    described_class.reset!
    expect(described_class.use(backend: 'probe')).to include(backend: 'probe')
    expect(described_class.current).to eq('probe')
    result = described_class.invoke(action: 'call_tool', name: 'echo', arguments: { 'msg' => 'hi' })
    expect(result[:backend]).to eq('probe')
    expect(result[:parsed]).to include('name' => 'echo', 'arguments' => { 'msg' => 'hi' })
    expect(result[:parsed]['name']).not_to eq('menu_catalog')
  ensure
    described_class.send(:remove_const, :Probe) if described_class.const_defined?(:Probe, false)
    described_class.reset!
  end
end
