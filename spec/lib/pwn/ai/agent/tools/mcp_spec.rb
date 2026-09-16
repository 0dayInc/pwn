# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe 'PWN::AI::Agent::Tools mcp' do
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
            { 'jsonrpc' => '2.0', 'id' => id, 'result' => { 'protocolVersion' => '2024-11-05', 'serverInfo' => { 'name' => 'combo.nation' } } }
          when 'notifications/initialized'
            nil
          when 'tools/list'
            { 'jsonrpc' => '2.0', 'id' => id, 'result' => { 'tools' => PWN::AI::MCP::ComboNation::TOOLS.map { |name| { 'name' => name } } } }
          when 'tools/call'
            { 'jsonrpc' => '2.0', 'id' => id, 'result' => { 'content' => [{ 'type' => 'text', 'text' => JSON.generate('ok' => true, 'name' => request.dig('params', 'name'), 'arguments' => request.dig('params', 'arguments')) }], 'isError' => false } }
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

  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/mcp.rb'
  end

  after do
    PWN::AI::MCP.reset!
  end

  it 'registers the mcp tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'mcp')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'mcp').toolset).to eq('mcp')
  end

  it 'dispatches the broker advertised for a combo.nation prompt and preserves menu IDs across calls' do
    registry = PWN::AI::Agent::Registry
    tools = registry.definitions(core_only: true, relevance: 'Inspect combo.nation menus')
    schema = tools.find { |tool| tool.dig(:function, :name) == 'mcp' }
    expect(schema).not_to be_nil
    fake = start_fake_server
    # Only replace process spawning; exercise the real protocol client, broker,
    # schema validation and Dispatch with JSON arguments as returned by a model.
    allow(PWN::AI::MCP::ComboNation).to receive(:connect).and_wrap_original do |method, opts|
      expect(opts[:allow_hardware]).not_to eq(true)
      method.call(opts.merge(reader: fake[:reader], writer: fake[:writer], timeout: 2))
    end
    calls = [
      { action: 'list_tools', backend: 'combo_nation' },
      { action: 'call_tool', backend: 'combo_nation', name: 'menu_guess', arguments: { option: '5.10' } }
    ]
    results = calls.map do |args|
      JSON.parse(PWN::AI::Agent::Dispatch.call(
                   scope_policy: { enabled: false },
                   tool_call: { id: 'mcp-test', type: 'function', function: { name: schema.dig(:function, :name), arguments: JSON.generate(args) } }
                 ))
    end
    expect(results.first.dig('result', 'tools').map { |tool| tool['name'] }).to include('menu_catalog')
    expect(results.last.dig('result', 'parsed', 'arguments')).to eq('option' => '5.10')
    expect(results.last.dig('result', 'allow_hardware')).to eq(false)
    expect(PWN::AI::MCP::ComboNation).to have_received(:connect).once
  ensure
    PWN::AI::MCP.reset!
    fake[:thread].join(2) if fake
  end

  it 'lists MCP backends and drives combo.nation tools through Dispatch-shaped args' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'mcp')
    listed = entry.handler.call(action: 'backends')
    expect(listed[:backends].map { |row| row[:name] }).to include('combo_nation')

    fake = start_fake_server
    connected = entry.handler.call(action: 'connect', backend: 'combo_nation', reader: fake[:reader], writer: fake[:writer], timeout: 2)
    expect(connected[:session_id]).to eq('combo_nation')
    tools = entry.handler.call(action: 'list_tools', backend: 'combo_nation')
    expect(tools[:tools].map { |tool| tool['name'] }).to include('menu_catalog', 'operation_status')
    catalog = entry.handler.call(action: 'call_tool', backend: 'combo_nation', name: 'menu_main', arguments: { 'option' => '0.3' })
    expect(catalog[:parsed]['name']).to eq('menu_main')
    expect(catalog[:parsed]['arguments']).to include('option' => '0.3')
    entry.handler.call(action: 'disconnect', backend: 'combo_nation')
    fake[:thread].join(2)
  end
end
