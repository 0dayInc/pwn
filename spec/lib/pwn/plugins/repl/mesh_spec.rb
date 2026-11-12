# frozen_string_literal: true

require 'spec_helper'

describe 'radio configuration handshake cleanup' do
  %i[serial bluetooth tcp].each do |kind|
    it "closes an opened #{kind} connection when configuration handshake fails" do
      transport = Module.new
      stub_const("Meshtastic::#{kind == :tcp ? 'TCP' : kind.to_s.capitalize}", transport)
      connection = { fixture: kind }
      allow(transport).to receive(:connect).and_return(connection)
      allow(transport).to receive(:wait_for_config).and_raise(IOError, 'fixture handshake failure')
      expect(transport).to receive(:disconnect).with({ "#{kind}_obj": connection })
      expect { PWN::Plugins::REPL.send(:mesh_connect_one, env: {}, transport: kind) }.to raise_error(IOError, 'fixture handshake failure')
    end
  end
end

describe 'auto-selected mesh device editing' do
  it 'updates the connected serial device without overwriting MQTT settings' do
    repl = PWN::Plugins::REPL
    stub_const('PWN::MeshTransport', :serial)
    env = { transport: :auto, serial: { port: '/dev/fixture-old' }, mqtt: { host: 'broker.example.test', port: 1883 } }
    allow(repl).to receive(:persist_mesh_env).and_return(true)
    allow(repl).to receive(:mesh_reconnect!).and_return(:reconnected)
    allow(repl).to receive(:mesh_ui_puts)
    repl.send(:pwn_mesh_run_device, env: env, args: ['/dev/fixture-new'])
    expect(env[:serial][:port]).to eq('/dev/fixture-new')
    expect(env[:mqtt]).to eq(host: 'broker.example.test', port: 1883)
    expect(env[:transport]).to eq(:auto)
  end
end

describe 'mesh conversation identity after eviction' do
  it 'retains distinct selectable message identities past the display limit' do
    repl = PWN::Plugins::REPL
    window = double('offline conversation', maxx: 100, attron: nil, attroff: nil, addstr: nil, refresh: nil)
    stub_const('PWN::MeshRxBodyWin', window)
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxState', {})
    allow(Curses).to receive(:color_pair).and_return(0)
    allow(repl).to receive(:mesh_paint_details)
    allow(repl).to receive(:mesh_ui_puts) { |opts| raise opts[:text] }
    obj = { my_node_num: 0xaabbccdd, proto_data: [] }
    205.times do |index|
      packet = { id: index + 1, from: 0xaabbccdd, to: 0xffffffff, decoded: { portnum: 1, payload: "fixture #{index}" } }
      repl.send(:mesh_handle_rx, local: true, obj: obj, env: {}, transport: :serial, channel_name: 'LongFast', msg: { packet: packet })
    end
    rows = PWN::MeshRxState[:detail_rows]
    expect(rows.size).to eq(200)
    expect(rows.map { |row| row[:index] }.uniq.size).to eq(rows.size)
    repl.send(:mesh_select_conversation?, key: :up)
    expect(repl.send(:mesh_highlighted_message)).to eq(rows[-2])
  end
end

describe PWN::Plugins::REPL::Mesh do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::REPL::Mesh
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::REPL::Mesh
    expect(help_response).to respond_to :help
  end

  it 'registers the pwn-mesh Pry command' do
    expect(described_class).to respond_to :add_commands
    described_class.add_commands
    expect(Pry::Commands.find_command('pwn-mesh')).not_to be_nil
  end
end
