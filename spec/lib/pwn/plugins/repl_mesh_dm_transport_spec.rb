# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

describe PWN::Plugins::REPL, 'mesh DM transport replay' do
  it 'encodes /msg on the active slot and paints a decoded receiver packet through Serial.subscribe' do
    env = { transport: 'serial', channel: { active: 'LongFast', LongFast: { radio_index: 1, psk: 'AQ==' } } }
    sender = { my_node_num: 0xaabbccdd, proto_data: [{ node_info: { num: 0xbbccddee, user: { public_key: 'b' * 32 } } }] }
    stub_const('PWN::MeshPendingDm', nil)
    receiver = { my_node_num: 0xbbccddee, from_radio_queue: Queue.new }
    stub_const('PWN::MeshTransport', :serial)
    stub_const('PWN::MeshObj', sender)
    stub_const('PWN::MeshLastChannel', '')
    stub_const('PWN::MeshLastTx', nil)
    stub_const('PWN::MeshLastDm', nil)
    allow(described_class).to receive(:mesh_env_hash).and_return(env)
    packet = nil
    allow(Meshtastic::Serial).to receive(:send_to_radio) do |opts|
      packet = Meshtastic::ToRadio.decode(opts[:to_radio]).packet
    end

    described_class.pwn_mesh_dispatch_slash!(request: '/msg !bbccddee hello receiver', env: env, pry: :fixture)
    expect(packet.to).to eq(receiver[:my_node_num])
    expect(packet.channel).to eq(1)
    expect(packet.decoded.payload).to eq('hello receiver')

    # Replay the firmware's decoded FromRadio boundary, not RF delivery.
    receiver[:from_radio_queue] << Meshtastic::FromRadio.decode(Meshtastic::FromRadio.new(packet: packet).to_proto)
    receiver[:from_radio_queue].close
    PWN.send(:remove_const, :MeshObj)
    PWN.const_set(:MeshObj, receiver)
    PWN.send(:remove_const, :MeshLastTx)
    PWN.const_set(:MeshLastTx, nil)
    win = double('conversation', maxx: 60, attron: nil, attroff: nil, addstr: nil, refresh: nil)
    stub_const('PWN::MeshRxBodyWin', win)
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxState', {})
    allow(Curses).to receive(:color_pair).and_return(0)

    described_class.send(
      :mesh_subscribe,
      env: env, obj: receiver, psks: {},
      on_message: proc { |msg| described_class.send(:mesh_handle_rx, msg: msg) }
    )

    expect(win).to have_received(:addstr).with(" hello receiver\n")
    expect(win).to have_received(:addstr).with(a_string_including('!aabbccdd', '!bbccddee (ME)'))
  end
end
