# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'
require 'timeout'

describe PWN::Plugins::REPL, 'explicit mesh channel identity' do
  let(:env) do
    { transport: 'serial', mqtt: { host: 'offline.invalid', region: 'US/CA' },
      dispatch_to_pwn_ai: true, ai_whitelist: ['LongFast'],
      channel: { active: 'LongFast', LongFast: { radio_index: 0, channel_num: 8, psk: Base64.strict_encode64('x' * 32), region: 'US/CA', topic: '2/e/LongFast/#' } } }
  end
  let(:radio) { { my_node_num: 0xaabbccdd, proto_data: [], rx_mutex: Mutex.new } }
  let(:broker) { double('offline broker', disconnect: nil, subscribe: nil) }
  let(:ready) { Queue.new }
  let(:win) { double('conversation', maxx: 200, attron: nil, attroff: nil, addstr: nil, refresh: nil) }
  let(:packet) { { id: 123, from: 0xbbccddee, to: 0xffffffff, decoded: { portnum: :TEXT_MESSAGE_APP, payload: '@ai question' } } }

  before do
    allow(described_class).to receive(:mesh_ai_session).and_return(id: '20260101_000000_aabbccdd', lease: nil)
    stub_const('PWN::MeshTransport', :serial)
    stub_const('PWN::MeshObj', radio)
    stub_const('PWN::MeshReceivers', [])
    stub_const('PWN::MeshRxState', {})
    stub_const('PWN::MeshEvents', SizedQueue.new(1000))
    stub_const('PWN::MeshLastTx', nil)
    stub_const('PWN::MeshLastChannel', nil)
    stub_const('PWN::MeshLastDm', nil)
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxBodyWin', win)
    allow(Curses).to receive(:color_pair) { |color| color }
    allow(described_class).to receive(:mesh_env_hash).and_return(env)
    allow(described_class).to receive(:mesh_ui_puts)
    allow(described_class).to receive(:mesh_wait_tx_slot).and_return(:ok)
    allow(described_class).to receive(:mesh_connect_one).with(hash_including(transport: :mqtt)).and_return(broker)
    allow(described_class).to receive(:mesh_subscribe) do |opts|
      ready << opts
      sleep
    end
    [Meshtastic::Serial, Meshtastic::Bluetooth, Meshtastic::TCP].each do |backend|
      allow(backend).to receive(:send_to_radio)
    end
  end

  after do
    described_class.send(:mesh_stop_receivers!)
    PWN.send(:remove_const, :MeshSubThread) if PWN.const_defined?(:MeshSubThread)
    PWN.send(:remove_const, :MeshDispatchLock) if PWN.const_defined?(:MeshDispatchLock)
  end

  it 'does not infer a radio channel name from an ambiguous shared PSK' do
    env[:channel][:LongFast][:psk] = Base64.strict_encode64("\x99".b * 32)
    env[:channel][:Other] = env[:channel][:LongFast].except(:radio_index)
    env[:channel][:LongFast].delete(:radio_index)
    radio[:proto_data] = [{ channel: { index: 0, role: :PRIMARY, settings: { psk: "\x99".b * 32 } } }]
    expect(described_class.send(:mesh_channel_name_for_index, env: env, obj: radio, index: 0)).to eq('')
    expect(described_class.send(:mesh_whitelist_name_for_index, env: env, obj: radio, index: 0)).to eq('')
    env[:channel][:LongFast][:radio_index] = 0
    expect(described_class.send(:mesh_channel_name_for_index, env: env, obj: radio, index: 0)).to eq('LongFast')
  end

  %i[serial mqtt].each do |first|
    it "replies on the exact shared-key channel once when #{first} arrives first" do
      env[:channel][:Other] = env[:channel][:LongFast].merge(radio_index: 0, topic: '2/e/Other/#')
      env[:channel][:active] = 'Other'
      env[:channel][:LongFast][:radio_index] = 3
      radio[:proto_data] = [{ channel: { index: 3, role: :SECONDARY, settings: { name: 'LongFast' } } }]
      allow(Thread).to receive(:new) { |&block| block.call }
      allow(PWN::AI::Agent::Loop).to receive(:run).and_return('offline reply')
      sent = []
      allow(Meshtastic::Serial).to receive(:send_to_radio) { |args| sent << [:serial, Meshtastic::ToRadio.decode(args[:to_radio]).packet] }
      allow(broker).to receive(:publish) do |topic, bytes|
        envelope = Meshtastic::ServiceEnvelope.decode(bytes)
        expect(envelope.channel_id).to eq('LongFast')
        expect(topic).to include('/US/CA/2/e/LongFast/')
        sent << [:mqtt, envelope.packet]
      end
      rx_radio = Meshtastic::FromRadio.decode(Meshtastic::FromRadio.new(packet: packet.merge(channel: 3)).to_proto).to_h
      rx_mqtt = Meshtastic::ServiceEnvelope.decode(Meshtastic::ServiceEnvelope.new(channel_id: 'LongFast', packet: packet.merge(channel: 8)).to_proto).to_h
      [first, first == :serial ? :mqtt : :serial].each do |kind|
        msg = kind == :serial ? rx_radio : rx_mqtt.merge(topic: 'msh/US/CA/2/e/LongFast/!bbccddee')
        described_class.send(:mesh_handle_rx, env: env, obj: kind == :serial ? radio : broker, msg: msg.merge(mesh_transport: kind))
      end
      expect(PWN::AI::Agent::Loop).to have_received(:run).once
      expect(sent.size).to eq(1)
      expect(sent.first.first).to eq(first)
      expect(sent.first.last.channel).to eq(3) if first == :serial
      expect(sent.first.last.to).to eq(0xffffffff)
    end
  end

  it 'selects the exact MQTT channel with shared PSKs for every automatic reply chunk' do
    env[:channel] = { active: 'Other', Other: env[:channel][:LongFast].merge(topic: '2/e/Other/#'), LongFast: env[:channel][:LongFast] }
    env[:channel][:LongFast].delete(:channel_num)
    allow(Thread).to receive(:new) { |&block| block.call }
    allow(described_class).to receive(:mesh_ui_puts) { |args| raise args[:text] if args[:text].start_with?('TX failed:') }
    reply = 'offline answer ' * 60
    allow(PWN::AI::Agent::Loop).to receive(:run).and_return(reply)
    sends = []
    allow(broker).to receive(:publish) { |topic, bytes| sends << [topic, Meshtastic::ServiceEnvelope.decode(bytes)] }
    described_class.send(:mesh_maybe_dispatch_to_pwn_ai, env: env, obj: broker, transport: :mqtt,
                                                         text: '@ai question', from: '!bbccddee', to: '!ffffffff', channel_name: 'LongFast')
    expect(described_class).not_to have_received(:mesh_ui_puts).with(hash_including(text: a_string_including('TX failed:')))
    chunks = described_class.send(:mesh_text_chunks, text: reply)
    expect(sends.size).to eq(chunks.size)
    sends.zip(chunks).each do |(topic, envelope), chunk|
      expect(topic).to include('/US/CA/2/e/LongFast/')
      expect(envelope.channel_id).to eq('LongFast')
      expect(envelope.packet.channel).to eq(('LongFast'.bytes + ('x' * 32).bytes).reduce(0, :^))
      expect(envelope.packet.encrypted).not_to be_empty
      message = envelope.packet.to_h
      Meshtastic::MeshInterface.new.decrypt_packet(message: message, psks: { LongFast: env[:channel][:LongFast][:psk] }, source: :mqtt, channel: 'LongFast')
      expect(message.dig(:decoded, :payload)).to eq(chunk)
    end
  end

  it 'uses the same explicit channel selection for manual MQTT compose' do
    stub_const('PWN::MeshTransport', :mqtt)
    env[:channel] = { active: 'LongFast', Other: env[:channel][:LongFast].merge(topic: '2/e/Other/#'), LongFast: env[:channel][:LongFast] }
    expect(broker).to receive(:publish) do |topic, bytes|
      expect(topic).to include('/US/CA/2/e/LongFast/')
      expect(Meshtastic::ServiceEnvelope.decode(bytes).channel_id).to eq('LongFast')
    end
    described_class.send(:mesh_compose_send, env: env, obj: broker, text: 'manual reply')
  end

  it 'does not publish using another key when the selected MQTT name has no PSK' do
    expect(broker).not_to receive(:publish)
    expect do
      described_class.send(:mesh_send_text, env: env, obj: broker, transport: :mqtt, from: '!aabbccdd',
                                            channel_name: 'Other', topic: '2/e/Other/#', text: 'must not send')
    end.to raise_error(ArgumentError, 'No PSK for selected channel_id')
  end
end
