# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'
require 'timeout'

describe PWN::Plugins::REPL, 'additive MQTT receive ownership' do
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

  def subscriptions(count)
    Timeout.timeout(3) { Array.new(count) { ready.pop } }
  end

  %i[serial bluetooth tcp].each do |kind|
    it "adds exactly one MQTT receiver alongside #{kind}, without changing primary" do
      stub_const('PWN::MeshTransport', kind)
      described_class.send(:mesh_start_rx!, env: env, obj: radio)
      subs = subscriptions(2)
      expect(subs.map { |sub| sub[:transport] }).to contain_exactly(kind, :mqtt)
      expect(subs.find { |sub| sub[:transport] == :mqtt }[:obj]).to equal(broker)
      expect(PWN::MeshObj).to equal(radio)
      expect(PWN::MeshTransport).to eq(kind)
      expect(described_class).to have_received(:mesh_connect_one).once
      expect(broker).not_to respond_to(:send_to_radio)
    end

    [nil, {}].each do |config|
      it "does not connect extra MQTT for #{kind} with #{config.inspect} config" do
        stub_const('PWN::MeshTransport', kind)
        env[:mqtt] = config
        described_class.send(:mesh_start_rx!, env: env, obj: radio)
        expect(subscriptions(1).first[:transport]).to eq(kind)
        expect(PWN::MeshReceivers.size).to eq(1)
        expect(described_class).not_to have_received(:mesh_connect_one)
      end
    end
  end

  it 'does not duplicate a primary MQTT subscription' do
    stub_const('PWN::MeshTransport', :mqtt)
    described_class.send(:mesh_start_rx!, env: env, obj: broker)
    expect(subscriptions(1).first[:obj]).to equal(broker)
    expect(PWN::MeshReceivers.size).to eq(1)
    expect(described_class).not_to have_received(:mesh_connect_one)
  end

  it 'reports a failed secondary connection while primary remains active' do
    allow(described_class).to receive(:mesh_connect_one).and_raise(IOError, 'offline failure')
    thread = described_class.send(:mesh_start_rx!, env: env, obj: radio)
    subscriptions(1)
    PWN::MeshReceivers.last[:thread].join(3)
    described_class.send(:mesh_drain_events)
    expect(thread).to be_alive
    expect(described_class).to have_received(:mesh_ui_puts).with(hash_including(text: a_string_including('mqtt RX failed', 'other connections continue')))
  end

  it 'drops old-generation queued callbacks and cleans up both workers on replacement' do
    described_class.send(:mesh_start_rx!, env: env, obj: radio)
    old_subs = subscriptions(2)
    old = PWN::MeshReceivers.dup
    old_subs.each { |sub| sub[:on_message].call(packet: packet) }
    described_class.send(:mesh_start_rx!, env: env, obj: radio)
    subscriptions(2)
    allow(described_class).to receive(:mesh_handle_rx)
    described_class.send(:mesh_drain_events)
    expect(described_class).not_to have_received(:mesh_handle_rx)
    expect(old).to all(include(active: false))
    expect(old.map { |record| record[:thread].alive? }).to eq([false, false])
    expect(broker).to have_received(:disconnect).once
  end

  %i[serial bluetooth tcp mqtt].each do |kind|
    it "sends one automatic reply through owning #{kind} after primary switches" do
      owner = kind == :mqtt ? broker : radio
      allow(Thread).to receive(:new) { |&block| block.call }
      allow(PWN::AI::Agent::Loop).to receive(:run) do
        stub_const('PWN::MeshTransport', kind == :mqtt ? :tcp : :mqtt)
        stub_const('PWN::MeshObj', {})
        'offline reply'
      end
      sends = []
      if kind == :mqtt
        allow(broker).to receive(:publish) { |_topic, bytes| sends << Meshtastic::ServiceEnvelope.decode(bytes).packet }
      else
        backend = kind == :bluetooth ? Meshtastic::Bluetooth : Meshtastic::Serial
        allow(backend).to receive(:send_to_radio) { |args| sends << Meshtastic::ToRadio.decode(args[:to_radio]).packet }
      end
      result = described_class.send(:mesh_maybe_dispatch_to_pwn_ai, env: env, obj: owner, transport: kind,
                                                                    text: '@ai question', from: '!bbccddee', to: '!ffffffff', channel_name: 'LongFast', radio: 0)
      expect(result).to eq(:dispatched)
      expect(sends.size).to eq(1)
      expect(sends.first.to).to eq(0xffffffff)
      expect(PWN::AI::Agent::Loop).to have_received(:run).once
    end
  end

  it 'fails closed for MQTT DM AI requests without invoking a provider or radio' do
    allow(PWN::AI::Agent::Loop).to receive(:run)
    result = described_class.send(:mesh_maybe_dispatch_to_pwn_ai, env: env, obj: broker, transport: :mqtt,
                                                                  text: '@ai question', from: '!bbccddee', to: '!00000b0b', channel_name: 'LongFast')
    expect(result).to eq(:skipped)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'cancels a completed AI reply when its originating generation closes' do
    record = { active: true }
    allow(Thread).to receive(:new) { |&block| block.call }
    allow(PWN::AI::Agent::Loop).to receive(:run) {
      record[:active] = false
      'reply'
    }
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(:mesh_maybe_dispatch_to_pwn_ai, env: env, obj: broker, transport: :mqtt, connection: record,
                                                         text: '@ai question', from: '!bbccddee', to: '!ffffffff', channel_name: 'LongFast')
    expect(described_class).not_to have_received(:mesh_send_text)
    expect(described_class).to have_received(:mesh_ui_puts).with(hash_including(text: a_string_including('Origin connection closed')))
  end

  %i[serial bluetooth tcp].each do |kind|
    it "deduplicates real #{kind} and MQTT codecs before AI, preserving first origin" do
      allow(described_class).to receive(:mesh_subscribe).and_call_original
      allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
      queue = Queue.new
      queue << Meshtastic::FromRadio.decode(Meshtastic::FromRadio.new(packet: packet).to_proto)
      queue.close
      radio[:from_radio_queue] = queue
      envelope = Meshtastic::ServiceEnvelope.new(packet: packet.merge(channel: 8)).to_proto
      allow(broker).to receive(:get_packet) do |&block|
        block.call(Struct.new(:topic, :payload).new('msh/US/CA/2/e/LongFast/!bbccddee', envelope))
      end
      [kind, :mqtt].each do |transport|
        obj = transport == :mqtt ? broker : radio
        described_class.send(:mesh_subscribe, env: env, obj: obj, transport: transport, psks: {},
                                              on_message: proc { |msg| described_class.send(:mesh_handle_rx, env: env, msg: msg) })
      end
      expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).once.with(hash_including(obj: radio, transport: kind, text: '@ai question'))
      expect(win).to have_received(:addstr).with(" @ai question\n").once
      expect(PWN::MeshRxState[:seen_packets].values.first[:via]).to eq([kind, :mqtt])
    end
  end

  it 'does not conflate different payloads, IDs, senders or network paths' do
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    variants = [packet, packet.merge(id: 124), packet.merge(from: 0xccddeeff), packet.merge(decoded: { portnum: 1, payload: '@ai other' })]
    variants.each { |item| described_class.send(:mesh_handle_rx, env: env, obj: broker, msg: { packet: item, mesh_transport: :mqtt, topic: 'msh/US/CA/2/e/LongFast/!bbccddee' }) }
    described_class.send(:mesh_handle_rx, env: env, obj: broker, msg: { packet: packet, mesh_transport: :mqtt, topic: 'msh/EU/2/e/LongFast/!bbccddee' })
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).exactly(5).times
  end

  it 'keeps MQTT first-arrival ownership when a radio duplicate follows' do
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    described_class.send(:mesh_handle_rx, env: env, obj: broker, msg: { packet: packet.merge(channel: 8), mesh_transport: :mqtt, topic: 'msh/US/CA/2/e/LongFast/!bbccddee' })
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet, mesh_transport: :serial })
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).once.with(hash_including(obj: broker, transport: :mqtt))
    expect(PWN::MeshRxState[:seen_packets].values.first[:via]).to eq(%i[mqtt serial])
  end

  it 'preserves manual primary selection and primary implicit reply targets during secondary RX' do
    stub_const('PWN::MeshLastDm', '!ddeeff00')
    stub_const('PWN::MeshLastChannel', 'LongFast')
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    described_class.send(:mesh_handle_rx, env: env, obj: broker, connection: { secondary: true },
                                          msg: { packet: packet.merge(to: 0xb0b), mesh_transport: :mqtt, topic: 'msh/US/CA/2/e/LongFast/!bbccddee' })
    expect(PWN::MeshLastDm).to eq('!ddeeff00')
    expect(PWN::MeshLastChannel).to eq('LongFast')
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(:pwn_mesh_run_msg, env: env, args: ['manual reply'])
    expect(described_class).to have_received(:mesh_send_text).once.with(hash_including(obj: radio, to: '!ddeeff00', text: 'manual reply'))
  end

  it 'snapshots sender and radio channel metadata before queued rendering' do
    allow(described_class).to receive(:mesh_subscribe).and_call_original
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    radio[:proto_data] = [{ channel: { index: 0, role: :PRIMARY, settings: { name: 'LongFast' } } },
                          { node_info: { num: 0xbbccddee, user: { short_name: 'FIRST' } } }]
    callback = nil
    allow(Meshtastic::Serial).to receive(:subscribe) { |*, &block| callback = block }
    messages = []
    described_class.send(:mesh_subscribe, env: env, obj: radio, transport: :serial, psks: {}, on_message: proc { |msg| messages << msg })
    callback.call(packet: packet)
    radio[:proto_data].first[:channel][:settings][:name] = 'Changed'
    radio[:proto_data].last[:node_info][:user][:short_name] = 'LATE'
    stub_const('PWN::MeshObj', {})
    stub_const('PWN::MeshTransport', :mqtt)
    described_class.send(:mesh_handle_rx, env: env, msg: messages.first)
    expect(win).to have_received(:addstr).with(a_string_including('FIRST', '/LongFast/', 'RX via Serial'))
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).with(hash_including(obj: radio, channel_name: 'LongFast'))
  end

  it 'keeps a callback exception from disconnecting the subscription' do
    allow(described_class).to receive(:mesh_subscribe).and_call_original
    allow(Meshtastic::Serial).to receive(:subscribe) do |*, &block|
      block.call(packet: packet)
      block.call(packet: packet.merge(id: 124))
    end
    calls = 0
    described_class.send(:mesh_subscribe, env: env, obj: radio, transport: :serial, psks: {}, on_message: proc { |_msg|
      calls += 1
      raise IOError, 'fixture callback failure' if calls == 1
    })
    expect(calls).to eq(2)
    expect(described_class).to have_received(:mesh_ui_puts).with(hash_including(text: a_string_including('RX callback failed')))
  end

  it 'stops producers blocked on a full bounded queue without waiting for draining' do
    stub_const('PWN::MeshEvents', SizedQueue.new(1))
    allow(described_class).to receive(:mesh_subscribe) do |opts|
      ready << opts
      loop { opts[:on_message].call(packet: packet) }
    end
    described_class.send(:mesh_start_rx!, env: env, obj: radio)
    subscriptions(2)
    records = PWN::MeshReceivers.dup
    Timeout.timeout(3) { described_class.send(:mesh_stop_receivers!) }
    expect(records.map { |record| record[:thread].alive? }).to eq([false, false])
    expect(PWN::MeshEvents.size).to eq(1)
  end

  it 'keeps secondary TX echo state off the primary and does not suppress a different packet ID' do
    primary_tx = { id: 999, from: '!aabbccdd', to: '!ffffffff', text: 'primary', at: Time.now }
    stub_const('PWN::MeshLastTx', primary_tx)
    allow(Meshtastic::MQTT).to receive(:send_text)
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    described_class.send(:mesh_send_text, env: env, obj: broker, transport: :mqtt, text: 'repeated', channel_name: 'LongFast', channel: 8)
    expect(PWN::MeshLastTx).to equal(primary_tx)
    sent = broker.instance_variable_get(:@pwn_mesh_last_tx)
    inbound = { packet: { id: sent[:id] + 1, from: 0xb0b, to: 0xffffffff, decoded: { portnum: 1, payload: 'repeated' } },
                mesh_transport: :mqtt, topic: 'msh/US/CA/2/e/LongFast/!00000b0b' }
    described_class.send(:mesh_handle_rx, env: env, obj: broker, msg: inbound)
    expect(win).to have_received(:addstr).with(" repeated\n").twice
  end

  it 'stops remaining reply chunks if their generation closes after the first publish' do
    record = { active: true }
    allow(Meshtastic::MQTT).to receive(:send_text) { record[:active] = false }
    expect do
      described_class.send(:mesh_send_text, env: env, obj: broker, transport: :mqtt, connection: record,
                                            text: 'word ' * 100, channel_name: 'LongFast', channel: 8)
    end.to raise_error(IOError, /remaining reply text is unsent/)
    expect(Meshtastic::MQTT).to have_received(:send_text).once
  end

  it 'never resolves an origin radio slot using another connection inventory during AI gating' do
    env[:channel][:LongFast].delete(:radio_index)
    radio[:proto_data] << { channel: { index: 3, role: :SECONDARY, settings: { name: 'LongFast' } } }
    origin = { my_node_num: 0xddeeff00, proto_data: [] }
    allow(PWN::AI::Agent::Loop).to receive(:run)
    result = described_class.send(:mesh_maybe_dispatch_to_pwn_ai, env: env, obj: origin, transport: :tcp, text: '@ai question', from: '!bbccddee', to: '!ffffffff', radio: 3)
    expect(result).to eq(:skipped)
    expect(PWN::AI::Agent::Loop).not_to have_received(:run)
  end

  it 'accepts non-packet FromRadio channel configuration without callback error notices' do
    allow(described_class).to receive(:mesh_subscribe).and_call_original
    queue = Queue.new
    queue << Meshtastic::FromRadio.decode(Meshtastic::FromRadio.new(channel: { index: 0, role: :PRIMARY, settings: { name: 'LongFast' } }).to_proto)
    queue.close
    radio[:from_radio_queue] = queue
    messages = []
    described_class.send(:mesh_subscribe, env: env, obj: radio, transport: :serial, psks: {}, on_message: proc { |msg| messages << msg })
    expect(messages.first.dig(:channel, :settings, :name)).to eq('LongFast')
    expect(described_class).not_to have_received(:mesh_ui_puts)
  end

  it 'displays distinct packet IDs even when sender, text and render timestamp are identical' do
    allow(Time).to receive(:now).and_return(Time.utc(2026, 1, 2))
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    [123, 124].each do |id|
      described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet.merge(id: id), mesh_transport: :serial })
    end
    expect(win).to have_received(:addstr).with(" @ai question\n").twice
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).twice
  end
end
