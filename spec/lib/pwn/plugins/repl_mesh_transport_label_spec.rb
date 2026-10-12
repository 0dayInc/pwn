# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

describe PWN::Plugins::REPL, 'mesh per-message transport labels' do
  let(:env) do
    { transport: 'auto', mqtt: { region: 'US/CA' }, channel: {
      active: 'LongFast', LongFast: { radio_index: 0, psk: 'AQ==' }
    } }
  end
  let(:obj) do
    rows = [[0xaabbccdd, 'SELF'], [0xbbccddee, 'PEER']].map do |num, name|
      wire = Meshtastic::FromRadio.new(node_info: { num: num, user: { short_name: name, long_name: 'Not a short name' } }).to_proto
      Meshtastic::FromRadio.decode(wire).to_h
    end
    { my_node_num: 0xaabbccdd, proto_data: rows, rx_mutex: Mutex.new }
  end
  let(:win) { double('conversation', maxx: 200, attron: nil, attroff: nil, addstr: nil, refresh: nil) }
  let(:message) do
    { packet: Meshtastic::MeshPacket.new(id: 123, from: 0xbbccddee, to: 0xffffffff,
                                         decoded: { portnum: :TEXT_MESSAGE_APP, payload: 'hello' }).to_h }
  end

  before do
    stub_const('PWN::MeshObj', obj)
    stub_const('PWN::MeshRxBodyWin', win)
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxState', {})
    stub_const('PWN::MeshLastTx', nil)
    stub_const('PWN::MeshLastChannel', nil)
    stub_const('PWN::MeshEvents', Queue.new)
    allow(described_class).to receive(:mesh_env_hash).and_return(env)
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    allow(described_class).to receive(:mesh_wait_tx_slot).and_return(:ok)
    allow(Curses).to receive(:color_pair) { |color| color }
    allow(Time).to receive(:now).and_return(Time.utc(2026, 1, 2, 3, 4, 5))
  end

  { serial: 'Serial', bluetooth: 'Bluetooth', tcp: 'TCP', mqtt: 'MQTT' }.each do |kind, label|
    it "retains #{label} RX origin through callback and queued rendering after transport changes" do
      stub_const('PWN::MeshTransport', kind)
      backend = Meshtastic.const_get(label)
      callback = nil
      expect(backend).to receive(:subscribe).with(hash_including("#{kind}_obj": obj)) { |*, &block| callback = block }
      described_class.send(:mesh_subscribe, env: env, obj: obj, psks: {}, on_message: proc { |msg| PWN::MeshEvents << { msg: msg, obj: obj } })
      # Neither a changed pin nor a newly resolved connection can relabel old events.
      env[:transport] = kind == :mqtt ? 'serial' : 'mqtt'
      stub_const('PWN::MeshTransport', kind == :mqtt ? :serial : :mqtt)
      message[:topic] = 'msh/US/CA/2/e/LongFast/!bbccddee' if kind == :mqtt
      callback.call(message.freeze)
      obj[:proto_data].last[:node_info][:user][:short_name] = 'LATE'
      described_class.send(:mesh_drain_events)

      expect(win).to have_received(:addstr).with(" 2026-01-02 03:04:05+0000 🔍 · PEER · US/CA/2/e/LongFast/!bbccddee · US/CA/2/e/LongFast/# · RX via #{label}\n")
      expect(win).to have_received(:attron).with(21 | Curses::A_BOLD)
      expect(win).to have_received(:addstr).with(" hello\n")
      expect(message).not_to have_key(:mesh_transport)
      expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).with(hash_including(text: 'hello', from: '!bbccddee'))
    end

    it "labels TX with the resolved #{label} sender rather than auto or a later binding" do
      stub_const('PWN::MeshTransport', kind)
      allow(described_class).to receive(:mesh_connect_one) do |options|
        raise IOError, 'offline probe unavailable' unless options[:transport] == kind

        obj
      end
      expect(described_class.send(:mesh_connect, env: env)).to equal(obj)
      expect(PWN::MeshTransport).to eq(kind)
      backend = Meshtastic.const_get(label)
      expect(backend).to receive(:send_text).with(hash_including("#{kind}_obj": obj, text: 'sent')) do
        stub_const('PWN::MeshTransport', kind == :mqtt ? :serial : :mqtt)
        stub_const('PWN::MeshObj', { my_node_num: 0xbbccddee, proto_data: [] })
      end
      described_class.send(:mesh_send_text, env: env, obj: obj, text: 'sent', channel_name: 'LongFast', channel: 0)

      expect(win).to have_received(:addstr).with(" 2026-01-02 03:04:05+0000 🔍 · SELF · US/CA/2/e/LongFast/!aabbccdd (ME) · US/CA/2/e/LongFast/# · TX via #{label}\n")
      expect(win).to have_received(:attron).with(23 | Curses::A_BOLD)
      expect(described_class).not_to have_received(:mesh_maybe_dispatch_to_pwn_ai)
    end
  end

  it 'includes direction and origin in display dedup while still suppressing a local TX echo' do
    stub_const('PWN::MeshTransport', :serial)
    message[:packet][:channel] = 0
    %i[mqtt serial serial].each do |kind|
      described_class.send(:mesh_handle_rx, msg: message.merge(mesh_transport: kind))
    end
    expect(win).to have_received(:addstr).with(" hello\n").twice
    described_class.send(:mesh_handle_rx, local: true, transport: :serial, msg: message)
    expect(win).to have_received(:addstr).with(" hello\n").exactly(3).times
    stub_const('PWN::MeshLastTx', { from: '!bbccddee', text: 'hello', at: Time.now })
    described_class.send(:mesh_handle_rx, msg: message.merge(mesh_transport: :mqtt))
    expect(win).to have_received(:addstr).with(" hello\n").exactly(3).times
  end

  it 'preserves PKI DM endpoints, reply rendering and raw AI text alongside the origin' do
    stub_const('PWN::MeshTransport', :tcp)
    message[:packet].merge!(channel: 0, to: obj[:my_node_num], pki_encrypted: true)
    described_class.send(:mesh_handle_rx, msg: message.merge(mesh_transport: :tcp))
    reply = message[:packet].merge(id: 124, decoded: { portnum: 1, reply_id: 123, payload: '@ai reply' })
    described_class.send(:mesh_handle_rx, msg: { packet: reply, mesh_transport: :tcp })
    expect(win).to have_received(:addstr).with(a_string_matching(/🔒 · PEER · .*!bbccddee.*!aabbccdd \(ME\) · RX via TCP\n/)).twice
    expect(win).to have_received(:addstr).with(" Replied to: \"!bbccddee >> hello\" with: @ai reply\n")
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).with(hash_including(text: '@ai reply', radio: 0))
  end

  it 'does not invent a known transport for an untagged event' do
    stub_const('PWN::MeshTransport', :mqtt)
    described_class.send(:mesh_handle_rx, msg: message)
    expect(win).to have_received(:addstr).with(a_string_ending_with(" · RX via Unknown\n"))
  end

  it 'learns MQTT sender names from real NODEINFO envelopes, not gateway or destination names' do
    stub_const('PWN::MeshTransport', :mqtt)
    broker = double('offline MQTT', subscribe: nil, disconnect: nil)
    stub_const('PWN::MeshObj', broker)
    frames = [[0xbbccddee, 'PEER'], [0x00000b0b, 'SELF']].map do |num, name|
      user = Meshtastic::User.new(short_name: name).to_proto
      Meshtastic::ServiceEnvelope.new(packet: { from: num, to: 0xffffffff, decoded: { portnum: :NODEINFO_APP, payload: user } }).to_proto
    end
    frames << Meshtastic::ServiceEnvelope.new(packet: message[:packet], gateway_id: '!aabbccdd').to_proto
    allow(broker).to receive(:get_packet) do |&block|
      frames.each { |bytes| block.call(Struct.new(:topic, :payload).new('msh/US/CA/2/e/LongFast/!aabbccdd', bytes)) }
    end
    described_class.send(:mesh_subscribe, env: env, obj: broker, psks: {}, on_message: proc { |msg| described_class.send(:mesh_handle_rx, msg: msg) })
    expect(win).to have_received(:addstr).with(a_string_including('🔍 · PEER · US/CA/2/e/LongFast/!bbccddee'))
    expect(broker).to receive(:publish) do |topic, bytes|
      envelope = Meshtastic::ServiceEnvelope.decode(bytes)
      expect(envelope.packet.from).to eq(0x00000b0b)
      expect(envelope.packet.to).to eq(0xffffffff)
      expect(topic).to eq('msh/US/CA/2/e/LongFast/!00000b0b')
    end
    described_class.send(:mesh_send_text, env: env, obj: broker, from: '!00000b0b', text: 'sent', channel_name: 'LongFast', channel: 0)
    expect(win).to have_received(:addstr).with(a_string_including('🔍 · SELF · US/CA/2/e/LongFast/!00000b0b (ME)'))
  end

  [nil, '', " \t\n", "\u00a0"].each do |name|
    it "omits absent/blank short names without substituting the long name: #{name.inspect}" do
      obj[:proto_data].each { |row| row[:node_info][:user][:short_name] = name }
      described_class.send(:mesh_handle_rx, msg: message.merge(mesh_transport: :serial))
      expect(win).to have_received(:addstr).with(" 2026-01-02 03:04:05+0000 🔍 · US/CA/2/e/LongFast/!bbccddee · US/CA/2/e/LongFast/# · RX via Serial\n")
    end
  end

  it 'sanitizes control/newline/delimiter text while preserving Unicode and legitimate internal spaces' do
    obj[:proto_data].last[:node_info][:user][:short_name] = "\u00a0\e[31mÉ  山\n·\tX\e[0m\u00a0"
    described_class.send(:mesh_handle_rx, msg: message.merge(mesh_transport: :serial))
    expect(win).to have_received(:addstr).with(a_string_including('🔍 · É  山   X · US/CA/2/e/LongFast/!bbccddee'))
  end

  %i[serial bluetooth tcp].each do |kind|
    it "renders actual #{kind} FromRadio replay and encoded TX using the local User, never the recipient" do
      stub_const('PWN::MeshTransport', kind)
      queue = Queue.new
      queue << Meshtastic::FromRadio.decode(Meshtastic::FromRadio.new(packet: message[:packet]).to_proto)
      queue.close
      obj[:from_radio_queue] = queue
      described_class.send(:mesh_subscribe, env: env, obj: obj, psks: {}, on_message: proc { |msg| described_class.send(:mesh_handle_rx, msg: msg) })
      backend = { serial: Meshtastic::Serial, bluetooth: Meshtastic::Bluetooth, tcp: Meshtastic::Serial }.fetch(kind)
      expect(backend).to receive(:send_to_radio) do |args|
        packet = Meshtastic::ToRadio.decode(args[:to_radio]).packet
        expect(packet.from).to eq(0xaabbccdd)
        expect(packet.to).to eq(0xffffffff)
        expect(packet.decoded.payload).to eq('sent')
        expect(packet.channel).to eq(0)
      end
      described_class.send(:mesh_send_text, env: env, obj: obj, from: '!bbccddee', text: 'sent', channel_name: 'LongFast')
      expect(win).to have_received(:addstr).with(a_string_including('🔍 · PEER · US/CA/2/e/LongFast/!bbccddee'))
      expect(win).to have_received(:addstr).with(a_string_including('🔍 · SELF · US/CA/2/e/LongFast/!aabbccdd (ME)'))
    end
  end

  it 'keeps sender names on reactions without dispatching their body to AI' do
    described_class.send(:mesh_handle_rx, msg: message.merge(mesh_transport: :tcp))
    data = { portnum: :TEXT_MESSAGE_APP, reply_id: 123, emoji: 1, payload: '👍'.b }
    reaction = Meshtastic::FromRadio.new(packet: { id: 124, from: 0xbbccddee, to: 0xffffffff, decoded: data })
    described_class.send(:mesh_handle_rx, msg: Meshtastic::FromRadio.decode(reaction.to_proto).to_h.merge(mesh_transport: :tcp))
    expect(win).to have_received(:addstr).with(a_string_including('🔍 · PEER ·')).twice
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).once
  end

  [40, 80, 160].each do |width|
    it "retains complete headers and exact delimiter spacing at #{width} columns" do
      allow(win).to receive(:maxx).and_return(width)
      headers = []
      allow(win).to receive(:addstr) { |text| headers << text if text.include?(' via ') }
      described_class.send(:mesh_handle_rx, msg: message.merge(mesh_transport: :serial))
      expect(headers.size).to eq(1)
      expect(headers.first.split(' · ').size).to eq(5)
      expect(headers.first).not_to match(/  ·|·  /)
      expect(headers.first).to include('US/CA/2/e/LongFast/!bbccddee', 'US/CA/2/e/LongFast/#', 'RX via Serial')
    end
  end

  it 'keeps a captured missing name absent even if inventory is learned before queued rendering' do
    obj[:proto_data].clear
    callback = nil
    stub_const('PWN::MeshTransport', :serial)
    allow(Meshtastic::Serial).to receive(:subscribe) { |*, &block| callback = block }
    events = []
    described_class.send(:mesh_subscribe, env: env, obj: obj, psks: {}, on_message: proc { |msg| events << msg })
    callback.call(message)
    obj[:proto_data] << { node_info: { num: 0xbbccddee, user: { short_name: 'LATE' } } }
    described_class.send(:mesh_handle_rx, msg: events.first)
    expect(win).to have_received(:addstr).with(a_string_including('🔍 · US/CA/2/e/LongFast/!bbccddee'))
    expect(events.first).to have_key(:mesh_short_name)
    expect(events.first[:mesh_short_name]).to be_nil
  end

  it 'omits unavailable local names instead of borrowing the destination name' do
    stub_const('PWN::MeshTransport', :serial)
    obj[:proto_data].first[:node_info][:user].delete(:short_name)
    allow(Meshtastic::Serial).to receive(:send_text)
    described_class.send(:mesh_send_text, env: env, obj: obj, text: 'sent', channel_name: 'LongFast')
    expect(win).to have_received(:addstr).with(a_string_including('🔍 · US/CA/2/e/LongFast/!aabbccdd (ME) ·'))
  end

  it 'uses the self short name for offline AI replies through the real TX encoder' do
    stub_const('PWN::MeshTransport', :serial)
    env[:dispatch_to_pwn_ai] = true
    env[:ai_whitelist] = ['LongFast']
    env[:channel][:LongFast][:psk] = Base64.strict_encode64('x' * 32)
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai).and_call_original
    allow(PWN::AI::Agent::Loop).to receive(:run).and_return('offline reply')
    allow(Thread).to receive(:new) { |&block| block.call }
    expect(Meshtastic::Serial).to receive(:send_to_radio) do |args|
      packet = Meshtastic::ToRadio.decode(args[:to_radio]).packet
      expect(packet.from).to eq(0xaabbccdd)
      expect(packet.decoded.payload).to eq('offline reply')
    end
    described_class.send(:mesh_maybe_dispatch_to_pwn_ai, env: env, text: '@ai question', from: '!bbccddee', to: '!ffffffff', channel_name: 'LongFast', radio: 0)
    expect(win).to have_received(:addstr).with(a_string_including('🔒 · SELF · US/CA/2/e/LongFast/!aabbccdd (ME)'))
  end
end
