# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'
require 'socket'
require 'timeout'

describe PWN::Plugins::REPL, 'mesh RX error boundaries' do
  include_context 'pwn tmp sandbox'

  let(:env) do
    { transport: 'mqtt', dispatch_to_pwn_ai: true, ai_whitelist: ['LongFast'],
      channel: { active: 'LongFast', LongFast: { psk: Base64.strict_encode64('x' * 32), region: 'US/CA', topic: '2/e/LongFast/#' } } }
  end
  let(:args) { { env: env, obj: {}, transport: :mqtt, text: '@ai hello', from: '!aabbccdd', to: '!ffffffff', channel_name: 'LongFast' } }

  before do
    allow(described_class).to receive(:mesh_ui_puts)
    allow(described_class).to receive(:mesh_send_text)
  end

  after do
    described_class.send(:mesh_stop_receivers!)
    PWN.send(:remove_const, :MeshDispatchLock) if PWN.const_defined?(:MeshDispatchLock)
  end

  %i[primary secondary].product(%i[eof truncated shutdown race saturated]).each do |role, failure|
    it "owns #{role} MQTT #{failure} without a thread crash or caller interruption" do
      stub_const('PWN::MeshReceivers', [])
      stub_const('PWN::MeshEvents', SizedQueue.new(failure == :saturated ? 1 : 8))
      server = TCPServer.new('127.0.0.1', 0)
      env[:mqtt] = { host: '127.0.0.1', port: server.addr[1], user: 'offline', pass: 'offline', tls: false }
      accepted = Queue.new
      close = Queue.new
      broker = Thread.new do
        socket = server.accept
        MQTT::Packet.read(socket)
        socket.write(MQTT::Packet::Connack.new.to_s)
        MQTT::Packet.read(socket)
        accepted << true
        if failure == :saturated
          packet = Meshtastic::MeshPacket.new(from: 0xaabbccdd, to: 0xffffffff,
                                              decoded: Meshtastic::Data.new(portnum: :TEXT_MESSAGE_APP, payload: 'offline'.b))
          payload = Meshtastic::ServiceEnvelope.new(packet: packet, channel_id: 'LongFast', gateway_id: '!11223344').to_proto
          2.times { socket.write(MQTT::Packet::Publish.new(topic: 'msh/US/CA/2/e/LongFast/!11223344', payload: payload).to_s) }
        end
        close.pop
        socket.write("\x30") if failure == :truncated
        socket.close
      ensure
        socket&.close
      end
      ready = Queue.new
      faults = Queue.new
      caller = Thread.new do
        obj = described_class.send(:mesh_connect_one, env: env, transport: :mqtt) if role == :primary
        ready << described_class.send(:mesh_start_receiver!, env: env, transport: :mqtt, obj: obj, secondary: role == :secondary)
        sleep
      rescue StandardError => e
        faults << e
      end
      record = Timeout.timeout(5) { ready.pop }
      Timeout.timeout(5) { accepted.pop }
      reader = record[:obj].instance_variable_get(:@read_thread)
      owner = record[:obj].instance_variable_get(:@pwn_mesh_mqtt_owner)[:thread]
      expect do
        described_class.send(:mesh_mqtt_subscribe, options: { mqtt_obj: record[:obj] }, callback: proc {})
      end.to raise_error(IOError, /already subscribed/)
      if %i[shutdown race saturated].include?(failure)
        Timeout.timeout(5) { sleep 0.01 until PWN::MeshEvents.num_waiting.positive? } if failure == :saturated
        close << true if failure == :race
        described_class.send(:mesh_stop_receivers!)
        close << true unless failure == :race
        described_class.send(:mesh_drain_events)
        expect(PWN::MeshEvents).to be_empty
      else
        close << true
        Timeout.timeout(5) { sleep 0.01 until record[:stopped] || !faults.empty? }
        event = Timeout.timeout(5) { PWN::MeshEvents.pop }
        expect(event[:text]).to include('mqtt RX failed', 'MQTT::ProtocolException', 'reconnect')
      end
      expect(faults.size).to eq(0)
      expect(record[:thread].join(5)).to be_a(Thread)
      expect(owner).not_to be_alive
      expect(reader).not_to be_alive
      expect(record[:obj]).not_to be_connected
    ensure
      caller&.kill&.join
      broker&.kill&.join
      server&.close
    end
  end

  it 'runs the real request runtime with a canonical leased transcript before provider dispatch' do
    reached = Queue.new
    allow(PWN::AI::Agent::Loop).to receive(:run_turn) do |options|
      sid = options[:session_id]
      reached << [sid, PWN::Sessions.active?(session_id: sid), Thread.current]
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'offline reply')
      'offline reply'
    end
    expect(described_class.send(:mesh_maybe_dispatch_to_pwn_ai, args)).to eq(:dispatched)
    Timeout.timeout(5) { sleep 0.01 while PWN.const_defined?(:MeshDispatchLock) }
    expect(described_class).to have_received(:mesh_send_text).with(hash_including(text: 'offline reply'))
    sid, active, worker = reached.pop(true)
    expect(sid).to match(PWN::Sessions::SESSION_ID)
    expect(active).to be(true)
    expect(worker).not_to equal(Thread.current)
    expect(PWN::Sessions.active?(session_id: sid)).to be(false)
  end

  it 'closes an in-flight broker handshake when its receiving generation is stopped' do
    stub_const('PWN::MeshReceivers', [])
    stub_const('PWN::MeshEvents', SizedQueue.new(8))
    server = TCPServer.new('127.0.0.1', 0)
    env[:mqtt] = { host: '127.0.0.1', port: server.addr[1], user: 'offline', pass: 'offline' }
    record = described_class.send(:mesh_start_receiver!, env: env, transport: :mqtt, secondary: true)
    socket = Timeout.timeout(5) { server.accept }
    MQTT::Packet.read(socket)
    described_class.send(:mesh_stop_receivers!)
    expect(record[:thread]).not_to be_alive
    expect(Timeout.timeout(2) { socket.read }).to eq('')
  ensure
    socket&.close
    server&.close
  end

  it 'reproduces the original missing-ID failure in the actual runtime, not the transport' do
    expect { PWN::AI::Agent::Loop.run(request: 'offline', nested: true) }.to raise_error(ArgumentError, 'invalid session ID')
  end

  it 'keeps real MQTT protobuf reception alive after a callback exception' do
    server = TCPServer.new('127.0.0.1', 0)
    env[:mqtt] = { host: '127.0.0.1', port: server.addr[1], user: 'offline', pass: 'offline' }
    close = Queue.new
    received = Queue.new
    broker = Thread.new do
      socket = server.accept
      MQTT::Packet.read(socket)
      socket.write(MQTT::Packet::Connack.new.to_s)
      MQTT::Packet.read(socket)
      [1, 2].each do |id|
        packet = Meshtastic::MeshPacket.new(id: id, from: 0xaabbccdd, to: 0xffffffff,
                                            decoded: Meshtastic::Data.new(portnum: :TEXT_MESSAGE_APP, payload: 'offline'.b))
        payload = Meshtastic::ServiceEnvelope.new(packet: packet, channel_id: 'LongFast', gateway_id: '!11223344').to_proto
        socket.write(MQTT::Packet::Publish.new(topic: 'msh/US/CA/2/e/LongFast/!11223344', payload: payload).to_s)
      end
      close.pop
    ensure
      socket&.close
    end
    obj = described_class.send(:mesh_connect_one, env: env, transport: :mqtt)
    subscriber = Thread.new do
      described_class.send(:mesh_subscribe, env: env, transport: :mqtt, obj: obj, psks: { LongFast: env[:channel][:LongFast][:psk] },
                                            on_message: proc { |msg|
                                              received << msg[:packet][:id]
                                              raise 'callback fixture'
                                            })
    rescue IOError => e
      received << e
    end
    expect(Timeout.timeout(5) { [received.pop, received.pop] }).to eq([1, 2])
    expect(obj).to be_connected
    expect(described_class).to have_received(:mesh_ui_puts).with(hash_including(text: a_string_including('RX callback failed'))).twice
    close << true
    expect(subscriber.join(5)).to be_a(Thread)
    expect(received.pop(true)).to be_a(IOError)
  ensure
    described_class.send(:mesh_disconnect, obj: obj, transport: :mqtt) if obj
    subscriber&.kill&.join
    broker&.kill&.join
    server&.close
  end

  it 'reuses durable history across transports but isolates peer, channel, region, key and DM destination' do
    session_args = { env: env, channel_name: 'LongFast', from: '!aabbccdd', to: '!ffffffff' }
    first = described_class.send(:mesh_ai_session, session_args)
    PWN::Sessions.append(session_id: first[:id], role: 'user', content: 'previous offline question')
    PWN::Sessions.deactivate(lease: first[:lease])
    again = described_class.send(:mesh_ai_session, session_args.merge(env: env.merge(transport: 'serial')))
    expect(again[:id]).to eq(first[:id])
    expect(PWN::Sessions.load(session_id: again[:id]).map { |row| row[:content] }).to include('previous offline question')
    PWN::Sessions.deactivate(lease: again[:lease])
    variants = [session_args.merge(from: '!bbccddee'), session_args.merge(to: '!11223344'),
                session_args.merge(channel_name: 'Different'), session_args.merge(network_path: 'EU/2/e/LongFast'),
                session_args.merge(env: env.merge(channel: { LongFast: env[:channel][:LongFast].merge(psk: Base64.strict_encode64('y' * 32)) }))]
    ids = variants.map do |options|
      session = described_class.send(:mesh_ai_session, options)
      PWN::Sessions.deactivate(lease: session[:lease])
      session[:id]
    end
    expect(ids.uniq.size).to eq(variants.size)
    expect(ids).not_to include(first[:id])
    expect(ids).to all(match(PWN::Sessions::SESSION_ID))
  end

  %w[AI TX].each do |stage|
    it "labels #{stage} failures correctly and closes the session lease" do
      ids = Queue.new
      allow(PWN::AI::Agent::Loop).to receive(:run) do |options|
        ids << options[:session_id]
        raise IOError, 'offline provider error' if stage == 'AI'

        'reply'
      end
      allow(described_class).to receive(:mesh_send_text).and_raise(IOError, 'offline send error') if stage == 'TX'
      described_class.send(:mesh_maybe_dispatch_to_pwn_ai, args)
      Timeout.timeout(5) { sleep 0.01 while PWN.const_defined?(:MeshDispatchLock) }
      expect(described_class).to have_received(:mesh_ui_puts).with(hash_including(text: a_string_starting_with("#{stage} failed: IOError:")))
      expect(PWN::Sessions.active?(session_id: ids.pop(true))).to be(false)
      expect(described_class).not_to have_received(:mesh_send_text) if stage == 'AI'
    end
  end

  it 'does not create a session or worker for ordinary RX text' do
    expect(PWN::Sessions).not_to receive(:create)
    expect(Thread).not_to receive(:new)
    expect(described_class.send(:mesh_maybe_dispatch_to_pwn_ai, args.merge(text: 'ordinary receipt'))).to eq(:skipped)
  end

  it 'deduplicates RX before real runtime session creation and replies only to the first origin' do
    stub_const('PWN::MeshRxState', {})
    allow(described_class).to receive(:mesh_env_hash).and_return(env)
    origins = [{ active: true, env: env, obj: {}, transport: :mqtt }, { active: true, env: env, obj: {}, transport: :tcp }]
    calls = Queue.new
    allow(PWN::AI::Agent::Loop).to receive(:run_turn) do |options|
      calls << options[:session_id]
      'offline reply'
    end
    origins.each do |origin|
      message = { topic: 'msh/US/CA/2/e/LongFast/!aabbccdd', mesh_transport: origin[:transport], mesh_channel_name: 'LongFast',
                  packet: { id: 987, from: 0xaabbccdd, to: 0xffffffff, decoded: { portnum: 1, payload: '@ai hello' } } }
      message.delete(:topic) if origin[:transport] == :tcp
      described_class.send(:mesh_handle_rx, msg: message, env: env, obj: origin[:obj], connection: origin)
      Timeout.timeout(5) { sleep 0.01 while PWN.const_defined?(:MeshDispatchLock) }
    end
    Timeout.timeout(5) { sleep 0.01 while PWN.const_defined?(:MeshDispatchLock) }
    expect(calls.size).to eq(1)
    expect(calls.pop).to match(PWN::Sessions::SESSION_ID)
    expect(PWN::MeshRxState[:seen_packets].size).to eq(1)
    expect(described_class).to have_received(:mesh_send_text).once.with(hash_including(transport: :mqtt, obj: origins.first[:obj], connection: origins.first))
  end

  it 'owns a rejected CONNACK and closes the socket before returning an actionable connect error' do
    server = TCPServer.new('127.0.0.1', 0)
    closed = Queue.new
    broker = Thread.new do
      socket = server.accept
      MQTT::Packet.read(socket)
      socket.write("\x20\x02\x00\x05")
      closed << socket.read
    ensure
      socket&.close
    end
    env[:mqtt] = { host: '127.0.0.1', port: server.addr[1], user: 'offline', pass: 'offline' }
    expect { described_class.send(:mesh_connect_one, env: env, transport: :mqtt) }.to raise_error(IOError, /MQTT::ProtocolException/)
    expect(Timeout.timeout(5) { closed.pop }).to eq('')
  ensure
    broker&.kill&.join
    server&.close
  end

  it 'reconnects a failed broker with one fresh subscriber and invalidates old events' do
    stub_const('PWN::MeshReceivers', [])
    stub_const('PWN::MeshEvents', SizedQueue.new(8))
    stub_const('PWN::MeshTransport', :mqtt)
    stub_const('PWN::MeshSubThread', nil)
    stub_const('PWN::MqttObj', nil)
    allow(described_class).to receive(:mesh_refresh_ui!)
    server = TCPServer.new('127.0.0.1', 0)
    env[:mqtt] = { host: '127.0.0.1', port: server.addr[1], user: 'offline', pass: 'offline' }
    accepted = Queue.new
    close = Queue.new
    broker = Thread.new do
      socket = nil
      2.times do
        socket = server.accept
        MQTT::Packet.read(socket)
        socket.write(MQTT::Packet::Connack.new.to_s)
        MQTT::Packet.read(socket)
        accepted << true
        close.pop
        socket.close
      end
    ensure
      socket&.close
    end
    obj = described_class.send(:mesh_connect_one, env: env, transport: :mqtt)
    stub_const('PWN::MeshObj', obj)
    described_class.send(:mesh_start_rx!, env: env, obj: obj)
    Timeout.timeout(5) { accepted.pop }
    old = PWN::MeshReceivers.first
    close << true
    expect(old[:thread].join(5)).to be_a(Thread)
    expect(described_class.send(:mesh_reconnect!, env: env)).to eq(:reconnected)
    Timeout.timeout(5) { accepted.pop }
    expect(PWN::MeshReceivers.size).to eq(1)
    expect(PWN::MeshReceivers.first[:thread]).to be_alive
    expect(old[:active]).to be(false)
    described_class.send(:mesh_drain_events)
    expect(PWN::MeshEvents).to be_empty
    expect(PWN::MeshObj).not_to equal(obj)
    described_class.send(:mesh_stop_receivers!)
    close << true
  ensure
    broker&.kill&.join
    server&.close
  end

  it 'bounds queued diagnostics and discards stale-generation notices without UI requeueing' do
    stub_const('PWN::MeshEvents', SizedQueue.new(1))
    allow(described_class).to receive(:mesh_ui_puts).and_call_original
    allow(described_class).to receive(:mesh_notice)
    record = { active: true }
    described_class.send(:mesh_ui_puts, text: "AI failed: #{'x' * 2000}", connection: record)
    expect(PWN::MeshEvents.pop[:notice].size).to eq(1024)
    PWN::MeshEvents << { notice: 'old failure', connection: record }
    record[:active] = false
    described_class.send(:mesh_drain_events)
    expect(described_class).not_to have_received(:mesh_notice)
    PWN::MeshEvents << { text: 'mqtt RX failed: offline' }
    Timeout.timeout(2) { described_class.send(:mesh_drain_events) }
    expect(described_class).to have_received(:mesh_notice).with(text: 'mqtt RX failed: offline')
  end
end
