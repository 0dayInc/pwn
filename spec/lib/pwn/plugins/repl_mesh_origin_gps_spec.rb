# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

describe PWN::Plugins::REPL, 'mesh primary display, MQTT sender, and GPS link' do
  let(:env) do
    { transport: 'serial', mqtt: { host: 'offline.invalid', region: 'US' },
      channel: { active: 'LongFast', LongFast: { psk: 'AQ==', region: 'US', topic: '2/e/LongFast/#', from: '!00001337' } } }
  end
  let(:radio) { { my_node_num: 0x1337, proto_data: [], rx_mutex: Mutex.new } }
  let(:broker) { double('offline broker', publish: nil, client_id: '00000b0b') }
  let(:win) do
    Class.new do
      attr_reader :lines

      def initialize
        @lines = []
      end

      def maxx
        180
      end

      def attron(*) end
      def attroff(*) end
      def refresh; end
      def setpos(*); end

      def addstr(text)
        @lines << text
      end

      def clear
        @lines.clear
      end
    end.new
  end
  let(:packet) { { id: 123, from: 0x421f6f22, to: 0xffffffff, decoded: { portnum: :TEXT_MESSAGE_APP, payload: 'hello' } } }

  before do
    stub_const('PWN::MeshTransport', :serial)
    stub_const('PWN::MeshObj', radio)
    stub_const('PWN::MeshReceivers', [])
    stub_const('PWN::MeshRxState', {})
    stub_const('PWN::MeshLastTx', nil)
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxBodyWin', win)
    allow(Curses).to receive(:color_pair) { |color| color }
    allow(described_class).to receive(:mesh_env_hash).and_return(env)
    allow(described_class).to receive(:mesh_maybe_dispatch_to_pwn_ai)
    allow(described_class).to receive(:mesh_ui_puts)
  end

  def headers
    win.lines.grep(/RX via|TX via/)
  end

  it 'relabels an MQTT-first row to the primary transport without a second AI dispatch' do
    described_class.send(:mesh_handle_rx, env: env, obj: broker, msg: { packet: packet, mesh_transport: :mqtt, topic: 'msh/US/2/e/LongFast/!421f6f22' })
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet, mesh_transport: :serial })

    expect(headers).to eq(headers.grep(/RX via Serial/))
    expect(headers.join).to include('RX via Serial')
    expect(headers.join).not_to include('RX via MQTT')
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).once.with(hash_including(transport: :mqtt))
  end

  it 'keeps RX via MQTT when that is the only observation' do
    described_class.send(:mesh_handle_rx, env: env, obj: broker, msg: { packet: packet, mesh_transport: :mqtt, topic: 'msh/US/2/e/LongFast/!421f6f22' })

    expect(headers.join).to include('RX via MQTT')
    expect(headers.join).not_to include('RX via Serial')
  end

  it 'publishes the configured channel sender instead of the MQTT library default' do
    expect(broker).to receive(:publish) do |_topic, bytes|
      expect(Meshtastic::ServiceEnvelope.decode(bytes).packet.from).to eq(0x1337)
    end
    described_class.send(:mesh_send_text, env: env, obj: broker, transport: :mqtt, from: '!00000b0b', text: 'sent', channel_name: 'LongFast')
  end

  it 'uses the connected radio node when channel.from is absent' do
    radio_env = env.merge(channel: { active: 'LongFast', LongFast: { psk: 'AQ==', region: 'US', topic: '2/e/LongFast/#' } })
    expect(broker).to receive(:publish) do |_topic, bytes|
      expect(Meshtastic::ServiceEnvelope.decode(bytes).packet.from).to eq(0x1337)
    end
    described_class.send(:mesh_send_text, env: radio_env, obj: broker, transport: :mqtt, from: '!00000b0b', text: 'sent', channel_name: 'LongFast')
  end

  it 'links a known sender position and leaves unknown positions unlabeled' do
    lat_i = 10_000_000
    lon_i = -20_000_000
    coord = format('%<lat>.7f,%<lon>.7f', lat: lat_i / 10_000_000.0, lon: lon_i / 10_000_000.0)
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: {
                           packet: { id: 1, from: 0x421f6f22, decoded: { portnum: :POSITION_APP, payload: { latitude_i: lat_i, longitude_i: lon_i, location_source: :LOC_INTERNAL } } }
                         })
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet, mesh_transport: :serial })
    linked = headers.join
    expect(linked).to include("#{coord} >> https://maps.google.com/?q=#{coord}")
    expect(linked).not_to include("\e")
    expect(win.lines.join).not_to include("\n https://")
    win.lines.clear
    allow(win).to receive(:maxx).and_return(120)
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet.merge(id: 9), mesh_transport: :serial })
    expect(win.lines.map(&:strip).grep(Regexp.new(Regexp.escape(coord.split(',').first)))).to all(include(coord))

    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: {
                           packet: { id: 2, from: 0x99aabbcc, to: 0xffffffff, decoded: { portnum: 1, payload: 'no fix' } }, mesh_transport: :serial
                         })
    expect(headers.last).to include('!99aabbcc')
    expect(headers.last).to end_with(" · GPS N/A\n")
  end

  it 'treats unset 0,0 as unknown and an explicit source at 0,0 as a real fix' do
    expect(described_class.send(:mesh_position_pair, position: { latitude_i: 0, longitude_i: 0, location_source: :LOC_UNSET })).to be_nil
    expect(described_class.send(:mesh_position_pair, position: { latitude_i: 0, longitude_i: 0, location_source: :LOC_MANUAL })).to eq([0.0, 0.0])
    expect(described_class.send(:mesh_position_pair, position: { latitude_i: 910_000_000, longitude_i: 0, location_source: :LOC_INTERNAL })).to be_nil
  end
end
