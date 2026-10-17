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
  let(:details) do
    Class.new do
      attr_reader :lines
      attr_accessor :width

      def initialize
        @lines = []
        @width = 32
      end

      def maxx
        @width
      end

      def maxy
        20
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
  let(:rcvr) { details.class.new }
  let(:packet) { { id: 123, from: 0x421f6f22, to: 0xffffffff, decoded: { portnum: :TEXT_MESSAGE_APP, payload: 'hello' } } }

  before do
    stub_const('PWN::MeshTransport', :serial)
    stub_const('PWN::MeshObj', radio)
    stub_const('PWN::MeshReceivers', [])
    stub_const('PWN::MeshRxState', {})
    stub_const('PWN::MeshLastTx', nil)
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxBodyWin', win)
    stub_const('PWN::MeshSndrWin', details)
    stub_const('PWN::MeshRcvrWin', rcvr)
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

    painted = win.lines.join
    expect(painted).to include('RX via Serial')
    expect(painted).not_to include('RX via MQTT')
    expect(rcvr.lines.join).not_to include('VIA')
    expect(details.lines.join).not_to include('VIA')
    expect(described_class).to have_received(:mesh_maybe_dispatch_to_pwn_ai).once.with(hash_including(transport: :mqtt))
  end

  it 'does not index an MQTT client while painting node details' do
    require 'mqtt'
    client = MQTT::Client.new(host: 'offline.invalid')
    stub_const('PWN::MeshReceivers', [{ obj: client, transport: :mqtt, secondary: true, active: true }])
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet, mesh_transport: :serial })
    described_class.send(:mesh_handle_rx, env: env, obj: client, msg: { packet: packet.merge(id: 124), mesh_transport: :mqtt, topic: 'msh/US/2/e/LongFast/!421f6f22' })
    expect(described_class).not_to have_received(:mesh_ui_puts).with(hash_including(text: a_string_including('RX display failed')))
    expect(details.lines.join).to include('Node ID: !421f6f22')
  end

  it 'keeps RX via MQTT when that is the only observation' do
    described_class.send(:mesh_handle_rx, env: env, obj: broker, msg: { packet: packet, mesh_transport: :mqtt, topic: 'msh/US/2/e/LongFast/!421f6f22' })

    expect(win.lines.join).to include('RX via MQTT')
    expect(win.lines.join).not_to include('RX via Serial')
    expect(rcvr.lines.join).not_to include('VIA')
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

  it 'links a known sender position in MSG DETAILS and leaves unknown positions unlabeled' do
    lat_i = 10_000_000
    lon_i = -20_000_000
    coord = format('%<lat>.7f,%<lon>.7f', lat: lat_i / 10_000_000.0, lon: lon_i / 10_000_000.0)
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: {
                           packet: { id: 1, from: 0x421f6f22, decoded: { portnum: :POSITION_APP, payload: { latitude_i: lat_i, longitude_i: lon_i, location_source: :LOC_INTERNAL } } }
                         })
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet, mesh_transport: :serial })
    linked = details.lines.join
    expect(details.lines.join).to include('SENDER', 'Node ID: !421f6f22', coord)
    expect(rcvr.lines.join).to include('RECEIVER', 'Node ID: LongFast', 'GPS: N/A')
    expect(rcvr.lines.join).not_to include('broadcast')
    expect(linked).not_to include('maps.google.com')
    expect(linked).not_to include("\e")
    hit = PWN::MeshRxState[:gps_hits].find { |row| row[:url].include?(coord) }
    expect(hit[:url]).to eq("https://maps.google.com/?q=#{coord}")
    allow(described_class).to receive(:mesh_maps_opener).and_return(['/usr/bin/xdg-open'])
    expect(Process).to receive(:spawn).with('/usr/bin/xdg-open', hit[:url], hash_including(out: File::NULL, err: File::NULL)).and_return(0)
    expect(Process).to receive(:detach).with(0)
    described_class.send(:mesh_open_gps_at, x: hit[:x], y: hit[:y])
    expect(details.lines.join).not_to include('maps.google.com')
    expect(headers.join).not_to include('GPS N/A')
    expect(headers.join).not_to include('maps.google.com')
    details.lines.clear
    allow(details).to receive(:maxx).and_return(20)
    described_class.send(:mesh_paint_details, obj: radio)
    expect(details.lines.grep(Regexp.new(Regexp.escape(coord.split(',').first)))).to all(include(coord))

    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: {
                           packet: { id: 2, from: 0x99aabbcc, to: 0xffffffff, decoded: { portnum: 1, payload: 'no fix' } }, mesh_transport: :serial
                         })
    expect(details.lines.join).to include('!99aabbcc', 'GPS: N/A')
    expect(details.lines.join).not_to include('maps.google.com')
  end

  it 'shows the highlighted conversation message, and the last received message while composing' do
    first = '1.0000000,2.0000000'
    second = '3.0000000,4.0000000'
    described_class.send(:mesh_store_position, id: '!421f6f22', position: { latitude_i: 10_000_000, longitude_i: 20_000_000, location_source: :LOC_INTERNAL })
    described_class.send(:mesh_store_position, id: '!99aabbcc', position: { latitude_i: 30_000_000, longitude_i: 40_000_000, location_source: :LOC_INTERNAL })
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet, mesh_transport: :serial })
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: {
                           packet: packet.merge(id: 9, from: 0x99aabbcc), mesh_transport: :serial
                         })
    expect(details.lines.join).to include(second)
    expect(details.lines.join).not_to include(first)
    allow(win).to receive(:maxy).and_return(1)
    described_class.send(:mesh_set_focus, focus: :conversation)
    described_class.send(:mesh_scroll_conversation, key: :home)
    expect(details.lines.join).to include(first)
    expect(details.lines.join).not_to include(second)
    described_class.send(:mesh_set_focus, focus: :compose)
    expect(details.lines.join).to include(second)
    expect(details.lines.join).not_to include(first)
    described_class.send(:mesh_handle_rx, env: env, obj: radio, local: true, transport: :serial, msg: {
                           packet: packet.merge(id: 11, from: 0x1337, to: 0x99aabbcc), decoded: { portnum: 1, payload: 'sent' }
                         })
    expect(details.lines.join).to include(second)
    expect(details.lines.join).not_to include('!00001337')
  end

  it 'includes the receiver fix for a direct message and not for broadcast' do
    described_class.send(:mesh_store_position, id: '!421f6f22', position: { latitude_i: 10_000_000, longitude_i: -20_000_000, location_source: :LOC_INTERNAL })
    described_class.send(:mesh_store_position, id: '!00001337', position: { latitude_i: 11_000_000, longitude_i: -21_000_000, location_source: :LOC_MANUAL })
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: {
                           packet: packet.merge(to: 0x1337), mesh_transport: :serial
                         })
    sender = '1.0000000,-2.0000000'
    receiver = '1.1000000,-2.1000000'
    painted = details.lines.join
    expect(details.lines.join).to include('SENDER', 'Node ID: !421f6f22', sender)
    expect(rcvr.lines.join).to include('RECEIVER', 'Node ID: !00001337', receiver)
    expect(rcvr.lines.join).not_to include('broadcast')
  end

  it 'shows node inventory fields under cyan SENDER and RECEIVER titles' do
    heard = Time.at(1_700_000_000).getlocal.strftime('%Y-%m-%d %H:%M:%S%z')
    key = 'k' * 32
    radio[:proto_data] << {
      node_info: {
        num: 0x421f6f22, last_heard: 1_700_000_000, hops_away: 3, is_key_manually_verified: true,
        device_metrics: { uptime_seconds: 3661 },
        user: { short_name: 'PEER', role: :ROUTER, public_key: key }
      }
    }
    colors = []
    allow(details).to receive(:attron) { |attr| colors << attr }
    described_class.send(:mesh_handle_rx, env: env, obj: radio, msg: { packet: packet, mesh_transport: :serial })
    painted = details.lines.join("\n")
    expect(painted).to include('SENDER', 'Node ID: !421f6f22', 'GPS:')
    expect(painted).not_to include('VIA')
    node_num = 0x421f6f22
    expect(painted).to include('Short Name: PEER', 'Device Role: ROUTER', "Node #: #{node_num}")
    expect(painted).to include('Last Heard:', heard, 'Hops Away: 3', 'Uptime: 1h 1m 1s')
    expect(painted).to include('Security: PKI verified', 'Public Key:')
    expect(painted.gsub(/\s+/, '')).to include(key.unpack1('H*'))
    expect(colors).to include(Curses.color_pair(20) | Curses::A_BOLD)
    expect(rcvr.lines.join).to include('RECEIVER', 'Node ID: LongFast', 'Short Name: —', 'Device Role: —')
    expect(rcvr.lines.join).not_to include('VIA', 'PEER', 'broadcast')
  end

  it 'does not refresh MSG DETAILS from the radio position cache' do
    refreshes = 0
    allow(details).to receive(:refresh) { refreshes += 1 }
    20.times do |index|
      described_class.send(:mesh_store_position, id: format('!%08x', index), position: { latitude_i: 10_000_000, longitude_i: -20_000_000, location_source: :LOC_INTERNAL })
    end
    expect(refreshes).to eq(0)
  end

  it 'does not warn when reading a curses mouse event' do
    allow(Curses).to receive(:getmouse) do
      warn 'undefining the allocator of T_DATA class Curses::MouseEvent'
      nil
    end
    expect { described_class.send(:mesh_open_gps_click) }.not_to output(/MouseEvent/).to_stderr
  end

  it 'treats unset 0,0 as unknown and an explicit source at 0,0 as a real fix' do
    expect(described_class.send(:mesh_position_pair, position: { latitude_i: 0, longitude_i: 0, location_source: :LOC_UNSET })).to be_nil
    expect(described_class.send(:mesh_position_pair, position: { latitude_i: 0, longitude_i: 0, location_source: :LOC_MANUAL })).to eq([0.0, 0.0])
    expect(described_class.send(:mesh_position_pair, position: { latitude_i: 910_000_000, longitude_i: 0, location_source: :LOC_INTERNAL })).to be_nil
  end
end
