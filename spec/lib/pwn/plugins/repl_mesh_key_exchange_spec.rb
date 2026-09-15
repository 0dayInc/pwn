# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

describe PWN::Plugins::REPL, 'mesh DM key exchange' do
  let(:local_user) { { id: '!aabbccdd', public_key: 'a' * 32 } }
  let(:remote_user) { { id: '!bbccddee', public_key: 'b' * 32 } }
  let(:obj) { { my_node_num: 0xaabbccdd, proto_data: [{ node_info: { num: 0xaabbccdd, user: local_user } }] } }
  let(:env) { { transport: 'auto', channel: { active: 'LongFast', LongFast: { radio_index: 1, psk: 'AQ==' } } } }

  before do
    stub_const('PWN::MeshPendingDm', nil)
    allow(described_class).to receive(:mesh_ui_puts)
    allow(described_class).to receive(:mesh_handle_rx)
  end

  %i[serial bluetooth tcp].each do |kind|
    it "exchanges NodeInfo then sends a PKI-enforced DM over #{kind}" do
      stub_const('PWN::MeshTransport', kind)
      transport = kind == :bluetooth ? Meshtastic::Bluetooth : Meshtastic::Serial
      packets = []
      allow(transport).to receive(:send_to_radio) do |opts|
        packet = Meshtastic::ToRadio.decode(opts[:to_radio]).packet
        packets << packet
        if packet.decoded.portnum == :NODEINFO_APP
          expect(packet.decoded.want_response).to eq(true)
          expect(Meshtastic::User.decode(packet.decoded.payload).public_key).to eq('a' * 32)
          obj[:proto_data] << { packet: { from: 0xbbccddee, decoded: { portnum: 4, payload: Meshtastic::User.new(remote_user).to_proto } } }
        end
      end
      described_class.send(:mesh_send_text, env: env, obj: obj, to: '!bbccddee', text: 'private', channel_name: 'LongFast')
      expect(packets.map { |p| p.decoded.portnum }).to eq(%i[NODEINFO_APP TEXT_MESSAGE_APP])
      expect(packets.last.pki_encrypted).to eq(true)
      expect(packets.last.public_key).to eq('b' * 32)
      expect(packets.last.to).to eq(0xbbccddee)
      expect(PWN::MeshPendingDm).to be_nil
    end
  end

  it 'retains the unsent text and never transmits it after discovery times out' do
    stub_const('PWN::MeshTransport', :serial)
    allow(Meshtastic::Serial).to receive(:send_data)
    expect(Meshtastic::Serial).not_to receive(:send_text)
    expect(Meshtastic::Serial).not_to receive(:send_to_radio)
    expect do
      described_class.send(:mesh_send_text, env: env, obj: obj, to: '!bbccddee', text: 'private', key_timeout: 0)
    end.to raise_error(IOError, /public key.*unsent/i)
    expect(PWN::MeshPendingDm[:text]).to eq('private')
  end

  it 'retries the retained message with bare /msg after the key becomes available' do
    stub_const('PWN::MeshTransport', :serial)
    stub_const('PWN::MeshObj', obj)
    stub_const('PWN::MeshPendingDm', { to: '!bbccddee', text: 'retained text' })
    stub_const('PWN::MeshLastTx', nil)
    obj[:proto_data] << { node_info: { num: 0xbbccddee, user: remote_user } }
    expect(Meshtastic::Serial).not_to receive(:send_data)
    expect(Meshtastic::Serial).to receive(:send_to_radio) do |opts|
      packet = Meshtastic::ToRadio.decode(opts[:to_radio]).packet
      expect(packet.pki_encrypted).to eq(true)
      expect(packet.decoded.payload).to eq('retained text')
    end
    described_class.send(:pwn_mesh_run_msg, env: env, args: [])
    expect(PWN::MeshPendingDm).to be_nil
  end

  it 'does not use another node public key as the destination key' do
    stub_const('PWN::MeshTransport', :serial)
    obj[:proto_data] << { node_info: { num: 0xccddeeff, user: remote_user } }
    allow(Meshtastic::Serial).to receive(:send_data)
    expect do
      described_class.send(:mesh_send_text, env: env, obj: obj, to: '!bbccddee', text: 'private', key_timeout: 0)
    end.to raise_error(IOError, /timed out/)
  end

  it 'refuses MQTT DMs without publishing a legacy encrypted or plaintext fallback' do
    stub_const('PWN::MeshTransport', :mqtt)
    expect(Meshtastic::MQTT).not_to receive(:send_text)
    expect do
      described_class.send(:mesh_send_text, env: env, obj: double('broker'), to: '!bbccddee', text: 'private')
    end.to raise_error(IOError, /MQTT.*PKI/)
    expect(PWN::MeshPendingDm[:text]).to eq('private')
  end
end
