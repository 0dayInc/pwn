# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

describe PWN::Plugins::REPL, 'mesh msg command' do
  let(:mesh_env) do
    {
      transport: 'mqtt',
      channel: {
        active: 'LongFast',
        LongFast: { psk: 'AQ==', region: 'US/UT', topic: '2/e/#', channel_num: 8 }
      }
    }
  end

  before do
    PWN::Env[:plugins] ||= {}
    @prev_mesh = PWN::Env[:plugins][:meshtastic]
    PWN::Env[:plugins][:meshtastic] = mesh_env
    %i[MeshLastDm MeshLastChannel MeshTransport MeshObj].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
    PWN.const_set(:MeshTransport, :mqtt)
    PWN.const_set(:MeshObj, :mqtt)
  end

  after do
    PWN::Env[:plugins][:meshtastic] = @prev_mesh if PWN::Env[:plugins].is_a?(Hash)
    %i[MeshLastDm MeshLastChannel MeshTransport MeshObj].each do |c|
      PWN.send(:remove_const, c) if PWN.const_defined?(c)
    end
  end

  it 'replies to the last incoming DM with /msg text and to an explicit node with /msg !id text' do
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(
      :mesh_handle_rx,
      msg: {
        packet: {
          node_id_from: '!abcabcab',
          node_id_to: '!00000b0b',
          decoded: { portnum: 1, payload: 'ping' }
        }
      }
    )
    expect(described_class.pwn_mesh_dispatch_slash!(request: '/msg pong', pry: :fixture)).to eq(true)
    expect(described_class).to have_received(:mesh_send_text).with(hash_including(to: '!abcabcab', text: 'pong'))
    expect(described_class.pwn_mesh_dispatch_slash!(request: '/msg !deadbeef hello', pry: :fixture)).to eq(true)
    expect(described_class).to have_received(:mesh_send_text).with(hash_including(to: '!deadbeef', text: 'hello'))
    expect(described_class.pwn_mesh_complete(target: '/', line: '/')).to include('/msg')
    expect(described_class.pwn_mesh_complete(target: '/', line: '/')).not_to include('/dm')
  end

  it 'encodes a named MQTT channel message before receiving anything' do
    broker = double('broker', client_id: '!00000b0b')
    PWN.send(:remove_const, :MeshObj)
    PWN.const_set(:MeshObj, broker)
    envelope = nil
    allow(broker).to receive(:publish) do |_topic, bytes|
      envelope = Meshtastic::ServiceEnvelope.decode(bytes)
    end

    described_class.send(:pwn_mesh_run_msg, env: mesh_env, args: %w[LongFast hello])

    expect(envelope.packet.to).to eq(0xffffffff)
    expect(envelope.packet.channel).to eq(8)
    expect(envelope.channel_id).to eq('LongFast')
  end

  it 'addresses a named channel with /msg <channel> text' do
    mesh_env[:channel][:LongFast] = { psk: 'cHdu', radio_index: 1, topic: '2/e/LongFast/#' }
    allow(described_class).to receive(:mesh_send_text)
    expect(described_class.pwn_mesh_dispatch_slash!(request: '/msg LongFast hello channel', pry: :fixture)).to eq(true)
    expect(described_class).to have_received(:mesh_send_text).with(
      hash_including(to: '!ffffffff', text: 'hello channel', channel_name: 'LongFast', radio: 1)
    )
    expect(described_class.pwn_mesh_complete(target: 'L', line: '/msg L')).to include('LongFast')
  end

  it 'sends a compose line without /msg on the active channel' do
    PWN.const_set(:MeshLastChannel, 'LongFast')
    allow(described_class).to receive(:mesh_send_text)
    described_class.send(:mesh_compose_send, env: mesh_env, obj: :mqtt, text: 'hello on active')
    expect(described_class).to have_received(:mesh_send_text).with(
      hash_including(to: '!ffffffff', text: 'hello on active', channel_name: 'LongFast')
    )
  end
end
