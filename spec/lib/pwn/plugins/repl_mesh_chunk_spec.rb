# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

describe PWN::Plugins::REPL, 'mesh payload chunking' do
  let(:max) { Meshtastic::Constants::DATA_PAYLOAD_LEN }
  let(:env) { { transport: 'serial' } }

  before do
    PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
    PWN.const_set(:MeshTransport, :serial)
    allow(described_class).to receive(:mesh_handle_rx)
  end

  after do
    PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
  end

  it 'sends text that fits DATA_PAYLOAD_LEN as a single unprefixed payload' do
    expect(Meshtastic::Serial).to receive(:send_text).once.with(
      hash_including(text: 'hi', to: '!ffffffff')
    )
    described_class.send(:mesh_send_text, env: env, obj: :serial_obj, text: 'hi', to: '!ffffffff')
  end

  it 'chunks text longer than DATA_PAYLOAD_LEN as (i/N) payloads until complete' do
    body = 'A' * (max + 10)
    sent = []
    allow(Meshtastic::Serial).to receive(:send_text) { |h| sent << h[:text] }

    described_class.send(:mesh_send_text, env: env, obj: :serial_obj, text: body, to: '!ffffffff')

    expect(sent.size).to be > 1
    n = sent.size
    expect(sent[0]).to start_with("(1/#{n}) ")
    expect(sent[-1]).to start_with("(#{n}/#{n}) ")
    expect(sent).to all(satisfy { |piece| piece.length <= max && piece.bytesize <= max })
    reconstructed = sent.map { |piece| piece.sub(%r{\A\(\d+/\d+\) }, '') }.join
    expect(reconstructed).to eq(body)
  end

  it 'keeps each chunk small enough that the encoded ToRadio fits a 256-byte LoRa frame' do
    body = 'A' * max
    chunks = described_class.send(:mesh_text_chunks, text: body)
    expect(chunks.size).to be > 1
    mui = Meshtastic::MeshInterface.new
    chunks.each do |piece|
      expect(piece.bytesize).to be <= max
      proto = mui.send_text(
        from: '!00000b0b',
        to: '!ffffffff',
        channel: 0,
        text: piece,
        want_ack: true,
        psks: nil,
        via: :radio
      )
      body_bytes = proto.is_a?(String) ? proto.b.bytesize : proto.to_proto.bytesize
      expect(body_bytes).to be <= 256
    end
    reconstructed = chunks.map { |piece| piece.sub(%r{\A\(\d+/\d+\) }, '') }.join
    expect(reconstructed).to eq(body)
  end

  it 'sends chunked frames with want_ack so the radio reports when each chunk is on the air' do
    body = 'A' * (max + 10)
    sent = []
    allow(Meshtastic::Serial).to receive(:send_text) { |h| sent << h[:want_ack] }
    described_class.send(:mesh_send_text, env: env, obj: :serial_obj, text: body, to: '!ffffffff')
    expect(sent.size).to be > 1
    expect(sent).to all(eq(true))
  end

  it 'waits for a free device TX slot before sending the next chunk' do
    body = 'A' * (max + 10)
    obj = { proto_data: [], rx_mutex: Mutex.new }
    allow(Meshtastic::Serial).to receive(:send_text)
    allow(described_class).to receive(:mesh_wait_tx_slot)
    described_class.send(:mesh_send_text, env: env, obj: obj, text: body, to: '!ffffffff')
    n = described_class.send(:mesh_text_chunks, text: body).size
    expect(described_class).to have_received(:mesh_wait_tx_slot).exactly(n - 1).times
  end

  it 'does not wait for a TX slot after a single payload' do
    allow(Meshtastic::Serial).to receive(:send_text)
    allow(described_class).to receive(:mesh_wait_tx_slot)
    described_class.send(:mesh_send_text, env: env, obj: { proto_data: [] }, text: 'hi', to: '!ffffffff')
    expect(described_class).not_to have_received(:mesh_wait_tx_slot)
  end

  it 'does not treat QueueStatus free as the chunk being on the air' do
    obj = { proto_data: [{ queueStatus: { free: 15, maxlen: 16 } }], rx_mutex: Mutex.new }
    t = Time.now
    described_class.send(:mesh_wait_tx_slot, obj: obj, since: 0, timeout: 0.25)
    expect(Time.now - t).to be >= 0.2
  end

  it 'treats a ROUTING_APP FromRadio as a TX slot without a fixed sleep' do
    obj = { proto_data: [], rx_mutex: Mutex.new }
    Thread.new do
      sleep 0.05
      obj[:rx_mutex].synchronize do
        obj[:proto_data] << { packet: { decoded: { portnum: :ROUTING_APP, request_id: 1 } } }
      end
    end
    t = Time.now
    described_class.send(:mesh_wait_tx_slot, obj: obj, since: 0, timeout: 1)
    expect(Time.now - t).to be < 0.5
  end
end
