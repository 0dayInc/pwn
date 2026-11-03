# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Native YubiKey protocol framing' do
  let(:protocol) { PWN::Plugins::YubiKey::Protocol }

  it 'encodes and decodes ordered BER-TLV without losing duplicate tags or binary bytes' do
    first = [0x71, 3, 0, 255, 1].pack('C*')
    second = [0x7f, 0x49, 0x81, 128].pack('C*') + ('x'.b * 128)
    expect(protocol.tlv(tag: 0x71, value: "\x00\xff\x01".b)).to eq(first)
    expect(protocol.tlv(tag: 0x7f49, value: 'x'.b * 128)).to eq(second)
    expected = [{ tag: 0x71, value: "\x00\xff\x01".b }, { tag: 0x7f49, value: 'x'.b * 128 }, { tag: 0x71, value: "\x00\xff\x01".b }]
    expect(protocol.untlv(data: first + second + first)).to eq(expected)
  end

  it 'selects an application and assembles a bounded GET RESPONSE exchange' do
    frames = []
    replies = ["first\x61\x03".b, "end\x90\x00".b]
    connection = double('offline smartcard')
    allow(connection).to receive(:exchange) do |opts|
      frames << opts
      replies.shift
    end
    expect(protocol.select(connection: connection, aid: "\xa0\x00\x01".b, timeout: 2)).to eq('firstend'.b)
    expect(frames.map { |frame| frame[:data].unpack1('H*') }).to eq(%w[00a4040003a00001 00c0000003])
    expect(frames).to all(include(protocol: :apdu, timeout: be_between(0, 2)))
  end

  it 'chains short commands and supports explicit extended-length APDUs' do
    frames = []
    connection = double('offline smartcard')
    allow(connection).to receive(:exchange) do |opts|
      frames << opts[:data]
      "\x90\x00".b
    end
    data = 'x'.b * 256
    expect(protocol.apdu(connection: connection, ins: 0xda, data: data)).to eq(''.b)
    expect(frames).to eq([[0x10, 0xda, 0, 0, 255].pack('C*') + ('x' * 255), [0, 0xda, 0, 0, 1].pack('C*') << 'x'])
    frames.clear
    protocol.apdu(connection: connection, ins: 0xda, data: data, extended: true, le: 65_536)
    expect(frames).to eq([[0, 0xda, 0, 0, 0, 1, 0].pack('C*') + data + "\x00\x00".b])
    frames.clear
    protocol.apdu(connection: connection, ins: 0xf8)
    expect(frames).to eq([[0, 0xf8, 0, 0, 0].pack('C*')])
  end

  it 'corrects one wrong Le and uses an application-specific continuation instruction' do
    frames = []
    replies = ["\x6c\x03".b, "a\x61\x00".b, "bc\x90\x00".b]
    connection = double('offline smartcard')
    allow(connection).to receive(:exchange) do |opts|
      frames << opts[:data].unpack1('H*')
      replies.shift
    end
    expect(protocol.apdu(connection: connection, ins: 0xca, le: 1, get_response_ins: 0xa5, get_response_le: 0)).to eq('abc'.b)
    expect(frames).to eq(%w[00ca000001 00ca000003 00a5000000])
  end

  it 'interprets wrong-Le zero as 256 bytes even for an extended command' do
    frames = []
    replies = ["\x6c\x00".b, "\x90\x00".b]
    connection = double('offline smartcard')
    allow(connection).to receive(:exchange) do |opts|
      frames << opts[:data].unpack1('H*')
      replies.shift
    end
    protocol.apdu(connection: connection, ins: 0xca, le: 512, extended: true)
    expect(frames).to eq(%w[00ca0000000200 00ca0000000100])
  end

  it 'parses only declared native options and preserves identifiers and repeated values' do
    args = ['--rp-id', 'first.example', '--rp-id', 'second.example', '--no-enter', '--', '-例:account  ']
    expect(protocol.parse_args(args: args, flags: ['--no-enter'], values: ['--rp-id'])).to eq(
      positionals: ['-例:account  '], options: { rp_id: %w[first.example second.example], no_enter: true }
    )
    expect { protocol.parse_args(args: ['--pin', 'fixture'], flags: [], values: []) }.to raise_error(ArgumentError, /option/)
    expect { protocol.parse_args(args: ['--rp-id'], values: ['--rp-id']) }.to raise_error(ArgumentError, /value/)
  end

  it 'provides a unique-tag mapping while rejecting truncated and duplicate fields' do
    expect(protocol.tlv_map(data: "\x71\x01a\x72\x01b".b)).to eq(0x71 => 'a'.b, 0x72 => 'b'.b)
    expect { protocol.tlv_map(data: "\x71\x01a\x71\x01b".b) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /Duplicate/)
    ["\x71", "\x71\x80", "\x71\x82\x00", "\x71\x02a", "\x7f\x81"].each do |truncated|
      expect { protocol.untlv(data: truncated.b) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    end
  end

  it 'applies the same complete-frame bound to TLV encoding and decoding' do
    expect { protocol.tlv(tag: 0x71, value: 'x' * protocol::MAX_BYTES) }.to raise_error(ArgumentError, /frame/)
  end

  it 'requires literal caller consent instead of truthy substitutes' do
    expect(protocol.require_confirm(confirm: true)).to eq(:confirmed)
    [nil, false, 'true', 1].each do |value|
      expect { protocol.require_confirm(confirm: value) }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    end
  end

  it 'obtains secrets only from explicit memory values or a supplied callback' do
    provider = double('private caller input')
    expect(provider).to receive(:call).with(:pin).once.and_return('000123')
    expect(protocol.secret(name: :pin, secret_provider: provider)).to eq('000123')
    expect(protocol.secret(name: :key, value: "\x00\xff".b, secret_provider: provider)).to eq("\x00\xff".b)
    expect { protocol.secret(name: :pin, value: false, secret_provider: provider) }.to raise_error(ArgumentError, /pin/)
    expect { protocol.secret(name: :pin) }.to raise_error(ArgumentError, /pin/)
  end

  it 'compares explicit firmware tuples without normalizing malformed versions' do
    expect(protocol.version_at_least?(version: [5, 7, 0], minimum: [5, 6, 9])).to be(true)
    expect(protocol.version_at_least?(version: [5, 7, 0], minimum: [5, 7, 1])).to be(false)
    expect { protocol.version_at_least?(version: ['5', 7, 0], minimum: [5, 7, 0]) }.to raise_error(ArgumentError)
  end

  it 'rejects invalid request bounds before sending any command' do
    connection = double('offline smartcard', exchange: nil)
    expect(connection).not_to receive(:exchange)
    [{ timeout: false }, { timeout: 0 }, { timeout: Float::INFINITY }, { ins: 256 }, { cla: 1.0 },
     { extended: 'true' }, { le: 257 }, { data: 'x' * 65_536 }, { get_response_ins: -1 }, { max_response: 0 }].each do |invalid|
      expect { protocol.apdu({ connection: connection, ins: 1 }.merge(invalid)) }.to raise_error(ArgumentError)
    end
  end

  it 'keeps authentication errors secret-free and never replays them' do
    connection = double('offline smartcard')
    expect(connection).to receive(:exchange).once.and_return("\x63\xc2".b)
    expect { protocol.apdu(connection: connection, ins: 0x20, data: 'fixture-private-pin') }.to raise_error(PWN::Plugins::YubiKey::Protocol::APDUError) do |error|
      expect(error.status).to eq(0x63c2)
      expect(error.message).not_to include('fixture-private-pin')
    end
  end

  it 'bounds truncated, oversized and endless continuation responses' do
    connection = double('offline smartcard')
    ['', "\x90", "long\x90\x00"].each do |response|
      allow(connection).to receive(:exchange).and_return(response.b)
      expect { protocol.apdu(connection: connection, ins: 1, max_response: 2) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    end
    allow(connection).to receive(:exchange).and_return("\x61\x00".b)
    expect { protocol.apdu(connection: connection, ins: 1) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /fragments/)
  end

  it 'uses one total deadline across response fragments' do
    connection = double('offline smartcard')
    expect(connection).to receive(:exchange).once.and_return("\x61\x00".b)
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC).and_return(1, 1, 2)
    expect { protocol.apdu(connection: connection, ins: 1, timeout: 1) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
  end
end
