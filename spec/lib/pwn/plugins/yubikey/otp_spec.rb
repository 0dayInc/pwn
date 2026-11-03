# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'pwn/plugins/yubikey/otp'

RSpec.describe 'PWN::Plugins::YubiKey::OTP native protocol' do
  subject(:otp) { PWN::Plugins::YubiKey::OTP }

  let(:wire) do
    Class.new do
      attr_reader :calls, :descriptor

      def initialize(responses, descriptor = { protocol: :otp })
        @responses = responses
        @descriptor = descriptor
        @calls = []
      end

      def exchange(opts = {})
        @calls << opts
        raise 'Unexpected device request' if @responses.empty?

        response = @responses.shift
        raise response if response.is_a?(Exception)

        response.respond_to?(:call) ? response.call(opts) : response
      end
    end
  end

  let(:status) { [5, 7, 1, 9, 3, 0].pack('C*') }

  it 'returns RFC 2202 raw SHA1 bytes over OTP HID, not hex or TOTP' do
    # RFC 2202 case 1; the peer boundary, not the host application, owns the key.
    expected = ['b617318655057264e28bc0b6fb378c8ef146be00'].pack('H*')
    peer = wire.new([status, expected])
    result = otp.challenge_response(connection: peer, challenge: 'Hi There'.b, slot: 2, confirm: true)
    expect(result).to eq(expected)
    expect(result.bytesize).to eq(20)
    expect(peer.calls.last).to include(protocol: :otp, command: 0x38, data: 'Hi There'.b.ljust(64, "\0"), response_length: 20)
  end

  it 'preserves trailing zero challenge bytes with nonzero padding' do
    peer = wire.new([status, 'x' * 20])
    otp.challenge_response(connection: peer, challenge: "a\0".b, slot: 1, confirm: true)
    expect(peer.calls.last[:data]).to eq("a\0".b + ("\1" * 62))
  end

  it 'validates raw challenge length and literal consent before device traffic' do
    peer = wire.new([])
    [nil, '', 'x' * 65, 12].each do |invalid|
      expect { otp.challenge_response(connection: peer, challenge: invalid, confirm: true) }.to raise_error(ArgumentError)
    end
    expect { otp.challenge_response(connection: peer, challenge: 'a', confirm: 'true') }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect(peer.calls).to be_empty
  end

  it 'programs an independent 52-byte configuration vector and verifies real HMAC readback' do
    # X25 complement from an independent MSB-first 0x1021 calculation, not OTP.crc.
    config = ['000000000000000000000000000000000b0b0b0b00000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000024402600007818'].pack('H*')
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    expected = ['b617318655057264e28bc0b6fb378c8ef146be00'].pack('H*')
    peer = wire.new([status, after, after, after, expected])
    result = otp.provision_challenge_response(connection: peer, slot: 2, key: "\x0b".b * 20, touch: false, confirm: true, verification_challenge: 'Hi There'.b)
    expect(peer.calls[1]).to include(command: 3, data: config + ("\0" * 6))
    expect(result).to eq(:verified)
    expect(peer.calls.count { |call| call[:command] == 0 }).to eq(3)
  end

  it 'does not retry programming when explicit readback is stale or HMAC mismatches' do
    peer = wire.new([status, status, status])
    expect { otp.provision_challenge_response(connection: peer, key: 'k' * 20, touch: false, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /uncertain/i)
    expect(peer.calls.count { |call| call[:command] == 3 }).to eq(1)
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    peer = wire.new([status, after, after, after, 'x' * 20])
    expect { otp.provision_challenge_response(connection: peer, key: 'k' * 20, touch: false, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /uncertain/i)
    expect(peer.calls.count { |call| call[:command] == 3 }).to eq(1)
  end

  it 'routes info locally and distinguishes empty-slot deletion readback from ACK' do
    expect(otp.operations).to contain_exactly('info', 'swap', 'ndef', 'delete', 'yubiotp', 'static', 'chalresp', 'calculate', 'hotp', 'settings')
    expect(otp.execute(args: [])).to include(application: :otp)
    peer = wire.new([status])
    expect(otp.execute(args: ['info'], connection: peer)[:slots][1][:configured]).to be(true)
    empty = [5, 7, 1, 0, 0, 0].pack('C*')
    peer = wire.new([status, empty, empty])
    result = otp.execute(args: ['delete', '2', '--force'], connection: peer, confirm: true)
    expect(peer.calls[1]).to include(command: 3, data: "\0" * 58)
    expect(result[:status][:slots][2][:configured]).to be(false)
  end

  it 'swaps configuration-state bits and verifies fresh status' do
    before = [5, 7, 1, 9, 5, 0].pack('C*')
    after = [5, 7, 1, 10, 10, 0].pack('C*')
    peer = wire.new([before, after, after])
    expect(otp.execute(args: ['swap'], connection: peer, confirm: true)[:verified]).to be(true)
    expect(peer.calls[1]).to include(command: 6, data: "\0" * 6)
  end

  it 'updates keyboard flags and access-code without reprogramming secrets' do
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    peer = wire.new([status, after, after])
    otp.execute(args: ['settings', '2', '--pacing', '60', '--no-enter', '--serial-usb-visible'], connection: peer, confirm: true, access_code: '123456', new_access_code: 'abcdef')
    config = peer.calls[1][:data]
    expect(peer.calls[1][:command]).to eq(5)
    expect(config.byteslice(0, 38)).to eq("\0" * 38)
    expect(config.byteslice(38, 6)).to eq('abcdef')
    expect(config.byteslice(44, 6)).to eq([16, 0x36, 0, 12, 0, 0].pack('C*'))
    expect(config.byteslice(52, 6)).to eq('123456')
  end

  it 'rejects credential argv and never treats force as consent' do
    peer = wire.new([])
    expect { otp.execute(args: %w[chalresp 2 secret], connection: peer, confirm: true) }.to raise_error(ArgumentError)
    expect { otp.execute(args: ['delete', '2', '--force'], connection: peer) }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect(peer.calls).to be_empty
  end

  it 'programs YubiOTP using binary keys without exposing or exporting secrets' do
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    peer = wire.new([status, after, after])
    result = otp.execute(args: ['yubiotp', '1', '--public-id', 'cbdefg', '--no-enter'], connection: peer, confirm: true, key: 'k' * 16, private_id: 'u' * 6)
    config = peer.calls[1][:data]
    expect(config.byteslice(0, 16)).to eq([0x01, 0x23, 0x45].pack('C*').ljust(16, "\0"))
    expect(config.byteslice(16, 22)).to eq(('u' * 6) + ('k' * 16))
    expect(config.byteslice(44, 6)).to eq([3, 0x34, 0, 0, 0, 0].pack('C*'))
    expect(result[:secret_readback]).to be(false)
    expect(result.to_s).not_to include('kkkkkkkkkkkkkkkk')
  end

  it 'programs static keyboard scan codes rather than UTF8 password bytes' do
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    peer = wire.new([status, after, after])
    otp.execute(args: ['static', '2', '--keyboard-layout', 'US'], connection: peer, confirm: true, password: 'Ab1!')
    config = peer.calls[1][:data]
    expect(config.byteslice(0, 38)).to eq([0x84, 5, 0x1e, 0x9e].pack('C*').ljust(38, "\0"))
    expect(config.byteslice(44, 4)).to eq([16, 0x34, 0x20, 2].pack('C*'))
  end

  it 'programs HOTP counter and identifier with exact binary field placement' do
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    peer = wire.new([status, after, after])
    otp.execute(args: ['hotp', '2', '--digits', '8', '--counter', '256', '--identifier', 'ubhe12345678'], connection: peer, confirm: true, key: '12345678901234567890')
    config = peer.calls[1][:data]
    expect(config.byteslice(0, 6)).to eq(['e16312345678'].pack('H*'))
    expect(config.byteslice(16, 6)).to eq("7890#{[16].pack('n')}")
    expect(config.byteslice(44, 4)).to eq([6, 0x34, 0x60, 0x42].pack('C*'))
  end

  it 'encodes URI and text NDEF records and performs separate status readback' do
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    peer = wire.new([status, after, after], protocol: :otp, nfc: true)
    otp.execute(args: ['ndef', '2', '--prefix', 'https://example.test/'], connection: peer, confirm: true)
    expect(peer.calls[1]).to include(command: 9, data: "#{[14, 0x55, 4].pack('C*')}example.test/#{"\0" * 40}#{"\0" * 6}")
    peer = wire.new([status, after, after], protocol: :otp, nfc: true)
    otp.execute(args: ['ndef', '1', '--ndef-type', 'TEXT', '--prefix', 'hello'], connection: peer, confirm: true)
    expect(peer.calls[1][:data].byteslice(0, 10)).to eq("#{[8, 0x54, 2].pack('C*')}enhello")
  end

  it 'calculates RFC 6238 TOTP natively while preserving raw HMAC API' do
    response = OpenSSL::HMAC.digest('SHA1', '12345678901234567890', [1].pack('Q>'))
    peer = wire.new([status, response])
    expect(otp.execute(args: ['calculate', '2', '59', '--totp', '--digits', '8'], connection: peer, confirm: true)).to eq('94287082')
    expect(peer.calls.last[:data]).to eq([1].pack('Q>').ljust(64, "\0"))
  end

  it 'uses the OTP smartcard application on NFC with full R-APDU validation' do
    expected = ['b617318655057264e28bc0b6fb378c8ef146be00'].pack('H*')
    peer = wire.new([status + "\x90\0".b, expected + "\x90\0".b], protocol: :apdu, transport: :nfc)
    expect(otp.challenge_response(connection: peer, challenge: 'Hi There', confirm: true)).to eq(expected)
    expect(peer.calls.first[:data]).to start_with(['00a4040007a0000005272001'].pack('H*'))
    expect(peer.calls.last[:data]).to eq(['0001380040'].pack('H*') + 'Hi There'.ljust(64, "\0"))
    peer = wire.new([status + "\x90\0".b, "\x69\x85".b], protocol: :apdu, transport: :nfc)
    expect { otp.challenge_response(connection: peer, challenge: 'Hi There', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    expect(peer.calls.length).to eq(2)
  end

  it 'encodes non-US static layouts and rejects unavailable characters' do
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    { 'DE' => ['z', 0x1c], 'FR' => ['a', 0x14], 'UK' => ['£', 0xa0], 'IT' => ['a', 4], 'BEPO' => ['b', 0x14], 'NORMAN' => ['a', 4] }.each do |layout, (password, code)|
      peer = wire.new([status, after, after])
      otp.provision_static(connection: peer, slot: 2, password: password, keyboard_layout: layout, confirm: true)
      expect(peer.calls[1][:data].getbyte(0)).to eq(code)
    end
  end

  it 'generates challenge keys only with consent and an explicit in-memory sink' do
    key = 'k' * 20
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    allow(SecureRandom).to receive(:random_bytes).with(20).and_return(key)
    captured = {}
    peer = wire.new([status, after, after, after, OpenSSL::HMAC.digest('SHA1', key, 'verify')])
    result = otp.execute(args: ['chalresp', '2', '--generate'], connection: peer, confirm: true, verification_challenge: 'verify', secret_sink: ->(name, secret) { captured[name] = secret })
    expect(captured).to eq(key: key)
    expect(result[:verification]).to eq(:hmac_sha1)
    expect(peer.calls[1][:data].getbyte(47)).to eq(0x26)
  end

  it 'exports explicitly requested Yubico CSV to a private file after verified programming' do
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    Dir.mktmpdir('otp-native-export-') do |dir|
      path = File.join(dir, 'configuration.csv')
      peer = wire.new([status, [12_345_678].pack('N'), status, after, after])
      otp.execute(args: ['yubiotp', '1', '--public-id', 'cb', '--config-output', path], connection: peer, confirm: true, key: 'k' * 16, private_id: 'u' * 6)
      fields = File.read(path).strip.split(',', -1)
      expect(fields.take(5)).to eq(['12345678', 'cb', ('75' * 6), ('6b' * 16), ''])
      expect(File.stat(path).mode & 0o777).to eq(0o600)
      expect(fields.last).to eq('')
    end
  end

  it 'accepts explicitly encoded Base32 TOTP secrets but never guesses an encoding' do
    key = '12345678901234567890'
    after = [5, 7, 1, 10, 3, 0].pack('C*')
    peer = wire.new([status, after, after, after, OpenSSL::HMAC.digest('SHA1', key, 'verify')])
    result = otp.execute(args: ['chalresp', '2', '--totp'], connection: peer, confirm: true, key: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', verification_challenge: 'verify')
    expect(result[:verification]).to eq(:hmac_sha1)
    expect(peer.calls[1][:data].byteslice(22, 16)).to eq('1234567890123456')
  end

  it 'refuses known USB-smartcard HMAC provisioning before overwriting a slot' do
    peer = wire.new([], protocol: :apdu, transport: :usb)
    expect { otp.provision_challenge_response(connection: peer, key: 'k' * 20, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /HID/)
    expect(peer.calls).to be_empty
  end

  it 'validates unsupported input and export destinations before any configuration write' do
    peer = wire.new([])
    expect { otp.provision_hotp(connection: peer, slot: 2, key: 'k' * 20, counter: 1, confirm: true) }.to raise_error(ArgumentError)
    expect { otp.provision_static(connection: peer, slot: 2, password: '!', confirm: true) }.to raise_error(ArgumentError)
    expect { otp.configure_ndef(connection: peer, slot: 2, prefix: 'x' * 60, confirm: true) }.to raise_error(ArgumentError)
    Dir.mktmpdir('otp-export-links-') do |dir|
      target = File.join(dir, 'private.csv')
      File.write(target, 'unchanged', mode: 'w', perm: 0o600)
      link = File.join(dir, 'link.csv')
      File.symlink(target, link)
      expect { otp.provision_yubiotp(connection: peer, slot: 2, public_id: 'cb', key: 'k' * 16, private_id: 'u' * 6, config_output: link, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
      expect(File.read(target)).to eq('unchanged')
    end
    expect(peer.calls).to be_empty
  end

  it 'checks NFC capability metadata before programming NDEF on an unknown HID model' do
    peer = wire.new([status, [9, 1, 2, 0, 1, 5, 3, 5, 7, 1].pack('C*')])
    expect { otp.configure_ndef(connection: peer, slot: 2, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /NFC/)
    expect(peer.calls.none? { |call| [8, 9].include?(call[:command]) }).to be(true)
  end

  it 'rejects ambiguous boolean controls and missing credentials before authentication' do
    peer = wire.new([])
    provider = instance_double(Proc)
    expect(provider).not_to receive(:call)
    expect { otp.provision_static(connection: peer, slot: 2, generate: 'false', secret_provider: provider, confirm: true) }.to raise_error(ArgumentError)
    expect { otp.provision_challenge_response(connection: peer, secret_provider: provider, confirm: false) }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect(peer.calls).to be_empty
  end

  it 'propagates cancelled HMAC operations without provisioning or replay' do
    peer = wire.new([status, PWN::Plugins::YubiKey::TimeoutError.new('cancelled synthetic touch wait')])
    expect { otp.challenge_response(connection: peer, challenge: 'a', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(peer.calls.map { |call| call[:command] }).to eq([0, 0x38])
  end

  it 'exercises the real native HID codec with an independent RFC response and wire CRC' do
    require 'pwn/plugins/yubikey/transport'
    feature = "\0".b + status + "\0".b
    digest = ['b617318655057264e28bc0b6fb378c8ef146be00'].pack('H*')
    # Independent reflected X25 complement for this RFC digest is little-endian 5754.
    body = (digest + ['5754'].pack('H*')).ljust(28, "\0")
    reports = Array.new(5, feature) + 4.times.map { |index| body.byteslice(index * 7, 7) + [0x40 + index].pack('C') } + ["\0\0\0\0\0\0\0\x40".b]
    io = Class.new do
      attr_reader :written, :closed

      def initialize(reports)
        @reports = reports
        @written = []
      end

      def read_feature
        @reports.shift || raise('Unexpected HID report read')
      end

      def write_feature(value)
        @written << value
      end

      def close
        @closed = true
      end
    end.new(reports)
    connection = PWN::Plugins::YubiKey::Transport::Connection.new(descriptor: { protocol: :otp }, io: io, timeout: 1)
    expect(otp.challenge_response(connection: connection, challenge: 'Hi There', slot: 2, confirm: true, timeout: 1)).to eq(digest)
    expect(io.written.map { |packet| packet.getbyte(7) }).to eq([0x80, 0x81, 0x89, 0xff])
    connection.close
    expect(io.closed).to be(true)
  ensure
    connection&.close
  end

  it 'verifies NFC provisioning cryptographically on older firmware with the documented zero-sequence quirk' do
    before = [5, 2, 0, 9, 3, 0].pack('C*')
    after = [5, 2, 0, 0, 3, 0].pack('C*')
    expected = ['b617318655057264e28bc0b6fb378c8ef146be00'].pack('H*')
    peer = wire.new([before, after, after, after, expected].map { |data| data + "\x90\0".b }, protocol: :apdu, transport: :nfc)
    result = otp.provision_challenge_response(connection: peer, slot: 2, key: "\x0b".b * 20, touch: false, confirm: true, verification_challenge: 'Hi There', details: true)
    expect(result).to include(verified: true, verification: :hmac_sha1)
    expect(peer.calls[1][:data]).to start_with(['000103003a'].pack('H*'))
    expect(peer.calls.count { |call| call[:data].start_with?(['000103'].pack('H*')) }).to eq(1)
  end

  it 'closes a reserved export handle if validation fails before device programming' do
    peer = wire.new([])
    file = instance_double(File, closed?: false)
    path = File.join(Dir.tmpdir, 'synthetic-otp-export.csv')
    allow(File).to receive(:open).and_call_original
    expect(File).to receive(:open).with(path, anything, 0o600).and_return(file)
    expect(file).to receive(:stat).and_raise(IOError, 'synthetic fstat failure')
    expect(file).to receive(:close).once
    expect { otp.provision_yubiotp(connection: peer, slot: 2, public_id: 'cb', key: 'k' * 16, private_id: 'u' * 6, config_output: path, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    expect(peer.calls).to be_empty
  end

  it 'reads YubiKey 4 FIPS approval only after actual capability metadata identifies the edition' do
    old_status = [4, 4, 1, 9, 3, 0].pack('C*')
    fields = ['0102003f0401810503040401'].pack('H*')
    peer = wire.new([old_status, old_status, [fields.bytesize].pack('C') + fields, "\1".b])
    expect(otp.execute(args: ['info'], connection: peer)[:fips_approved]).to be(true)
    expect(peer.calls.last).to include(command: 0x14, response_length: 1)
  end

  it 'rejects truncated responses and never retries a failed challenge' do
    peer = wire.new([status, 'x' * 19])
    expect { otp.challenge_response(connection: peer, challenge: 'a', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    expect(peer.calls.length).to eq(2)
  end
end
