# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/yubikey/protocol'
require 'pwn/plugins/yubikey/management'

RSpec.describe 'PWN::Plugins::YubiKey::Management native protocol' do
  subject(:management) { PWN::Plugins::YubiKey::Management }

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
        raise 'Unexpected management request' if @responses.empty?

        response = @responses.shift
        raise response if response.is_a?(Exception)

        response
      end
    end
  end

  let(:status) { [5, 7, 1, 9, 3, 0].pack('C*') }
  # Literal protocol fields, independent of the application encoder.
  let(:tlvs) { ['0102023f020400bc614e0302023f04018105030507010602000007010f0801400a01000d02023f0e02023f'].pack('H*') }
  let(:encoded) { [tlvs.bytesize].pack('C') + tlvs }

  it 'reads exact native device capabilities without inventing application support' do
    peer = wire.new([status, encoded])
    info = management.info(connection: peer)
    expect(info).to include(version: [5, 7, 1], serial: '12345678', is_locked: false, is_fips: true, form_factor: 1)
    expect(info[:supported_capabilities]).to eq(usb: 0x23f, nfc: 0x23f)
    expect(info[:enabled_capabilities]).to eq(usb: 0x23f, nfc: 0x23f)
    expect(peer.calls.last).to include(protocol: :otp, command: 0x13, data: "\0".b)
  end

  it 'reads length-prefixed information over management smartcard and CTAP vendor commands' do
    peer = wire.new(["YubiKey 5.7.1\x90\0".b, encoded + "\x90\0".b], protocol: :apdu)
    expect(management.info(connection: peer)[:serial]).to eq('12345678')
    expect(peer.calls.first[:data]).to eq(['00a4040008a000000527471117'].pack('H*'))
    expect(peer.calls.last[:data]).to eq(['001d000000'].pack('H*'))
    peer = wire.new([encoded], protocol: :ctap, version: [5, 7, 1])
    expect(management.info(connection: peer)[:version]).to eq([5, 7, 1])
    expect(peer.calls.first).to include(command: 0x42, data: "\0".b)
  end

  it 'changes only requested USB applications and verifies new device fields' do
    changed = encoded.sub(['0302023f'].pack('H*'), ['0302022f'].pack('H*'))
    peer = wire.new([status, encoded, ''.b, changed])
    result = management.configure_usb(connection: peer, disable: ['PIV'], confirm: true)
    expect(peer.calls[2]).to include(command: 0x15, data: ['040302022f'].pack('H*'))
    expect(result).to include(verified: true, verification: :device_information)
    expect(result[:info][:enabled_capabilities][:usb]).to eq(0x22f)
    expect(peer.calls.last[:command]).to eq(0x13)
  end

  it 'requires explicit consent and refuses unsupported capabilities without a write' do
    peer = wire.new([])
    expect { management.configure_usb(connection: peer, disable: ['PIV'], confirm: 'true') }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect(peer.calls).to be_empty
    peer = wire.new([status, encoded])
    expect { management.configure_usb(connection: peer, enable: ['HSMAUTH'], confirm: true) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /supported/i)
    expect(peer.calls.none? { |call| call[:command] == 0x15 }).to be(true)
  end

  it 'treats lost ACK and mismatching readback as uncertain without replay' do
    peer = wire.new([status, encoded, ''.b, encoded])
    expect { management.configure_usb(connection: peer, disable: ['PIV'], confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /uncertain/i)
    expect(peer.calls.count { |call| call[:command] == 0x15 }).to eq(1)
    peer = wire.new([status, encoded, PWN::Plugins::YubiKey::TimeoutError.new('synthetic timeout')])
    expect { management.configure_usb(connection: peer, disable: ['PIV'], confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /uncertain/i)
    expect(peer.calls.count { |call| call[:command] == 0x15 }).to eq(1)
  end

  it 'routes all config leaves and treats group/list paths as read-only' do
    expect(management.operations).to contain_exactly('usb', 'nfc', 'mode', 'set-lock-code', 'reset')
    expect(management.execute(args: [])).to include(application: :management)
    peer = wire.new([status, encoded])
    expect(management.execute(args: ['usb', '--list'], connection: peer)[:enabled]).to include('OTP', 'PIV', 'FIDO2')
    expect(peer.calls.length).to eq(2)
  end

  it 'disables NFC applications while retaining USB settings and validates readback' do
    changed = encoded.sub(['0e02023f'].pack('H*'), ['0e020000'].pack('H*'))
    peer = wire.new([status, encoded, ''.b, changed])
    result = management.execute(args: ['nfc', '--disable-all'], connection: peer, confirm: true)
    expect(peer.calls[2]).to include(command: 0x15, data: ['040e020000'].pack('H*'))
    expect(result[:info][:enabled_capabilities]).to eq(usb: 0x23f, nfc: 0)
  end

  it 'sets a configuration lock with secret bytes only in the native request and reads the flag back' do
    locked = encoded.sub(['0a0100'].pack('H*'), ['0a0101'].pack('H*'))
    peer = wire.new([status, encoded, ''.b, locked])
    result = management.execute(args: ['set-lock-code'], connection: peer, confirm: true, new_lock_code: 'L' * 16)
    expect(peer.calls[2][:data]).to eq([18, 10, 16].pack('C*') + ('L' * 16))
    expect(result[:info][:is_locked]).to be(true)
    expect(result[:lock_secret_readback]).to be(false)
    expect(result.to_s).not_to include('L' * 16)
  end

  it 'supplies existing lock through an explicit secret provider and clears protection once' do
    locked = encoded.sub(['0a0100'].pack('H*'), ['0a0101'].pack('H*'))
    provider = instance_double(Proc)
    expect(provider).to receive(:call).with(:lock_code).once.and_return('L' * 16)
    peer = wire.new([status, locked, ''.b, encoded])
    result = management.execute(args: ['set-lock-code', '--clear'], connection: peer, confirm: true, secret_provider: provider)
    expect(result[:info][:is_locked]).to be(false)
    expect(peer.calls[2][:data]).to eq([36, 11, 16].pack('C*') + ('L' * 16) + [10, 16].pack('C*') + ("\0" * 16))
  end

  it 'sets legacy mode using little-endian fields and verifies a fresh USB product descriptor' do
    old_status = [4, 3, 1, 9, 3, 0].pack('C*')
    old_info = encoded.sub(['0503050701'].pack('H*'), ['0503040301'].pack('H*'))
    peer = wire.new([old_status, old_info, ''.b], protocol: :otp, product_id: 0x0407)
    fresh = wire.new([old_status, old_info], protocol: :otp, product_id: 0x0403)
    result = management.execute(args: ['mode', 'OTP+FIDO', '--chalresp-timeout', '15'], connection: peer, confirm: true, reconnect: ->(_identity) { fresh })
    expect(peer.calls.last).to include(command: 0x11, data: [4, 15, 0, 0].pack('C*'))
    expect(result).to include(verified: true, verification: :usb_descriptor, usb_interfaces: 3)
  end

  it 'translates modern mode to capabilities and verifies reboot on a fresh handle' do
    changed = encoded.sub(['0302023f'].pack('H*'), ['03020203'].pack('H*'))
    peer = wire.new([status, encoded, ''.b])
    fresh = wire.new([status, changed])
    result = management.execute(args: ['mode', 'OTP+FIDO'], connection: peer, confirm: true, reconnect: ->(_identity) { fresh })
    expect(peer.calls.last).to include(command: 0x15, data: ['060c0003020203'].pack('H*'))
    expect(result[:reconnected]).to be(true)
    expect(result[:info][:enabled_capabilities][:usb]).to eq(0x203)
  end

  it 'factory-resets only a reported Bio multi-protocol device and verifies reset-state metadata' do
    bio = tlvs.sub(['040181'].pack('H*'), ['040106'].pack('H*')) + ['18021010'].pack('H*')
    cleared = bio.sub(['18021010'].pack('H*'), ['18020000'].pack('H*'))
    before = [bio.bytesize].pack('C') + bio
    after = [cleared.bytesize].pack('C') + cleared
    peer = wire.new(["5.7.1\x90\0".b, before + "\x90\0".b, "\x90\0".b, after + "\x90\0".b], protocol: :apdu)
    result = management.execute(args: ['reset'], connection: peer, confirm: true)
    expect(peer.calls[2][:data]).to eq(['001f000000'].pack('H*'))
    expect(result).to include(verified: true, verification: :reset_state_metadata, data_erasure_verified: false)
    peer = wire.new(["5.7.1\x90\0".b, encoded + "\x90\0".b], protocol: :apdu)
    expect { management.reset(connection: peer, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /supported/)
    expect(peer.calls.length).to eq(2)
  end

  it 'restricts NFC only on 5.7 or later and verifies the actual restriction field' do
    restricted = tlvs + ['170101'].pack('H*')
    peer = wire.new([status, encoded, ''.b, [restricted.bytesize].pack('C') + restricted])
    expect(management.execute(args: ['nfc', '--restrict'], connection: peer, confirm: true)[:info][:nfc_restricted]).to be(true)
    expect(peer.calls[2][:data]).to eq(['03170101'].pack('H*'))
  end

  it 'supports legacy NEO mode switching without fabricating capability metadata' do
    old_status = [3, 4, 1, 9, 3, 0].pack('C*')
    peer = wire.new([old_status, ''.b], protocol: :otp, product_id: 0x0116, serial: '12345678')
    fresh = wire.new([old_status], protocol: :otp, product_id: 0x0114, serial: '12345678')
    result = management.set_mode(connection: peer, mode: 'OTP+FIDO', confirm: true, reconnect: ->(_identity) { fresh })
    expect(result[:info][:supported_capabilities]).to be_empty
    expect(result[:usb_interfaces]).to eq(3)
    expect(peer.calls.last).to include(command: 0x11, data: [4, 0, 0, 0].pack('C*'))
  end

  it 'applies the YubiKey 4.2.4 capability-reporting correction but never trusts its enabled tag' do
    old_status = [4, 2, 4, 9, 3, 0].pack('C*')
    old_info = encoded.sub(['0503050701'].pack('H*'), ['0503040204'].pack('H*')).sub(['0102023f'].pack('H*'), ['01020000'].pack('H*'))
    peer = wire.new([old_status, old_info], protocol: :otp, product_id: 0x0407)
    result = management.info(connection: peer)
    expect(result[:supported_capabilities][:usb]).to eq(0x3f)
    expect(result[:enabled_capabilities]).not_to have_key(:usb)
    expect(result[:usb_interfaces]).to eq(7)
  end

  it 'collects paginated metadata and retains exact additional fields' do
    first = tlvs + ['100101'].pack('H*')
    second = ['1305414243313216010114011115010120030102032103040506'].pack('H*')
    peer = wire.new([status, [first.bytesize].pack('C') + first, [second.bytesize].pack('C') + second])
    result = management.info(connection: peer)
    expect(peer.calls.last[:data]).to eq("\1".b)
    expect(result).to include(part_number: 'ABC12', pin_complexity: true, fps_version: [1, 2, 3], stm_version: [4, 5, 6], fips_capable: 0x300, fips_approved: 0x200)
  end

  it 'requires an explicit reconnection verifier before any reboot write' do
    peer = wire.new([status, encoded])
    expect { management.reboot(connection: peer, confirm: true) }.to raise_error(ArgumentError, /reconnect/i)
    expect(peer.calls.count { |call| call[:command] == 0x15 }).to eq(0)
    peer = wire.new([status, encoded, ''.b])
    fresh = wire.new([status, encoded])
    result = management.reboot(connection: peer, confirm: true, reconnect: ->(_identity) { fresh })
    expect(peer.calls.last[:data]).to eq(['020c00'].pack('H*'))
    expect(result[:reconnected]).to be(true)
  end

  it 'does not silently ignore configuration options or guess absent lock metadata' do
    peer = wire.new([])
    expect { management.configure_usb(connection: peer, confirm: true) }.to raise_error(ArgumentError)
    expect { management.execute(args: ['usb', '--list', '--disable', 'PIV'], connection: peer, confirm: true) }.to raise_error(ArgumentError)
    expect(peer.calls).to be_empty
    missing = tlvs.sub(['0a0100'].pack('H*'), '')
    peer = wire.new([status, [missing.bytesize].pack('C') + missing])
    expect { management.configure_usb(connection: peer, disable: ['PIV'], confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /lock/)
    expect(peer.calls.length).to eq(2)
  end

  it 'uses the NEO OTP applet for smartcard mode commands after management selection' do
    old_status = [3, 4, 1, 9, 3, 0].pack('C*')
    peer = wire.new(["3.4.1\x90\0".b, "\x90\0".b, old_status + "\x90\0".b, "\x90\0".b], protocol: :apdu, serial: '12345678', product_id: 0x0116)
    fresh = wire.new([old_status], protocol: :otp, serial: '12345678', product_id: 0x0114)
    result = management.set_mode(connection: peer, mode: 4, confirm: true, reconnect: ->(_identity) { fresh })
    expect(peer.calls[1][:data]).to eq(['a4040008'].pack('H*'))
    expect(peer.calls[2][:data]).to eq(['00a4040007a0000005272001'].pack('H*'))
    expect(peer.calls[3][:data]).to eq(['000111000404000000'].pack('H*'))
    expect(result[:verified]).to be(true)
  end

  it 'parses qualified development firmware metadata instead of guessing a production version' do
    qualifier = ['190b0103050800020101030107'].pack('H*')
    reported = tlvs.sub(['0503050701'].pack('H*'), ['0503000001'].pack('H*')) + qualifier
    peer = wire.new([[0, 0, 1, 0, 0, 0].pack('C*'), [reported.bytesize].pack('C') + reported])
    result = management.info(connection: peer)
    expect(result[:version]).to eq([5, 8, 0])
    expect(result[:reported_version]).to eq([0, 0, 1])
    expect(result[:version_qualifier]).to eq(version: [5, 8, 0], type: :beta, iteration: 7)
  end

  it 'falls back only for an absent NFC management applet on a legacy NEO' do
    old_status = [3, 4, 1, 9, 3, 0].pack('C*')
    peer = wire.new(["\x6a\x82".b, old_status + "\x90\0".b], protocol: :apdu, transport: :nfc)
    expect(management.info(connection: peer)[:version]).to eq([3, 4, 1])
    expect(peer.calls.last[:data]).to eq(['00a4040007a0000005272001'].pack('H*'))
  end

  it 'rejects ambiguous boolean controls instead of interpreting strings as consented flags' do
    peer = wire.new([])
    expect { management.configure_usb(connection: peer, enable_all: 'false', confirm: true) }.to raise_error(ArgumentError)
    expect { management.set_lock_code(connection: peer, clear: 'false', confirm: true) }.to raise_error(ArgumentError)
    expect(peer.calls).to be_empty
  end

  it 'writes capability settings through actual APDU and CTAP vendor request codecs' do
    changed = encoded.sub(['0302023f'].pack('H*'), ['0302022f'].pack('H*'))
    peer = wire.new(["5.7.1\x90\0".b, encoded + "\x90\0".b, "\x90\0".b, changed + "\x90\0".b], protocol: :apdu)
    expect(management.configure_usb(connection: peer, disable: ['PIV'], confirm: true)[:verified]).to be(true)
    expect(peer.calls[2][:data]).to eq(['001c000005040302022f'].pack('H*'))
    peer = wire.new([encoded, ''.b, changed], protocol: :ctap, version: [5, 7, 1])
    expect(management.configure_usb(connection: peer, disable: ['PIV'], confirm: true)[:verified]).to be(true)
    expect(peer.calls.map { |call| call[:command] }).to eq([0x42, 0x43, 0x42])
    expect(peer.calls[1][:data]).to eq(['040302022f'].pack('H*'))
  end

  it 'does not verify a different serial-less selector after reboot' do
    no_serial = tlvs.sub(['020400bc614e'].pack('H*'), '')
    data = [no_serial.bytesize].pack('C') + no_serial
    peer = wire.new([status, data, ''.b], protocol: :otp, device_path: '/synthetic/key-a')
    fresh = wire.new([status, data], protocol: :otp, device_path: '/synthetic/key-b')
    expect { management.reboot(connection: peer, confirm: true, reconnect: ->(_identity) { fresh }) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /uncertain/)
    expect(peer.calls.count { |call| call[:command] == 0x15 }).to eq(1)
  end

  it 'rejects bad length and duplicate metadata rather than silently overwriting it' do
    peer = wire.new([status, "#{encoded}\0"])
    expect { management.info(connection: peer) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    duplicate = tlvs + ['0503050701'].pack('H*')
    peer = wire.new([status, [duplicate.bytesize].pack('C') + duplicate])
    expect { management.info(connection: peer) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    duplicate = tlvs + ['100101100100'].pack('H*')
    peer = wire.new([status, [duplicate.bytesize].pack('C') + duplicate])
    expect { management.info(connection: peer) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
  end
end
