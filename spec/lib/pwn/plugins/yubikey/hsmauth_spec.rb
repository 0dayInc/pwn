# frozen_string_literal: true

require 'spec_helper'
require 'openssl'

# YubiHSM Auth v5.9.1 protocol fixtures. Keys are synthetic, never hardware captures.
describe 'PWN::Plugins::YubiKey::HSMAuth native protocol' do
  let(:hsmauth) { PWN::Plugins::YubiKey::HSMAuth }
  let(:wire_class) do
    Class.new do
      attr_reader :seen

      def initialize(steps)
        @steps = steps.dup
        @seen = []
      end

      def descriptor
        { protocol: :apdu }
      end

      def exchange(opts = {})
        raise 'wrong transport' unless opts[:protocol] == :apdu

        actual = opts[:data].unpack1('H*')
        @seen << actual
        expected, response = @steps.shift
        raise "unexpected APDU #{actual}" unless actual == expected

        [response].pack('H*')
      end

      def complete?
        @steps.empty?
      end
    end
  end
  let(:select) { %w[00a4040008a000000527210701 79030508009000] }
  let(:management) { 'm' * 16 }
  let(:password) { 'synthetic' }
  let(:entry) { '7207260061636374089000' }

  def field(tag, value)
    (value.bytesize < 128 ? [tag, value.bytesize] : [tag, 0x81, value.bytesize]).pack('C*') + value.b
  end

  def apdu(ins, payload = ''.b, param1: 0, param2: 0)
    ([0, ins, param1, param2] + (payload.empty? ? [] : [payload.bytesize])).pack('C*').unpack1('H*') + payload.unpack1('H*')
  end

  before do
    require 'pwn/plugins/yubikey/protocol'
    require 'pwn/plugins/yubikey/hsmauth'
  end

  it 'lists exact labels, algorithms, touch policies and retry counters' do
    wire = wire_class.new([select, ['0005000000', entry]])
    expect(hsmauth.execute(connection: wire, args: %w[credentials list])).to eq([{ label: 'acct', algorithm: :symmetric, touch: false, retries: 8 }])
    expect(wire.complete?).to be(true)
  end

  it 'imports symmetric keys through the actual raw APDU boundary and verifies metadata' do
    payload = field(0x7b, management) + field(0x71, 'acct') + field(0x74, "\x26") + field(0x75, 'e' * 16) + field(0x76, 'a' * 16) + field(0x73, password.ljust(16, "\x00")) + field(0x7a, "\x00")
    wire = wire_class.new([select, %w[0005000000 9000], [apdu(1, payload), '9000'], ['0005000000', entry]])
    result = hsmauth.execute(connection: wire, args: %w[credentials symmetric acct], key_enc: 'e' * 16, key_mac: 'a' * 16, credential_password: password, management_key: management, confirm: true)
    expect(result).to include(label: 'acct', verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'derives AES keys using the independently calculated PBKDF2 vector' do
    keys = ['6b267091bd381008dacf8eeddd0e3cd7a9cbea9664f5fc538491ce2945fb4991'].pack('H*')
    payload = field(0x7b, management) + field(0x71, 'acct') + field(0x74, "\x26") + field(0x75, keys[0, 16]) + field(0x76, keys[16, 16]) + field(0x73, password.ljust(16, "\x00")) + field(0x7a, "\x00")
    wire = wire_class.new([select, %w[0005000000 9000], [apdu(1, payload), '9000'], ['0005000000', entry]])
    expect(hsmauth.execute(connection: wire, args: %w[credentials derive acct], derivation_password: 'synthetic derive', credential_password: password, management_key: management, confirm: true)).to include(verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'calculates and strictly splits three session keys without exposing them to a process' do
    context = ('H' * 8) + ('C' * 8)
    payload = field(0x71, 'acct') + field(0x77, context) + field(0x78, 'R' * 8) + field(0x73, password.ljust(16, "\x00"))
    wire = wire_class.new([select, [apdu(3, payload), "#{(('E' * 16) + ('M' * 16) + ('R' * 16)).unpack1('H*')}9000"]])
    expect(hsmauth.calculate(connection: wire, label: 'acct', algorithm: :symmetric, context: context, card_crypto: 'R' * 8, credential_password: password, confirm: true)).to eq(key_senc: 'E' * 16, key_smac: 'M' * 16, key_srmac: 'R' * 16)
    expect(wire.complete?).to be(true)
  end

  it 'never assumes the factory management key or invokes a provider without consent' do
    wire = wire_class.new([])
    expect { hsmauth.execute(connection: wire, args: %w[credentials delete acct], secret_provider: ->(_name) { raise 'prompted' }) }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect(wire.seen).to be_empty
  end

  let(:p256_point) { ['046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'].pack('H*') }

  it 'generates an asymmetric key on device using the empty private-key TLV' do
    payload = field(0x7b, management) + field(0x71, 'acct') + field(0x74, "\x27") + field(0x7d, '') + field(0x73, password.ljust(16, "\x00")) + field(0x7a, "\x00")
    wire = wire_class.new([select, %w[0005000000 9000], [apdu(1, payload), '9000'], ['0005000000', entry.sub('2600', '2700')]])
    expect(hsmauth.execute(connection: wire, args: %w[credentials generate acct], management_key: management, credential_password: password, confirm: true)).to include(algorithm: :asymmetric, verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'imports a P-256 private scalar without treating a filename as secret input' do
    scalar = "#{"\x00" * 31}\x01"
    payload = field(0x7b, management) + field(0x71, 'acct') + field(0x74, "\x27") + field(0x7d, scalar) + field(0x73, password.ljust(16, "\x00")) + field(0x7a, "\x00")
    wire = wire_class.new([select, %w[0005000000 9000], [apdu(1, payload), '9000'], ['0005000000', entry.sub('2600', '2700')]])
    expect(hsmauth.execute(connection: wire, args: %w[credentials import acct], private_key: scalar, management_key: management, credential_password: password, confirm: true)).to include(verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'exports validated P-256 public keys as raw points, PEM and DER' do
    %w[RAW PEM DER].each do |format|
      wire = wire_class.new([select, [apdu(10, field(0x71, 'acct')), "#{p256_point.unpack1('H*')}9000"]])
      result = hsmauth.execute(connection: wire, args: ['credentials', 'export', 'acct', '--format', format])
      expect(format == 'RAW' ? result : OpenSSL::PKey.read(result).public_key.to_octet_string(:uncompressed)).to eq(p256_point)
      expect(wire.complete?).to be(true)
    end
  end

  it 'changes the credential password using the old credential password without retry' do
    payload = field(0x71, 'acct') + field(0x73, password.ljust(16, "\x00")) + field(0x73, 'new'.ljust(16, "\x00"))
    wire = wire_class.new([select, [apdu(11, payload), '9000']])
    expect(hsmauth.execute(connection: wire, args: %w[credentials change-password acct], credential_password: password, new_credential_password: 'new', confirm: true)).to include(status: :acknowledged, verification: :not_readable)
    expect(wire.complete?).to be(true)
  end

  it 'changes the credential password with the explicit management authorization mode' do
    payload = field(0x71, 'acct') + field(0x7b, management) + field(0x73, 'new'.ljust(16, "\x00"))
    wire = wire_class.new([select, [apdu(11, payload, param1: 1), '9000']])
    expect(hsmauth.execute(connection: wire, args: %w[credentials change-password acct], management_key: management, new_credential_password: 'new', confirm: true)).to include(status: :acknowledged)
    expect(wire.complete?).to be(true)
  end

  it 'changes management keys and padded passwords without assuming a default' do
    payload = field(0x7b, management) + field(0x7b, 'n' * 16)
    wire = wire_class.new([select, [apdu(8, payload), '9000']])
    expect(hsmauth.execute(connection: wire, args: %w[access change-management-key], management_key: management, new_management_key: 'n' * 16, confirm: true)).to include(status: :acknowledged)
    expect(wire.complete?).to be(true)
    payload = field(0x7b, 'old'.ljust(16, "\x00")) + field(0x7b, 'new'.ljust(16, "\x00"))
    wire = wire_class.new([select, [apdu(8, payload), '9000']])
    expect(hsmauth.execute(connection: wire, args: %w[access change-management-password], management_password: 'old', new_management_password: 'new', confirm: true)).to include(status: :acknowledged)
    expect(wire.complete?).to be(true)
  end

  it 'resets with DEAD confirmation bytes and verifies empty inventory' do
    wire = wire_class.new([select, %w[0006dead00 9000], select, %w[0005000000 9000], %w[0009000000 089000]])
    expect(hsmauth.execute(connection: wire, args: ['reset'], confirm: true)).to include(verified: true)
    expect(wire.complete?).to be(true)
  end

  it 'reads application version and management retry status without credentials' do
    wire = wire_class.new([select, %w[0009000000 059000]])
    expect(hsmauth.execute(connection: wire, args: ['info'])).to include(version: [5, 8, 0], management_key_retries: 5)
    expect(wire.complete?).to be(true)
  end

  it 'retains a selected session between asymmetric challenge and session-key calculation' do
    context = p256_point + p256_point
    challenge_payload = field(0x71, 'acct') + field(0x73, password.ljust(16, "\x00"))
    payload = field(0x71, 'acct') + field(0x77, context) + field(0x7c, p256_point) + field(0x78, 'R' * 16) + field(0x73, password.ljust(16, "\x00"))
    wire = wire_class.new([select, [apdu(4, challenge_payload), "#{p256_point.unpack1('H*')}9000"], [apdu(3, payload), "#{'01' * 48}9000"]])
    session = hsmauth.open_session(connection: wire)
    expect(hsmauth.challenge(session: session, label: 'acct', algorithm: :asymmetric, credential_password: password, confirm: true)).to eq(p256_point)
    expect(hsmauth.calculate(session: session, label: 'acct', algorithm: :asymmetric, context: context, public_key: p256_point, card_crypto: 'R' * 16, credential_password: password, confirm: true)).to include(key_senc: "\x01" * 16)
    expect(wire.complete?).to be(true)
  end

  it 'deletes an exact label with management authorization and verifies absence' do
    payload = field(0x7b, management) + field(0x71, 'acct')
    wire = wire_class.new([select, ['0005000000', entry], [apdu(2, payload), '9000'], %w[0005000000 9000]])
    expect(hsmauth.execute(connection: wire, args: %w[credentials delete acct], management_key: management, confirm: true)).to include(deleted: 'acct', verified: true)
    expect(wire.complete?).to be(true)
    wire = wire_class.new([select, ['0005000000', entry]])
    expect { hsmauth.execute(connection: wire, args: %w[credentials delete acc], management_key: management, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /exact/)
    expect(wire.complete?).to be(true)
  end

  it 'reports wrong credentials once without trying a default or another password' do
    payload = field(0x71, 'acct') + field(0x77, 'c' * 16) + field(0x73, password.ljust(16, "\x00"))
    wire = wire_class.new([select, [apdu(3, payload), '63c7']])
    expect { hsmauth.calculate(connection: wire, label: 'acct', context: 'c' * 16, credential_password: password, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::Protocol::APDUError) { |error| expect(error.status).to eq(0x63c7) }
    expect(wire.complete?).to be(true)
  end

  it 'rejects malformed session-key output instead of returning partial keys' do
    payload = field(0x71, 'acct') + field(0x77, 'c' * 16) + field(0x73, password.ljust(16, "\x00"))
    wire = wire_class.new([select, [apdu(3, payload), "#{'00' * 47}9000"]])
    expect { hsmauth.calculate(connection: wire, label: 'acct', context: 'c' * 16, credential_password: password, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /exactly/)
    expect(wire.complete?).to be(true)
  end

  it 'gates asymmetric and password-changing commands on the selected version' do
    old = [select[0], '79030504039000']
    wire = wire_class.new([old])
    expect { hsmauth.execute(connection: wire, args: %w[credentials generate acct], management_key: management, credential_password: password, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::Error, /unsupported/)
    wire = wire_class.new([old])
    expect { hsmauth.execute(connection: wire, args: %w[credentials change-password acct], credential_password: password, new_credential_password: 'new', confirm: true) }.to raise_error(PWN::Plugins::YubiKey::Error, /unsupported/)
    expect(wire.complete?).to be(true)
  end

  it 'refuses missing management credentials and malformed private keys without I/O' do
    wire = wire_class.new([])
    expect { hsmauth.execute(connection: wire, args: %w[credentials delete acct], confirm: true) }.to raise_error(ArgumentError, /management_key/)
    expect { hsmauth.execute(connection: wire, args: %w[credentials import acct], private_key: "\x00" * 32, management_key: management, credential_password: password, confirm: true) }.to raise_error(ArgumentError, /scalar/)
    expect(wire.seen).to be_empty
  end

  it 'gets a symmetric challenge without guessing a credential password' do
    wire = wire_class.new([select, [apdu(4, field(0x71, 'acct')), '01020304050607089000']])
    expect(hsmauth.challenge(connection: wire, label: 'acct', confirm: true)).to eq(['0102030405060708'].pack('H*'))
    expect(wire.complete?).to be(true)
  end

  it 'documents every public API and secret option in actual help output' do
    expect { hsmauth.help }.to output(/\.execute\(.*new_credential_password:.*management_key:.*\.operations.*\.open_session\(.*\.challenge\(.*\.calculate\(.*public_key:.*\.authors/m).to_stdout
  end

  it 'keeps groups local and rejects secret argv even with confirmation' do
    wire = wire_class.new([])
    expect(hsmauth.execute(connection: wire, args: ['credentials'])).to include(application: :hsmauth)
    expect { hsmauth.execute(connection: wire, args: %w[credentials generate acct --management-key secret], confirm: true) }.to raise_error(ArgumentError)
    expect(wire.seen).to be_empty
  end

  it 'does not silently change an explicit credential authentication mode' do
    wire = wire_class.new([])
    expect { hsmauth.execute(connection: wire, args: %w[credentials change-password acct], auth_method: :credential, management_key: management, new_credential_password: 'new', confirm: true) }.to raise_error(ArgumentError, /conflict/)
    expect { hsmauth.execute(connection: wire, args: %w[credentials symmetric acct], generate: 'false', confirm: true) }.to raise_error(ArgumentError, /boolean/)
    expect(wire.seen).to be_empty
  end

  it 'validates all public calculation arguments before credentials or I/O' do
    wire = wire_class.new([])
    expect { hsmauth.calculate(connection: wire, label: 'acct', algorithm: :symmetric, context: 'short', credential_password: password, confirm: true) }.to raise_error(ArgumentError)
    expect(wire.seen).to be_empty
  end
end
