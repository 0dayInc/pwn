# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/yubikey/fido'

# The only fake boundary is Connection#exchange. Crypto inside the fake is
# independently implemented with OpenSSL KDF/AES, not FIDO::PinProtocol.
class FidoFixtureConnection
  attr_reader :calls, :descriptor, :token
  attr_accessor :info, :fail_code, :handler, :app_handler

  def initialize(version: 2, options: {}, descriptor: { protocol: :ctap })
    @descriptor = descriptor
    @calls = []
    @version = version
    @token = 't'.b * 32
    @private_key = OpenSSL::PKey::EC.generate('prime256v1')
    @info = { 1 => ['FIDO_2_1'], 3 => "\x00".b * 16, 4 => { 'clientPin' => true, 'pinUvAuthToken' => true }.merge(options), 5 => 4096, 6 => [version], 13 => 4 }
  end

  def exchange(opts = {})
    @calls << opts
    return @handler.call(opts) if @handler

    raise 'Unexpected HID command' unless opts[:protocol] == :ctap && opts[:command] == 0x10

    command = opts[:data].getbyte(0)
    payload = opts[:data].bytesize > 1 ? PWN::Plugins::YubiKey::FIDO::CBOR.decode(data: opts[:data].byteslice(1..)) : {}
    response = case command
               when 4 then @info
               when 7 then {}
               when 6 then client_pin(payload)
               else
                 raise "Unexpected CTAP command #{command}" unless @app_handler

                 @app_handler.call(command, payload)
               end
    return [response].pack('C') if response.is_a?(Integer)

    "\x00".b + (response.empty? ? ''.b : PWN::Plugins::YubiKey::FIDO::CBOR.encode(value: response))
  end

  def client_pin(payload)
    case payload[2]
    when 1 then { 3 => 8, 4 => false }
    when 7 then { 5 => 5 }
    when 2
      pub = @private_key.public_key.to_octet_string(:uncompressed)
      { 1 => { 1 => 2, 3 => -25, -1 => 1, -2 => pub.byteslice(1, 32), -3 => pub.byteslice(33, 32) } }
    when 3, 4, 5, 6, 9
      return @fail_code if @fail_code

      peer = payload.fetch(3)
      point = OpenSSL::PKey::EC::Point.new(@private_key.group, OpenSSL::BN.new("\x04".b + peer[-2] + peer[-3], 2))
      z = @private_key.dh_compute_key(point)
      secret = if @version == 1
                 OpenSSL::Digest::SHA256.digest(z)
               else
                 ['CTAP2 HMAC key', 'CTAP2 AES key'].map { |info| OpenSSL::KDF.hkdf(z, salt: "\x00".b * 32, info: info, length: 32, hash: 'SHA256') }.join.b
               end
      raise 'Incorrect PIN encryption' if payload[6] && decrypt(secret, payload[6]) != OpenSSL::Digest.digest('SHA256', '123456').byteslice(0, 16)

      if [3, 4].include?(payload[2])
        raise 'Incorrect new PIN encryption' unless decrypt(secret, payload[5]) == '654321'.b.ljust(64, "\x00".b)

        message = payload[5] + (payload[6] || ''.b)
        raise 'Incorrect PIN MAC' unless payload[4] == mac(secret, message)

        {}
      else
        { 2 => encrypt(secret, @token) }
      end
    else raise 'Unexpected ClientPIN subcommand'
    end
  end

  def mac(key, message)
    result = OpenSSL::HMAC.digest('SHA256', @version == 1 ? key : key.byteslice(0, 32), message)
    @version == 1 ? result.byteslice(0, 16) : result
  end

  def encrypt(key, plain)
    iv = @version == 1 ? "\x00".b * 16 : 'i'.b * 16
    result = crypt(key, iv, plain, true)
    @version == 1 ? result : iv + result
  end

  def decrypt(key, data)
    iv = @version == 1 ? "\x00".b * 16 : data.byteslice(0, 16)
    crypt(key, iv, @version == 1 ? data : data.byteslice(16..), false)
  end

  def crypt(key, iv_bytes, data, encrypt)
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    encrypt ? cipher.encrypt : cipher.decrypt
    cipher.padding = 0
    cipher.key = @version == 1 ? key : key.byteslice(32, 32)
    cipher.iv = iv_bytes
    cipher.update(data) + cipher.final
  end
end

RSpec.describe 'Native YubiKey FIDO capability and PIN paths' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }

  it 'returns local help for each old group without touching a connection' do
    [[], ['access'], ['credentials'], ['fingerprints'], ['config']].each do |args|
      expect(fido.execute(args: args)).to include(:operations)
    end
  end

  it 'reads getInfo on a serial-less Security Key and resets once with literal consent' do
    connection = FidoFixtureConnection.new
    result = fido.execute(connection: connection, args: ['info'])
    expect(result[:versions]).to eq(['FIDO_2_1'])
    expect(result[:options]['clientPin']).to be(true)
    expect(connection.calls.first[:data]).to eq("\x04".b)
    expect { fido.execute(connection: connection, args: ['reset'], confirm: 'true') }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    fido.execute(connection: connection, args: ['reset'], confirm: true)
    expect(connection.calls.count { |call| call[:data] == "\x07".b }).to eq(1)
  end

  [1, 2].each do |version|
    it "sets, changes and verifies PIN with actual protocol #{version} ECDH/AES/MAC" do
      connection = FidoFixtureConnection.new(version: version)
      fido.execute(connection: connection, args: %w[access change-pin], pin: '123456', new_pin: '654321', confirm: true)
      expect(fido.execute(connection: connection, args: %w[access verify-pin], pin: '123456', confirm: true)).to eq({ verified: true })
      connection.info[4]['clientPin'] = false
      expect(fido.execute(connection: connection, args: %w[access change-pin], new_pin: '654321', confirm: true)).to eq({ changed: true, initialized: true })
    end
  end

  it 'does not retry a wrong PIN, reveal secrets, invoke a provider before consent or accept secret argv' do
    connection = FidoFixtureConnection.new
    connection.fail_code = 0x31
    expect { fido.execute(connection: connection, args: %w[access verify-pin], pin: '123456', confirm: true) }.to raise_error(fido::CTAPError) { |e|
      expect(e.code).to eq(0x31)
      expect(e.message).not_to include('123456')
    }
    attempts = connection.calls.count { |call| call[:data].start_with?("\x06".b) }
    expect(attempts).to eq(2)
    provider = ->(_name) { raise 'Provider must not be invoked' }
    expect { fido.execute(connection: connection, args: %w[access change-pin], secret_provider: provider) }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect { fido.execute(connection: connection, args: %w[access verify-pin --pin 123456], confirm: true) }.to raise_error(ArgumentError)
  end

  it 'reports U2F-only capabilities honestly and rejects unsupported CTAP2 management' do
    connection = FidoFixtureConnection.new(descriptor: { protocol: :ctap, capabilities: 1 })
    connection.handler = lambda do |request|
      expect(request[:command]).to eq(3)
      expect(request[:data]).to eq(['000300000000000000'].pack('H*'))
      'U2F_V2'.b + "\x90\x00".b
    end
    expect(fido.execute(connection: connection, args: ['info'])).to include(versions: ['U2F_V2'], ctap2: false, options: {})
    expect { fido.execute(connection: connection, args: %w[credentials list], confirm: true, pin: '123456') }.to raise_error(fido::UnsupportedError)
  end

  it 'propagates keepalive cancellation and malformed responses without retries' do
    connection = FidoFixtureConnection.new
    count = 0
    connection.handler = lambda { |request|
      count += 1
      request[:on_keepalive]&.call(2)
      "\x00".b
    }
    expect { fido.execute(connection: connection, args: ['reset'], confirm: true, on_keepalive: ->(_status) { raise Interrupt }) }.to raise_error(Interrupt)
    expect(count).to eq(1)
    connection.handler = ->(_request) { ''.b }
    expect { fido.execute(connection: connection, args: ['info']) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
  end
end

RSpec.describe 'Native YubiKey FIDO credential and config paths' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }
  let(:connection) { FidoFixtureConnection.new(options: { 'credMgmt' => true, 'authnrCfg' => true, 'setMinPINLength' => true, 'alwaysUv' => false, 'ep' => false }) }
  let(:options) { { connection: connection, pin: '123456', confirm: true } }

  def payloads
    connection.calls.filter_map { |call| fido::CBOR.decode(data: call[:data].byteslice(1..)) if call[:data].getbyte(0) == 6 }
  end

  it 'enumerates every RP and credential with authenticated begins and unauthenticated nexts' do
    expected_subcommands = [1, 2, 3, 4, 5, 4]
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(10)
      subcommand = expected_subcommands.shift
      expect(params[1]).to eq(subcommand)
      if [3, 5].include?(subcommand)
        expect(params).to eq({ 1 => subcommand })
      else
        msg = [subcommand].pack('C') + (params[2] ? fido::CBOR.encode(value: params[2]) : ''.b)
        expect(params[3]).to eq(2)
        expect(params[4]).to eq(connection.mac(connection.token, msg))
      end
      case subcommand
      when 1 then { 1 => 3, 2 => 22 }
      when 2 then { 3 => { 'id' => 'first.example' }, 4 => 'a'.b * 32, 5 => 2 }
      when 3 then { 3 => { 'id' => 'second.example' }, 4 => 'b'.b * 32 }
      when 4
        { 6 => { 'id' => 'user'.b, 'name' => 'Example' }, 7 => { 'id' => params[2][1].byteslice(0, 1), 'type' => 'public-key' }, 8 => { 1 => 2 }, 9 => params[2][1].start_with?('a') ? 2 : 1 }
      when 5 then { 6 => { 'id' => 'user2'.b }, 7 => { 'id' => 'c'.b, 'type' => 'public-key' }, 8 => { 1 => 2 } }
      end
    end
    result = fido.execute(options.merge(args: %w[credentials list]))
    expect(result[:credentials].map { |cred| cred[:credential]['id'] }).to eq(%w[a c b])
    expect(result[:relying_parties].size).to eq(2)
    expect(expected_subcommands).to be_empty
    expect(payloads.find { |payload| payload[2] == 9 }[9]).to eq(4)
  end

  it 'deletes an exact credential and updates the original user ID with authenticated canonical parameters' do
    id = 'credential'.b
    expected = [6, 7]
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(10)
      expect(params[1]).to eq(expected.shift)
      expect(params[2][2]).to eq({ 'id' => id, 'type' => 'public-key' })
      expect(params[4]).to eq(connection.mac(connection.token, [params[1]].pack('C') + fido::CBOR.encode(value: params[2])))
      expect(params[2][3]).to eq({ 'id' => 'original'.b, 'name' => 'new name', 'displayName' => 'Display' }) if params[1] == 7
      {}
    end
    expect(fido.execute(options.merge(args: ['credentials', 'delete', id.unpack1('H*')]))).to eq({ deleted: true })
    expect(fido.perform(options.merge(operation: :update_credential, credential_id: id, user: { 'id' => 'original'.b, 'name' => 'new name', 'displayName' => 'Display' }))).to eq({ updated: true })
    expect(expected).to be_empty
  end

  it 'supports preview credential management but rejects update and malformed IDs before authentication' do
    connection.info[1] = ['FIDO_2_1_PRE']
    connection.info[4].delete('credMgmt')
    connection.info[4]['credentialMgmtPreview'] = true
    connection.info[4]['pinUvAuthToken'] = false
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(0x41)
      params[1] == 1 ? { 1 => 0, 2 => 25 } : 0x2e
    end
    expect(fido.execute(options.merge(args: %w[credentials list]))[:credentials]).to be_empty
    expect(payloads.any? { |payload| payload[2] == 5 && !payload.key?(9) }).to be(true)
    expect { fido.perform(options.merge(operation: :update_credential, credential_id: 'a'.b, user: { 'id' => 'u'.b })) }.to raise_error(fido::UnsupportedError)
    count = connection.calls.size
    expect { fido.execute(options.merge(args: %w[credentials delete not-hex])) }.to raise_error(ArgumentError)
    expect(connection.calls.size).to eq(count)
  end

  it 'rejects inconsistent enumeration totals rather than claiming a partial list is complete' do
    connection.app_handler = ->(_command, params) { params[1] == 1 ? { 1 => 2, 2 => 2 } : 0x2e }
    expect { fido.execute(options.merge(args: %w[credentials list])) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /count/)
  end

  it 'signs all configuration commands with the ff32 and 0d domain separator' do
    connection.info[16] = 2
    subcommands = [3, 3, 2, 1]
    expected_parameters = [{ 3 => true }, { 1 => 6, 2 => %w[first.example second.example], 3 => false }, nil, nil]
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(13)
      expect(params[1]).to eq(subcommands.shift)
      expected_params = expected_parameters.shift
      expect(params[2]).to eq(expected_params)
      message = ("\xff".b * 32) + "\x0d".b + [params[1]].pack('C') + (expected_params ? fido::CBOR.encode(value: expected_params) : ''.b)
      expect(params[4]).to eq(connection.mac(connection.token, message))
      {}
    end
    [%w[access force-change], %w[access set-min-length 6 --rp-id first.example --rp-id second.example], %w[config toggle-always-uv], %w[config enable-ep-attestation]].each do |args|
      expect(fido.execute(options.merge(args: args))).to include(configured: true)
    end
    expect(subcommands).to be_empty
    expect(payloads.select { |payload| payload[2] == 9 }.map { |payload| payload[9] }.uniq).to eq([32])
  end

  it 'uses no fake PIN when configuration is allowed before a PIN is set' do
    connection.info[4]['clientPin'] = false
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(13)
      expect(params).to eq({ 1 => 2 })
      {}
    end
    expect(fido.execute(options.merge(args: %w[config toggle-always-uv], pin: nil))).to include(configured: true)
    expect(payloads).to be_empty
  end
end

RSpec.describe 'Native YubiKey FIDO fingerprint paths' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }
  let(:connection) { FidoFixtureConnection.new(options: { 'bioEnroll' => false }) }
  let(:options) { { connection: connection, pin: '123456', confirm: true } }

  def bio_reply(command, params)
    expect(command).to eq(9)
    return { 1 => 1 } if params[6]
    return { 2 => 1, 3 => 4, 8 => 20 } if params[2] == 7

    expect(params[1]).to eq(1)
    unless params[2] == 3
      expect(params[4]).to eq(2)
      msg = [1, params[2]].pack('CC') + (params[3] ? fido::CBOR.encode(value: params[3]) : ''.b)
      expect(params[5]).to eq(connection.mac(connection.token, msg))
    end
    yield params[2], params[3]
  end

  it 'lists, renames and deletes templates with permission 08 and exact identifiers' do
    commands = [4, 5, 6]
    connection.app_handler = lambda do |command, params|
      bio_reply(command, params) do |subcommand, values|
        expect(subcommand).to eq(commands.shift)
        expect(values).to eq({ 1 => 't'.b, 2 => 'index finger' }) if subcommand == 5
        expect(values).to eq({ 1 => 't'.b }) if subcommand == 6
        subcommand == 4 ? { 7 => [{ 1 => 't'.b, 2 => 'thumb' }] } : {}
      end
    end
    expect(fido.execute(options.merge(args: %w[fingerprints list]))).to eq([{ template_id: 't'.b, name: 'thumb' }])
    expect(fido.execute(options.merge(args: ['fingerprints', 'rename', '74', 'index finger']))).to eq({ renamed: true })
    expect(fido.execute(options.merge(args: %w[fingerprints delete 74]))).to eq({ deleted: true })
    requests = connection.calls.select { |call| call[:data].getbyte(0) == 6 }.map { |call| fido::CBOR.decode(data: call[:data].byteslice(1..)) }
    expect(requests.select { |req| req[2] == 9 }.map { |req| req[9] }.uniq).to eq([8])
    expect(commands).to be_empty
  end

  it 'enrolls bounded samples with authenticated capture-next and assigns the final friendly name' do
    commands = [1, 2, 2, 5]
    samples = []
    connection.app_handler = lambda do |command, params|
      bio_reply(command, params) do |subcommand, values|
        expect(subcommand).to eq(commands.shift)
        case subcommand
        when 1
          expect(values).to eq({ 3 => 1000 })
          { 4 => 't'.b, 5 => 0, 6 => 1 }
        when 2
          expect(values).to eq({ 1 => 't'.b, 3 => 1000 })
          commands == [2, 5] ? { 5 => 7, 6 => 1 } : { 5 => 0, 6 => 0 }
        when 5 then {}
        end
      end
    end
    result = fido.execute(options.merge(args: %w[fingerprints add index], capture_timeout_ms: 1000, on_sample: ->(sample) { samples << sample }))
    expect(result).to include(enrolled: true, template_id: 't'.b, name: 'index')
    expect(samples.map { |sample| sample[:status] }).to eq([0, 7, 0])
    expect(commands).to be_empty
  end

  it 'cancels a partial enrollment exactly once on callback interruption without masking the original failure' do
    cancels = 0
    connection.app_handler = lambda do |command, params|
      bio_reply(command, params) do |subcommand, _values|
        case subcommand
        when 1 then { 4 => 't'.b, 5 => 0, 6 => 1 }
        when 3
          cancels += 1
          expect(params).to eq({ 1 => 1, 2 => 3 })
          {}
        else raise 'Unexpected enrollment retry'
        end
      end
    end
    expect { fido.execute(options.merge(args: %w[fingerprints add], on_sample: ->(_sample) { raise Interrupt })) }.to raise_error(Interrupt)
    expect(cancels).to eq(1)
  end

  it 'cancels enrollment explicitly with consent and no PIN token' do
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(9)
      expect(params).to eq({ 1 => 1, 2 => 3 })
      {}
    end
    expect(fido.perform(connection: connection, operation: :cancel_enrollment, confirm: true)).to eq({ cancelled: true })
    expect(connection.calls.none? { |call| call[:data].getbyte(0) == 6 }).to be(true)
  end

  it 'supports preview enrollment and sensor information without attempting a PIN' do
    connection.info[1] = ['FIDO_2_1_PRE']
    connection.info[4].delete('bioEnroll')
    connection.info[4]['userVerificationMgmtPreview'] = false
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(0x40)
      params[6] ? { 1 => 1 } : { 2 => 1, 3 => 4, 8 => 20 }
    end
    expect(fido.perform(connection: connection, operation: :bio_sensor_info)).to include(max_samples: 4, max_name_bytes: 20)
    expect(connection.calls.none? { |call| call[:data].getbyte(0) == 6 }).to be(true)
  end
end

RSpec.describe 'Native YubiKey FIDO operational APIs' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }
  let(:connection) { FidoFixtureConnection.new }
  let(:hash) { 'h'.b * 32 }
  let(:options) { { connection: connection, confirm: true, pin: '123456', client_data_hash: hash } }
  let(:auth_data) { ('r'.b * 32) + [1, 12].pack('CN') }

  it 'makes credentials with caller-supplied RP/hash and permission 01 scoped to that RP' do
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(1)
      expect(params[1]).to eq(hash)
      expect(params[2]).to eq({ 'id' => 'login.example', 'name' => 'Example' })
      expect(params[3]).to eq({ 'id' => 'user'.b, 'name' => 'alice' })
      expect(params[4]).to eq([{ 'type' => 'public-key', 'alg' => -7 }])
      expect(params[8]).to eq(connection.mac(connection.token, hash))
      expect(params[9]).to eq(2)
      { 1 => 'packed', 2 => auth_data, 3 => { 'alg' => -7, 'sig' => 'signature'.b } }
    end
    result = fido.make_credential(options.merge(rp: { 'id' => 'login.example', 'name' => 'Example' }, user: { 'id' => 'user'.b, 'name' => 'alice' }))
    expect(result).to include(format: 'packed', authenticator_data: auth_data)
    request = connection.calls.filter_map { |call| fido::CBOR.decode(data: call[:data].byteslice(1..)) if call[:data].getbyte(0) == 6 }.find { |entry| entry[2] == 9 }
    expect(request.values_at(9, 10)).to eq([1, 'login.example'])
  end

  it 'gets all advertised assertions with permission 02 and handles built-in UV token negotiation' do
    connection.info[4]['uv'] = true
    expected = [2, 8]
    connection.app_handler = lambda do |command, params|
      expect(command).to eq(expected.shift)
      if command == 2
        expect(params[1]).to eq('login.example')
        expect(params[2]).to eq(hash)
        expect(params[6]).to eq(connection.mac(connection.token, hash))
        expect(params[7]).to eq(2)
      else
        expect(params).to be_empty
      end
      { 1 => { 'type' => 'public-key', 'id' => 'cred'.b }, 2 => auth_data, 3 => 'sig'.b, 5 => 2 }
    end
    result = fido.get_assertion(options.merge(pin: nil, uv: true, rp_id: 'login.example'))
    expect(result.size).to eq(2)
    expect(result.first).to include(authenticator_data: auth_data, signature: 'sig'.b)
    request = connection.calls.filter_map { |call| fido::CBOR.decode(data: call[:data].byteslice(1..)) if call[:data].getbyte(0) == 6 }.find { |entry| entry[2] == 6 }
    expect(request.values_at(9, 10)).to eq([2, 'login.example'])
    expect(request).not_to have_key(6)
  end

  it 'rejects missing RP/hash, textual IDs and oversized inputs before device authentication' do
    expect { fido.make_credential(options.merge(rp: {}, user: { 'id' => 'user'.b })) }.to raise_error(ArgumentError)
    expect { fido.get_assertion(options.merge(client_data_hash: nil, rp_id: 'login.example')) }.to raise_error(ArgumentError)
    expect { fido.get_assertion(options.merge(rp_id: 'login.example', allow_list: [{ 'id' => 'not-binary', 'type' => 'public-key' }])) }.to raise_error(ArgumentError)
    expect(connection.calls).to be_empty
  end

  it 'registers U2F and parses the raw credential and certificate without fabricating clientData' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=Synthetic fixture')
    cert.public_key = key
    cert.not_before = Time.at(0)
    cert.not_after = Time.at(1)
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    pub = key.public_key.to_octet_string(:uncompressed)
    connection.handler = lambda do |request|
      expect(request[:command]).to eq(3)
      expect(request[:data]).to eq(['00010000000040'].pack('H*') + hash + ('a'.b * 32) + "\x00\x00".b)
      "\x05".b + pub + "\x03".b + 'key'.b + cert.to_der + 'signature'.b + "\x90\x00".b
    end
    result = fido.u2f_register(options.merge(app_id_hash: 'a'.b * 32))
    expect(result).to include(public_key: pub, key_handle: 'key'.b, certificate: cert.to_der, signature: 'signature'.b)
  end

  it 'authenticates and checks U2F key handles using exact extended APDU vectors without retrying touch errors' do
    connection.handler = lambda do |request|
      expect(request[:data].byteslice(0, 7)).to eq(['00020300000044'].pack('H*'))
      expect(request[:data].byteslice(7, 68)).to eq(hash + ('a'.b * 32) + "\x03key".b)
      "\x01\x00\x00\x00\x09signature\x90\x00".b
    end
    expect(fido.u2f_authenticate(options.merge(app_id_hash: 'a'.b * 32, key_handle: 'key'.b))).to include(user_presence: 1, counter: 9, signature: 'signature'.b)
    connection.handler = lambda do |request|
      expect(request[:data].getbyte(2)).to eq(7)
      "\x69\x85".b
    end
    expect(fido.u2f_authenticate(options.merge(app_id_hash: 'a'.b * 32, key_handle: 'key'.b, check_only: true))).to eq({ recognized: true })
    connection.handler = ->(_request) { "\x69\x85".b }
    before = connection.calls.size
    expect { fido.u2f_authenticate(options.merge(app_id_hash: 'a'.b * 32, key_handle: 'key'.b)) }.to raise_error(fido::APDUError)
    expect(connection.calls.size).to eq(before + 1)
  end
end

RSpec.describe 'Native YubiKey FIDO smartcard and FIPS paths' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }

  it 'selects the FIDO AID and reads CTAP2 over NFC/PCSC with GET RESPONSE chaining' do
    connection = FidoFixtureConnection.new(descriptor: { protocol: :apdu })
    encoded_info = "\x00".b + fido::CBOR.encode(value: connection.info)
    calls = 0
    connection.handler = lambda do |request|
      expect(request[:protocol]).to eq(:apdu)
      calls += 1
      case calls
      when 1
        expect(request[:data]).to eq(['00a4040008a0000006472f000100'].pack('H*'))
        'FIDO_2_0'.b + "\x90\x00".b
      when 2
        expect(request[:data]).to eq(['80108000010400'].pack('H*'))
        encoded_info.byteslice(0, 12) + "\x61\x00".b
      when 3
        expect(request[:data]).to eq(['00c0000000'].pack('H*'))
        encoded_info.byteslice(12..) + "\x90\x00".b
      end
    end
    expect(fido.execute(connection: connection, args: ['info'])[:ctap2]).to be(true)
    expect(calls).to eq(3)
  end

  it 'handles NFC keepalive and sends NFC cancellation when the callback interrupts' do
    connection = FidoFixtureConnection.new(descriptor: { protocol: :apdu })
    calls = 0
    connection.handler = lambda do |request|
      calls += 1
      case request[:data].byteslice(0, 2)
      when "\x00\xa4".b then 'FIDO_2_0'.b + "\x90\x00".b
      when "\x80\x10".b
        if request[:data].getbyte(5) == 4
          "\x00".b + fido::CBOR.encode(value: connection.info) + "\x90\x00".b
        else
          "\x02\x91\x00".b
        end
      when "\x80\x11".b
        expect(request[:data]).to eq(['8011110000'].pack('H*'))
        "\x2d\x90\x00".b
      else raise 'Unexpected APDU'
      end
    end
    expect { fido.execute(connection: connection, args: ['reset'], confirm: true, on_keepalive: ->(_status) { raise Interrupt }) }.to raise_error(Interrupt)
    expect(calls).to eq(4)
  end

  it 'performs YubiKey 4 FIPS U2F PIN change, verification and one-shot reset without a CTAP2 stub' do
    connection = FidoFixtureConnection.new(descriptor: { protocol: :ctap, capabilities: 1 })
    mutation_ins = []
    connection.handler = lambda do |request|
      expect(request[:command]).to eq(3)
      ins = request[:data].getbyte(1)
      length = request[:data].byteslice(5, 2).unpack1('n')
      data = request[:data].byteslice(7, length)
      case ins
      when 3 then 'U2F_V2'.b + "\x90\x00".b
      when 0x46 then "\x90\x00".b
      when 0x43
        expect(data).to eq('123456')
        mutation_ins << ins
        "\x90\x00".b
      when 0x44
        expect(data).to eq("#{"\x06".b}123456654321")
        mutation_ins << ins
        "\x90\x00".b
      when 0x45
        mutation_ins << ins
        "\x69\x85".b
      else raise 'Unexpected FIPS command'
      end
    end
    opts = { connection: connection, pin: '123456', new_pin: '654321', confirm: true }
    expect(fido.execute(opts.merge(args: %w[access change-pin --u2f]))).to include(changed: true)
    expect(fido.execute(opts.merge(args: %w[access verify-pin]))).to eq({ verified: true })
    expect { fido.execute(opts.merge(args: ['reset'])) }.to raise_error(fido::APDUError) { |e| expect(e.code).to eq(0x6985) }
    expect(mutation_ins).to eq([0x44, 0x43, 0x45])
  end
end

RSpec.describe 'Native YubiKey FIDO boundary regressions' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }

  it 'uses capabilities learned during HID INIT to recognize legacy U2F-only keys' do
    connection = FidoFixtureConnection.new
    connection.handler = lambda do |request|
      if request[:command] == 16
        connection.descriptor[:capabilities] = 1
        raise PWN::Plugins::YubiKey::CommandError, 'CTAPHID invalid command'
      end
      'U2F_V2'.b + "\x90\x00".b
    end
    expect(fido.execute(connection: connection, args: ['info'])[:versions]).to eq(['U2F_V2'])
  end

  it 'passes cancellation to the transport for a blocked read with no keepalive' do
    connection = FidoFixtureConnection.new
    cancelled = -> { false }
    connection.handler = lambda do |request|
      expect(request[:cancelled]).to equal(cancelled)
      raise PWN::Plugins::YubiKey::TimeoutError, 'synthetic timeout'
    end
    expect { fido.execute(connection: connection, args: ['info'], cancelled: cancelled) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(connection.calls.size).to eq(1)
  end

  it 'does not turn a ClientPIN invalid-option response into an empty fingerprint list' do
    connection = FidoFixtureConnection.new(options: { 'bioEnroll' => true })
    connection.fail_code = 0x2c
    connection.app_handler = ->(_command, params) { params[6] ? { 1 => 1 } : { 2 => 1, 3 => 4 } }
    expect { fido.execute(connection: connection, args: %w[fingerprints list], pin: '123456', confirm: true) }.to raise_error(fido::CTAPError)
  end

  it 'preserves a completed enrollment identifier if friendly naming fails, without deleting it' do
    connection = FidoFixtureConnection.new(options: { 'bioEnroll' => false })
    subcommands = []
    connection.app_handler = lambda do |_command, params|
      next({ 1 => 1 }) if params[6]

      subcommands << params[2]
      case params[2]
      when 7 then { 2 => 1, 3 => 4 }
      when 1 then { 4 => 'new'.b, 5 => 0, 6 => 0 }
      when 5 then 0x30
      else raise 'Must not delete or cancel a completed enrollment'
      end
    end
    expect { fido.execute(connection: connection, args: %w[fingerprints add name], pin: '123456', confirm: true) }.to raise_error(fido::EnrollmentError) { |error| expect(error.template_id).to eq('new'.b) }
    expect(subcommands).to eq([7, 1, 5])
  end

  it 'enforces literal consent even on the underlying session entry points' do
    connection = FidoFixtureConnection.new
    session = fido::Session.new(connection: connection, pin: '123456', new_pin: '654321', secret_provider: ->(_name) { raise 'No provider call permitted' })
    expect { session.verify_pin }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    expect(connection.calls.none? { |call| call[:data].getbyte(0) == 6 }).to be(true)
  end
end

RSpec.describe 'Native YubiKey FIDO validation and bounded failures' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }
  let(:connection) { FidoFixtureConnection.new }

  it 'rejects nonboolean advertised capabilities and malformed PIN limits before a PIN attempt' do
    connection.info[4]['clientPin'] = 'false'
    expect { fido.execute(connection: connection, args: %w[access verify-pin], confirm: true, pin: '123456') }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    connection.info[4]['clientPin'] = true
    connection.info[13] = '6'
    expect { fido.execute(connection: connection, args: %w[access change-pin], confirm: true, pin: '123456', new_pin: '654321') }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    expect(connection.calls.none? { |call| call[:data].getbyte(0) == 6 }).to be(true)
  end

  it 'does not suppress a NO_CREDENTIALS error partway through an advertised RP enumeration' do
    connection.info[4]['credMgmt'] = true
    connection.app_handler = lambda do |_command, params|
      case params[1]
      when 1 then { 1 => 0, 2 => 25 }
      when 2 then { 3 => { 'id' => 'first.example' }, 4 => 'a'.b * 32, 5 => 2 }
      when 3 then 0x2e
      else raise 'unexpected command'
      end
    end
    expect { fido.execute(connection: connection, args: %w[credentials list], confirm: true, pin: '123456') }.to raise_error(fido::CTAPError)
  end

  it 'validates booleans, timeouts, and limits without opening or authenticating anything' do
    expect { fido.execute(args: false) }.to raise_error(ArgumentError)
    expect { fido.execute(connection: connection, args: ['info'], timeout: Complex(1, 2)) }.to raise_error(ArgumentError)
    expect { fido.execute(connection: connection, args: %w[credentials list], confirm: true, pin: '123456', max_records: 0) }.to raise_error(ArgumentError)
    expect(connection.calls).to be_empty
  end

  it 'rejects false callbacks, ambiguous boolean selectors and a current PIN on an uninitialized authenticator' do
    expect { fido.execute(connection: connection, args: ['info'], cancelled: false) }.to raise_error(ArgumentError)
    expect { fido.execute(connection: connection, args: %w[access change-pin], u2f: 'true', confirm: true) }.to raise_error(ArgumentError)
    connection.info[4]['clientPin'] = false
    expect { fido.execute(connection: connection, args: %w[access change-pin], pin: '123456', new_pin: '654321', confirm: true) }.to raise_error(ArgumentError)
    expect(connection.calls.none? { |call| call[:data].getbyte(0) == 6 }).to be(true)
  end

  it 'does not label built-in biometric authentication as PIN verification' do
    connection.info[4].merge!('credMgmt' => true, 'uv' => true)
    expect { fido.execute(connection: connection, args: %w[access verify-pin], confirm: true, uv: true) }.to raise_error(ArgumentError)
    expect(connection.calls).to be_empty
  end

  it 'uses a supported non-RP token permission or an explicit RP for modern PIN verification' do
    connection.info[4]['credMgmt'] = true
    expect(fido.execute(connection: connection, args: %w[access verify-pin], confirm: true, pin: '123456')).to eq({ verified: true })
    first = connection.calls.filter_map { |call| fido::CBOR.decode(data: call[:data].byteslice(1..)) if call[:data].getbyte(0) == 6 }.find { |params| params[2] == 9 }
    expect(first&.values_at(9, 10)).to eq([4, nil])
    connection.info[4].delete('credMgmt')
    connection.calls.clear
    fido.execute(connection: connection, args: %w[access verify-pin], confirm: true, pin: '123456', rp_id: 'operator.example')
    second = connection.calls.filter_map { |call| fido::CBOR.decode(data: call[:data].byteslice(1..)) if call[:data].getbyte(0) == 6 }.find { |params| params[2] == 9 }
    expect(second&.values_at(9, 10)).to eq([2, 'operator.example'])
  end

  it 'rejects an overlong padded PIN before key agreement even if a newer device advertises a larger limit' do
    connection.info[29] = 255
    expect { fido.execute(connection: connection, args: %w[access change-pin], confirm: true, pin: '123456', new_pin: 'x' * 250) }.to raise_error(ArgumentError)
    expect(connection.calls.none? { |call| call[:data].getbyte(0) == 6 }).to be(true)
  end

  it 'reads PIN retries without spending an attempt and formats explicit CSV as an in-memory return' do
    expect(fido.perform(connection: connection, operation: :pin_retries)).to include(pin_retries: 8, power_cycle_state: false)
    connection.info[4]['credMgmt'] = true
    connection.app_handler = ->(_command, params) { params[1] == 1 ? { 1 => 0, 2 => 25 } : 0x2e }
    csv = fido.execute(connection: connection, args: %w[credentials list --csv], confirm: true, pin: '123456')
    expect(csv).to eq("credential_id,rp_id,user_id,user_name,display_name\n")
  end

  it 'never retries reset rejection or blocked PIN status codes' do
    [0x31, 0x32, 0x34, 0x37].each do |status|
      connection.fail_code = status
      before = connection.calls.size
      expect { fido.execute(connection: connection, args: %w[access verify-pin], confirm: true, pin: '123456') }.to raise_error(fido::CTAPError) { |error| expect(error.code).to eq(status) }
      expect(connection.calls.size - before).to eq(3)
    end
    connection.handler = lambda do |request|
      request[:data] == "\x04".b ? "\x00".b + fido::CBOR.encode(value: connection.info) : "\x30".b
    end
    before = connection.calls.size
    expect { fido.execute(connection: connection, args: ['reset'], confirm: true) }.to raise_error(fido::CTAPError)
    expect(connection.calls.size - before).to eq(2)
  end

  it 'leaves caller-owned PIN Strings unchanged and keeps session diagnostics redacted' do
    pin = String.new('123456')
    new_pin = String.new('654321')
    fido.execute(connection: connection, args: %w[access change-pin], confirm: true, pin: pin, new_pin: new_pin)
    expect([pin, new_pin]).to eq(%w[123456 654321])
    session = fido::Session.new(connection: connection, pin: pin, confirm: true)
    expect(session.inspect).not_to include(pin)
    session.verify_pin
    owned_buffers = session.instance_variable_get(:@secrets).dup
    session.forget
    expect(owned_buffers).not_to be_empty
    expect(owned_buffers.all? { |buffer| buffer.bytes.all?(&:zero?) }).to be(true)
  end
end

RSpec.describe 'Native YubiKey FIDO transport integration' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }

  it 'drives the real CTAPHID framing/Connection with only native packet IO replaced' do
    require 'pwn/plugins/yubikey/transport'
    transport = PWN::Plugins::YubiKey::Transport
    io_type = Class.new do
      attr_reader :commands

      def initialize(capabilities, info_bytes)
        @capabilities = capabilities
        @info_bytes = info_bytes
        @queue = []
        @commands = []
      end

      def write_packet(packet)
        marker = packet.getbyte(4)
        @commands << marker
        channel = packet.unpack1('N')
        response = case marker
                   when 0x86 then packet.byteslice(7, 8) + [0x12345678, 2, 1, 0, 0, @capabilities].pack('NCCCCC')
                   when 0x90 then @info_bytes
                   when 0x83 then 'U2F_V2'.b + "\x90\x00".b
                   else raise 'Unexpected native packet command'
                   end
        @queue << ([channel, marker, response.bytesize].pack('NCn') + response.byteslice(0, 57)).ljust(64, "\x00".b)
        offset = 57
        sequence = 0
        while offset < response.bytesize
          @queue << ([channel, sequence].pack('NC') + response.byteslice(offset, 59)).ljust(64, "\x00".b)
          offset += 59
          sequence += 1
        end
        packet.bytesize
      end

      def read_packet(_timeout)
        @queue.shift || ''.b
      end

      def close
        :closed
      end
    end
    info = FidoFixtureConnection.new.info
    [1, 5].each do |caps|
      io = io_type.new(caps, "\x00".b + fido::CBOR.encode(value: info))
      connection = transport::Connection.new(descriptor: { protocol: :ctap }, io: io, prepare: transport::Deadline.new(2))
      begin
        result = fido.execute(connection: connection, args: ['info'])
        expect(result[:ctap2]).to eq(caps == 5)
        expect(io.commands).to eq(caps == 5 ? [0x86, 0x90] : [0x86, 0x83])
      ensure
        connection.close
      end
    end
  end

  it 'enforces the FIPS 32-byte limit before any vendor PIN mutation' do
    connection = FidoFixtureConnection.new(descriptor: { protocol: :ctap, capabilities: 1 })
    expect { fido.execute(connection: connection, args: %w[access change-pin --u2f], confirm: true, new_pin: 'x' * 33) }.to raise_error(ArgumentError)
    expect(connection.calls).to be_empty
  end
end

RSpec.describe 'Native YubiKey FIDO PIN cryptography' do
  let(:fido) { PWN::Plugins::YubiKey::FIDO }
  let(:z) { ['7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978'].pack('H*') }

  it 'derives protocol 1 and 2 keys against independent OpenSSL KDF golden values' do
    expect(fido::PinProtocol.new(1).derive(z).unpack1('H*')).to eq('23775201799b2234a18e8071e409cec80d42632fe77534180afdc533c9b76f81')
    expect(fido::PinProtocol.new(2).derive(z).unpack1('H*')).to eq('64ca541c7473e4a526a447a65f24c755d6098f8341d6731894bb241e6a6bf289ffdd11da665666f9e5a99ba18a1cf674a4f1adf68a436bf9d7f219980910e877')
  end

  it 'matches NIST SP800-38A AES-256 CBC including protocol 2 IV prefix and RFC4231 HMAC' do
    key = ['603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'].pack('H*')
    iv = ['000102030405060708090a0b0c0d0e0f'].pack('H*')
    plaintext = ['6bc1bee22e409f96e93d7e117393172a'].pack('H*')
    expected = iv + ['f58c4c04d6e5f1ba779eabfb5f7bfbd6'].pack('H*')
    allow(SecureRandom).to receive(:random_bytes).with(16).and_return(iv)
    proto = fido::PinProtocol.new(2)
    expect(proto.encrypt(("\x00".b * 32) + key, plaintext)).to eq(expected)
    expect(proto.decrypt(("\x00".b * 32) + key, expected)).to eq(plaintext)
    expect(fido::PinProtocol.new(1).encrypt("\x00".b * 32, "\x00".b * 16).unpack1('H*')).to eq('dc95c078a2408989ad48a21492842087')
    expect(proto.authenticate("\x0b".b * 20, 'Hi There').unpack1('H*')).to eq('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
    expect(fido::PinProtocol.new(1).authenticate("\x0b".b * 20, 'Hi There').unpack1('H*')).to eq('b0344c61d8db38535ca8afceaf0bf12b')
  end

  it 'performs actual P-256 ECDH with COSE keys and rejects invalid curve points' do
    generator = ['046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'].pack('H*')
    private_der = OpenSSL::ASN1::Sequence([
                                            OpenSSL::ASN1::Integer(1), OpenSSL::ASN1::OctetString(("\x00".b * 31) + "\x01".b),
                                            OpenSSL::ASN1::ObjectId('prime256v1', 0, :EXPLICIT), OpenSSL::ASN1::BitString(generator, 1, :EXPLICIT)
                                          ]).to_der
    allow(OpenSSL::PKey::EC).to receive(:generate).with('prime256v1').and_return(OpenSSL::PKey.read(private_der))
    peer = { 1 => 2, 3 => -25, -1 => 1, -2 => z, -3 => ['07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1'].pack('H*') }
    cose, shared = fido::PinProtocol.new(1).encapsulate(peer)
    expect(cose).to eq({ 1 => 2, 3 => -25, -1 => 1, -2 => generator.byteslice(1, 32), -3 => generator.byteslice(33, 32) })
    expect(shared.unpack1('H*')).to eq('23775201799b2234a18e8071e409cec80d42632fe77534180afdc533c9b76f81')
    expect { fido::PinProtocol.new(1).encapsulate(peer.merge(-2 => "\x00".b * 32)) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    expect { fido::PinProtocol.new(2).decrypt('x' * 64, 'x' * 16) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
  end
end

RSpec.describe 'Native YubiKey FIDO CBOR' do
  def codec
    PWN::Plugins::YubiKey::FIDO::CBOR
  end

  it 'encodes independent RFC 8949 integer, text, byte and container vectors' do
    vectors = { 0 => '00', 23 => '17', 24 => '1818', 1000 => '1903e8', -1 => '20', -1000 => '3903e7', true => 'f5', false => 'f4', nil => 'f6', [1, 2, 3] => '83010203', 'IETF' => '6449455446' }
    vectors.each do |value, hex|
      expect(codec.encode(value: value).unpack1('H*')).to eq(hex)
      expect(codec.decode(data: [hex].pack('H*'))).to eq(value)
    end
    expect(codec.encode(value: "\x01\x02".b).unpack1('H*')).to eq('420102')
    expect(codec.decode(data: ['420102'].pack('H*')).encoding).to eq(Encoding::BINARY)
  end

  it 'uses CTAP canonical major-type ordering rather than length-first ordering' do
    expect(codec.encode(value: { -1 => 1, 1000 => 2, 'z' => 3 }).unpack1('H*')).to eq('a31903e8022001617a03')
  end

  it 'rejects malformed, ambiguous, noncanonical and unbounded inputs' do
    %w[1817 5f 9f01ff a201010102 a220000100 61ff 1bffffffffffffffff00 d800 f7 fa00000000 440102].each do |hex|
      expect { codec.decode(data: [hex].pack('H*')) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    end
    cycle = []
    cycle << cycle
    expect { codec.encode(value: cycle) }.to raise_error(ArgumentError, /depth|cyclic/)
    expect { codec.decode(data: ("\x81".b * 40) + "\x00".b) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /depth/)
    expect { codec.encode(value: 'a' * 1_048_577) }.to raise_error(ArgumentError, /limit/)
    expect { codec.decode(data: ['9bffffffffffffffff'].pack('H*')) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /limit/)
  end
end
