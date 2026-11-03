# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'pwn/plugins/yubikey'
require 'pwn/plugins/yubikey/openpgp'

# Synthetic OpenPGP Card 3.4 APDUs. No encoder constants are borrowed from production.
# Every exchange is consumed in order; unexpected auth/write/retry fails immediately.
class OpenPGPWireConnection
  attr_reader :commands, :descriptor

  def initialize(script, descriptor = {})
    @script = script.dup
    @descriptor = { protocol: :apdu }.merge(descriptor)
    @commands = []
  end

  def exchange(opts = {})
    raise 'wrong protocol' unless opts[:protocol] == :apdu

    command = opts.fetch(:data).unpack1('H*')
    @commands << command
    expected, reply = @script.shift
    raise "Unexpected C-APDU header #{command[0, 8]}" unless expected
    raise "Wrong C-APDU header #{command[0, 8]} (expected #{expected[0, 8]})" unless command == expected
    raise reply if reply.is_a?(Exception)

    [reply].pack('H*')
  end

  def complete?
    @script.empty?
  end
end

RSpec.shared_context 'OpenPGP native wire' do
  let(:api) { PWN::Plugins::YubiKey::OpenPGP }

  def hx(bytes)
    bytes.unpack1('H*')
  end

  def tagged(tag, bytes)
    length = bytes.bytesize
    encoded_length = if length < 128
                       [length].pack('C')
                     elsif length < 256
                       [0x81, length].pack('CC')
                     else
                       [0x82, length].pack('Cn')
                     end
    [tag].pack('H*') + encoded_length + bytes
  end

  def app_hex(overrides = {}, card_version = '0304')
    fields = {
      'c0' => '74000020080000fe0000', 'c1' => '010800001100',
      'c2' => '010800001100', 'c3' => '010800001100',
      'c4' => '007f7f7f030003', 'c5' => '00' * 60,
      'c6' => '00' * 60, 'cd' => '00' * 12,
      'de' => '010102020301', 'd6' => '0020', 'd7' => '0120', 'd8' => '0320'
    }.merge(overrides).compact
    discretion = fields.map { |tag, value| tagged(tag, [value].pack('H*')) }.join
    outer = ["4f10d27600012401#{card_version}00061234567800005f5203000000"].pack('H*') + tagged('73', discretion)
    hx(tagged('6e', outer))
  end

  def command_chunks(header, bytes)
    chunks = bytes.bytes.each_slice(255).map { |chunk| chunk.pack('C*') }
    return [header] if chunks.empty?

    chunks.map.with_index do |chunk, index|
      cla = header[0, 2].to_i(16) | (index == chunks.length - 1 ? 0 : 0x10)
      format('%<cla>02x%<header>s%<length>02x%<payload>s', cla: cla, header: header[2..], length: chunk.bytesize, payload: hx(chunk))
    end
  end

  def fixture_certificate
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=OpenPGP offline fixture')
    cert.public_key = key
    cert.not_before = Time.at(0)
    cert.not_after = Time.at(1_000_000)
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def prelude(version = '050701', overrides = {})
    [
      %w[00a4040006d27600012401 9000],
      ['00f1000000', "#{version}9000"],
      ['00ca006e00', "#{app_hex(overrides)}9000"]
    ]
  end
end

RSpec.describe PWN::Plugins::YubiKey do
  include_context 'OpenPGP native wire'

  it 'reads version, capability, PIN and key metadata from actual SELECT and GET DATA APDUs' do
    connection = OpenPGPWireConnection.new(prelude + [%w[00ca007a00 7a05930300000a9000]])
    result = api.execute(args: ['info'], connection: connection)
    expect(result).to include(application: :openpgp, firmware: [5, 7, 1], card_version: [3, 4], signature_counter: 10)
    expect(result[:pin_status]).to include(user: 3, reset: 0, admin: 3, signature_policy: :always)
    expect(result[:keys][:sig]).to include(origin: :generated, algorithm: :rsa, bits: 2048, touch: :off)
    expect(result[:keys][:dec]).to include(origin: :imported, touch: :on)
    expect(result[:keys][:aut]).to include(origin: :generated, touch: :cached)
    expect(connection).to be_complete
  end

  it 'changes a user PIN with CHANGE REFERENCE DATA and reads fresh retry status' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[002400810c313131313131323232323232 9000], %w[00ca00c400 007f7f7f0300039000]
    ])
    result = api.execute(args: %w[access change-pin], connection: connection, confirm: true, pin: '111111', new_pin: '222222')
    expect(result).to include(changed: :pin, pin_status: include(user: 3))
    expect(connection).to be_complete
  end

  it 'does not authenticate or query a provider without literal consent' do
    connection = double('unused connection')
    provider = double('secret provider')
    expect(connection).not_to receive(:exchange)
    expect(provider).not_to receive(:call)
    expect { api.execute(args: %w[access change-pin], connection: connection, confirm: 'true', secret_provider: provider) }.to raise_error(described_class::ConfirmationRequired)
  end

  it 'does not verify an old credential when the replacement has invalid length' do
    connection = OpenPGPWireConnection.new(prelude)
    expect { api.execute(args: %w[access change-pin], connection: connection, confirm: true, pin: '111111', new_pin: 'x') }.to raise_error(ArgumentError, /length/)
    expect(connection.commands.none? { |command| %w[0020 0024].include?(command[0, 4]) }).to be true
  end

  it 'signs RSA DigestInfo through PSO and returns a host-verifiable signature' do
    key = OpenSSL::PKey::RSA.generate(2048)
    digest_info = '3031300d060960864801650304020105000420ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    signature = key.sign('SHA256', 'abc')
    connection = OpenPGPWireConnection.new(prelude + [
      %w[0020008106313131313131 9000], ["002a9e9a33#{digest_info}", "#{hx(signature)}9000"]
    ])
    result = api.sign(connection: connection, confirm: true, pin: '111111', message: 'abc', hash_algorithm: :sha256)
    expect(result).to eq(signature)
    expect(key.public_key.verify('SHA256', result, 'abc')).to be true
    expect(connection).to be_complete
  end

  it 'changes an admin PIN without first verifying it or replaying CHANGE' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[002400831038383838383838383939393939393939 9000], %w[00ca00c400 007f7f7f0300039000]
    ])
    result = api.execute(args: %w[access change-admin-pin], connection: connection, confirm: true, admin_pin: '88888888', new_admin_pin: '99999999')
    expect(result[:changed]).to eq(:admin_pin)
    expect(connection).to be_complete
  end

  it 'sets retries after explicit admin authentication and verifies counters by reading C4' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00200083083838383838383838 9000], %w[00f2000003050607 9000], %w[00ca00c400 007f7f7f0506079000]
    ])
    result = api.execute(args: %w[access set-retries 5 6 7], connection: connection, confirm: true, admin_pin: '88888888')
    expect(result).to include(verified: true, pins_reset: false)
    expect(connection).to be_complete
  end

  it 'rejects invalid retry counts before admin authentication or connection I/O' do
    connection = OpenPGPWireConnection.new([])
    expect { api.execute(args: %w[access set-retries 0 2 3], connection: connection, confirm: true) }.to raise_error(ArgumentError, /retries/)
    expect(connection.commands).to be_empty
  end

  it 'sets a reset code using PUT DATA only after validating both secrets' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00200083083838383838383838 9000], %w[00da00d3083737373737373737 9000], %w[00ca00c400 007f7f7f0303039000]
    ])
    result = api.execute(args: %w[access change-reset-code], connection: connection, confirm: true, admin_pin: '88888888', reset_code: '77777777')
    expect(result[:pin_status][:reset]).to eq(3)
    expect(connection).to be_complete
  end

  it 'unblocks using the reset code with RESET RETRY COUNTER P1 zero and no VERIFY' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[002c00810e3737373737373737323232323232 9000], %w[00ca00c400 007f7f7f0303039000]
    ])
    result = api.execute(args: %w[access unblock-pin], connection: connection, confirm: true, reset_code: '77777777', new_pin: '222222')
    expect(result).to include(unblocked: true)
    expect(connection).to be_complete
  end

  it 'unblocks using admin authorization with RESET RETRY COUNTER P1 two' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00200083083838383838383838 9000], %w[002c028106323232323232 9000], %w[00ca00c400 007f7f7f0300039000]
    ])
    result = api.execute(args: %w[access unblock-pin], connection: connection, confirm: true, admin_pin: '88888888', new_pin: '222222')
    expect(result).to include(unblocked: true)
    expect(connection).to be_complete
  end

  it 'sets signature PIN policy and rejects a mismatching readback without replay' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00200083083838383838383838 9000], %w[00da00c40101 9000], %w[00ca00c400 007f7f7f0300039000]
    ])
    expect { api.execute(args: %w[access set-signature-policy once], connection: connection, confirm: true, admin_pin: '88888888') }.to raise_error(described_class::ResponseError, /readback/)
    expect(connection).to be_complete
  end

  it 'applies card KDF S2K bytes for PIN changes using the card salt and byte count' do
    salt = 'saltsalt'
    old_hash = OpenSSL::Digest::SHA256.digest(("#{salt}111111" * 2) + "#{salt}111111"[0, 4])
    new_hash = OpenSSL::Digest::SHA256.digest(("#{salt}222222" * 2) + "#{salt}222222"[0, 4])
    connection = OpenPGPWireConnection.new(prelude('050701', 'c0' => '75000020080000fe0000') + [
      %w[00ca00f900 810103820108830400000020840873616c7473616c749000],
      ["0024008140#{hx(old_hash + new_hash)}", '9000'], %w[00ca00c400 007f7f7f0300039000]
    ])
    expect(api.execute(args: %w[access change-pin], connection: connection, confirm: true, pin: '111111', new_pin: '222222')[:changed]).to eq(:pin)
    expect(connection).to be_complete
  end

  it 'sets touch UIF including its button byte and verifies it by fresh GET DATA' do
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00ca00d600 00209000], %w[00200083083838383838383838 9000],
      %w[00da00d6020420 9000], %w[00ca00d600 04209000]
    ])
    result = api.execute(args: %w[keys set-touch sig cached-fixed], connection: connection, confirm: true, admin_pin: '88888888')
    expect(result).to include(touch: :'cached-fixed', irreversible: true, verified: true)
    expect(connection).to be_complete
  end

  it 'refuses changing an already fixed touch policy before admin verification' do
    connection = OpenPGPWireConnection.new(prelude + [%w[00ca00d600 02209000]])
    expect { api.execute(args: %w[keys set-touch sig off], connection: connection, confirm: true, admin_pin: '88888888') }.to raise_error(api::UnsupportedError, /fixed/i)
    expect(connection).to be_complete
  end

  it 'reads key metadata from application data without authentication' do
    connection = OpenPGPWireConnection.new(prelude)
    expect(api.execute(args: %w[keys info dec], connection: connection)).to include(slot: :dec, origin: :imported)
    expect(connection).to be_complete
  end

  it 'exports a real DER certificate after selecting the signature slot' do
    certificate = fixture_certificate
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00a502040660045c027f21 9000], ['00ca7f2100', "#{hx(certificate.to_der)}9000"]
    ])
    result = api.execute(args: %w[certificates export sig - --format DER], connection: connection)
    expect(result).to eq(certificate.to_der)
    expect(OpenSSL::X509::Certificate.new(result).verify(certificate.public_key)).to be true
    expect(connection).to be_complete
  end

  it 'imports a certificate through command chaining and verifies the exact stored DER' do
    certificate = fixture_certificate
    script = prelude + [%w[00200083083838383838383838 9000], %w[00a501040660045c027f21 9000]]
    script += command_chunks('00da7f21', certificate.to_der).map { |command| [command, '9000'] }
    script += [%w[00a501040660045c027f21 9000], ['00ca7f2100', "#{hx(certificate.to_der)}9000"]]
    connection = OpenPGPWireConnection.new(script)
    result = api.execute(args: %w[certificates import dec -], connection: connection, certificate: certificate.to_pem, confirm: true, admin_pin: '88888888')
    expect(result).to include(imported: :certificate, verified: true)
    expect(connection.commands.any? { |command| command.start_with?('10da7f21ff') }).to be true
    expect(connection).to be_complete
  end

  it 'deletes certificates using an empty PUT DATA and reads the empty slot back' do
    connection = OpenPGPWireConnection.new(prelude('050403') + [
      %w[00200083083838383838383838 9000], %w[00a50004070660045c027f21 9000], %w[00da7f2100 9000],
      %w[00a50004070660045c027f21 9000], %w[00ca7f2100 9000]
    ])
    result = api.execute(args: %w[certificates delete aut], connection: connection, confirm: true, admin_pin: '88888888')
    expect(result).to include(deleted: :certificate, verified: true)
    expect(connection).to be_complete
  end

  it 'attests a generated key with proprietary CLA 80 and returns the created certificate' do
    certificate = fixture_certificate
    connection = OpenPGPWireConnection.new(prelude + [
      %w[0020008106313131313131 9000], %w[80fb010000 9000],
      %w[00a502040660045c027f21 9000], ['00ca7f2100', "#{hx(certificate.to_der)}9000"]
    ])
    result = api.execute(args: %w[keys attest sig -], connection: connection, confirm: true, pin: '111111')
    expect(result).to eq(certificate.to_pem)
    expect(connection).to be_complete
  end

  it 'resets by deliberately exhausting only observed retry counters before TERMINATE and ACTIVATE' do
    script = prelude('050701', 'c4' => '007f7f7f010001') + [
      %w[00200081080000000000000000 6982], %w[00ca00c400 007f7f7f0000019000],
      %w[00200083080000000000000000 6983], %w[00ca00c400 007f7f7f0000009000],
      %w[00e6000000 9000], %w[0044000000 9000], %w[00a4040006d27600012401 9000],
      ['00ca006e00', "#{app_hex('de' => '010002000300')}9000"]
    ]
    connection = OpenPGPWireConnection.new(script)
    result = api.execute(args: ['reset', '--force'], connection: connection, confirm: true)
    expect(result).to include(reset: true, key_slots_verified_empty: true, attestation_preserved: true)
    expect(connection).to be_complete
  end

  it 'aborts a reset if the invalid sentinel unexpectedly verifies rather than trying guessed PINs' do
    connection = OpenPGPWireConnection.new(prelude + [%w[00200081080000000000000000 9000]])
    expect { api.execute(args: ['reset'], connection: connection, confirm: true) }.to raise_error(described_class::ResponseError, /unexpectedly verified/)
    expect(connection).to be_complete
  end

  it 'never treats --force as consent for reset or irreversible touch policies' do
    connection = OpenPGPWireConnection.new([])
    expect { api.execute(args: %w[reset --force], connection: connection) }.to raise_error(described_class::ConfirmationRequired)
    expect { api.execute(args: %w[keys set-touch att fixed --force], connection: connection) }.to raise_error(described_class::ConfirmationRequired)
    expect(connection.commands).to be_empty
  end

  it 'returns local metadata for every OpenPGP group without a connection' do
    [[], ['access'], ['keys'], ['certificates']].each do |args|
      expect(api.execute(args: args)).to include(application: :openpgp, group: args.join(' '))
    end
    expect(api.operations).to include('info', 'access change-pin', 'keys attest', 'certificates import')
    expect(api.operations).not_to include('access', 'keys', 'certificates')
  end

  it 'rejects unknown commands and credential argv without touching a connection' do
    connection = double('unopened connection')
    expect(connection).not_to receive(:exchange)
    expect { api.execute(args: %w[keys explode], connection: connection) }.to raise_error(ArgumentError)
    expect { api.execute(args: ['access', 'change-pin', '--pin', 'synthetic-pin'], connection: connection) }.to raise_error(ArgumentError)
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'native cryptographic operations' do
  include_context 'OpenPGP native wire'

  it 'converts ECDSA r||s card signatures to canonical DER verified by OpenSSL' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    digest = OpenSSL::Digest.digest('SHA256', 'abc')
    der = key.dsa_sign_asn1(digest)
    parts = OpenSSL::ASN1.decode(der).value.map { |number| number.value.to_s(2).rjust(32, "\0") }
    connection = OpenPGPWireConnection.new(prelude('050701', 'c1' => '132a8648ce3d030107') + [
      %w[0020008106313131313131 9000], ["002a9e9a20#{hx(digest)}", "#{hx(parts.join)}9000"]
    ])
    result = api.sign(connection: connection, confirm: true, pin: '111111', message: 'abc')
    expect(result).to eq(der)
    expect(key.dsa_verify_asn1(digest, result)).to be true
    expect(connection).to be_complete
  end

  it 'performs Ed25519 INTERNAL AUTHENTICATE on the raw message with extended PW1' do
    seed = ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'].pack('H*')
    key = OpenSSL::PKey.read(['302e020100300506032b657004220420'].pack('H*') + seed)
    signature = key.sign(nil, 'abc')
    connection = OpenPGPWireConnection.new(prelude('050701', 'c3' => '162b06010401da470f01') + [
      %w[0020008206313131313131 9000], ['0088000003616263', "#{hx(signature)}9000"]
    ])
    result = api.authenticate(connection: connection, confirm: true, pin: '111111', message: 'abc')
    expect(key.verify(nil, result, 'abc')).to be true
    expect(connection).to be_complete
  end

  it 'deciphers an RSA PKCS1 encrypted block with padding indicator zero and command chaining' do
    key = OpenSSL::PKey::RSA.generate(2048)
    ciphertext = key.public_encrypt('offline message')
    script = prelude + [%w[0020008206313131313131 9000]]
    blocks = command_chunks('002a8086', "\0#{ciphertext}")
    script += blocks.map.with_index { |command, index| [command, index == blocks.size - 1 ? "#{hx(key.private_decrypt(ciphertext))}9000" : '9000'] }
    connection = OpenPGPWireConnection.new(script)
    expect(api.decipher(connection: connection, confirm: true, pin: '111111', value: ciphertext)).to eq('offline message')
    expect(connection.commands).to include(blocks[0])
    expect(connection).to be_complete
  end

  it 'derives an X25519 secret using the OpenPGP A6/7F49/86 peer template' do
    local = OpenSSL::PKey.generate_key('X25519')
    peer = OpenSSL::PKey.generate_key('X25519')
    point = OpenSSL::ASN1.decode(peer.public_to_der).value[1].value
    secret = local.derive(peer)
    connection = OpenPGPWireConnection.new(prelude('050701', 'c2' => '122b060104019755010501') + [
      %w[0020008206313131313131 9000], ["002a808627a6257f49228620#{hx(point)}", "#{hx(secret)}9000"]
    ])
    expect(api.decipher(connection: connection, confirm: true, pin: '111111', value: peer)).to eq(peer.derive(local))
    expect(connection).to be_complete
  end

  it 'rejects truncated ECDSA card signatures rather than returning invalid DER' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'c1' => '132a8648ce3d030107') + [
      %w[0020008106313131313131 9000], ["002a9e9a20#{hx(OpenSSL::Digest.digest('SHA256', 'abc'))}", "#{'01' * 63}9000"]
    ])
    expect { api.sign(connection: connection, confirm: true, pin: '111111', message: 'abc') }.to raise_error(described_class::ResponseError, /signature/)
    expect(connection).to be_complete
  end

  it 'rejects incompatible ECDH points before a PIN attempt' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'c2' => '122a8648ce3d030107'))
    peer = OpenSSL::PKey::EC.generate('secp384r1')
    expect { api.decipher(connection: connection, confirm: true, pin: '111111', value: peer) }.to raise_error(ArgumentError, /curve/)
    expect(connection).to be_complete
  end

  it 'rejects invalid prehashed lengths before a PIN attempt' do
    connection = OpenPGPWireConnection.new(prelude)
    expect { api.sign(connection: connection, confirm: true, pin: '111111', message: 'abc', prehashed: true) }.to raise_error(ArgumentError, /digest length/)
    expect(connection).to be_complete
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'key provisioning' do
  include_context 'OpenPGP native wire'

  def public_wire(key)
    if key.is_a?(OpenSSL::PKey::RSA)
      inner = tagged('81', key.n.to_s(2)) + tagged('82', key.e.to_s(2))
    else
      raw = key.is_a?(OpenSSL::PKey::EC) ? key.public_key.to_octet_string(:uncompressed) : OpenSSL::ASN1.decode(key.public_to_der).value[1].value
      inner = tagged('86', raw)
    end
    hx(tagged('7f49', inner))
  end

  it 'generates an RSA key in-card and verifies its exported public key without private host generation' do
    key = OpenSSL::PKey::RSA.generate(2048)
    wire = public_wire(key)
    connection = OpenPGPWireConnection.new(prelude('040305') + [
      %w[00200083083838383838383838 9000], ['0047800002b600', "#{wire}9000"], ['0047810002b600', "#{wire}9000"]
    ])
    result = api.generate_key(connection: connection, confirm: true, slot: :sig, algorithm: :rsa2048, admin_pin: '88888888')
    expect(result).to be_a(OpenSSL::PKey::RSA)
    expect(result.public_to_der).to eq(key.public_to_der)
    expect(result).not_to be_private
    expect(connection).to be_complete
  end

  it 'uses advertised repeated FA algorithm entries before changing attributes for EC generation' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    wire = public_wire(key)
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00ca00fa00 fa13c106010800001100c109132a8648ce3d0301079000],
      %w[00200083083838383838383838 9000], %w[00da00c109132a8648ce3d030107 9000],
      %w[00ca00c100 132a8648ce3d0301079000], ['0047800002b600', "#{wire}9000"], ['0047810002b600', "#{wire}9000"]
    ])
    result = api.generate_key(connection: connection, confirm: true, slot: :sig, algorithm: :secp256r1, admin_pin: '88888888')
    expect(result.public_to_der).to eq(key.public_to_der)
    expect(connection).to be_complete
  end

  it 'rejects token-unsupported curves and vulnerable RSA generation before admin verification' do
    connection = OpenPGPWireConnection.new(prelude + [%w[00ca00fa00 fa08c1060108000011009000]])
    expect { api.generate_key(connection: connection, confirm: true, slot: :sig, algorithm: :secp384r1, admin_pin: '88888888') }.to raise_error(api::UnsupportedError)
    expect(connection).to be_complete
    vulnerable = OpenPGPWireConnection.new(prelude('040304'))
    expect { api.generate_key(connection: vulnerable, confirm: true, slot: :sig, algorithm: :rsa2048, admin_pin: '88888888') }.to raise_error(api::UnsupportedError, /RSA/)
    expect(vulnerable).to be_complete
  end

  it 'imports a real PKCS8 Ed25519 fixture as its seed rather than the DER wrapper' do
    seed = ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'].pack('H*')
    key_der = ['302e020100300506032b657004220420'].pack('H*') + seed
    key = OpenSSL::PKey.read(key_der)
    template = tagged('4d', ['b6007f480292205f4820'].pack('H*') + seed)
    script = prelude('050701', 'c1' => '162b06010401da470f01') + [
      %w[00ca00fa00 fa0cc10a162b06010401da470f019000], %w[00200083083838383838383838 9000]
    ]
    script += command_chunks('00db3fff', template).map { |command| [command, '9000'] }
    script << ['0047810002b600', "#{public_wire(key)}9000"]
    connection = OpenPGPWireConnection.new(script)
    result = api.import_key(connection: connection, confirm: true, slot: :sig, key: key_der, admin_pin: '88888888')
    expect(result).to include(imported: :key, slot: :sig, verified: true)
    expect(result[:public_key].public_to_der).to eq(key.public_to_der)
    expect(connection).to be_complete
  end

  it 'reverses only the X25519 raw scalar bytes for OpenPGP private key import' do
    seed = ['77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'].pack('H*')
    key = OpenSSL::PKey.read(['302e020100300506032b656e04220420'].pack('H*') + seed)
    template = tagged('4d', ['b8007f480292205f4820'].pack('H*') + seed.reverse)
    script = prelude('050701', 'c2' => '122b060104019755010501') + [
      %w[00ca00fa00 fa0dc20b122b0601040197550105019000], %w[00200083083838383838383838 9000]
    ]
    script += command_chunks('00db3fff', template).map { |command| [command, '9000'] }
    script << ['0047810002b800', "#{public_wire(key)}9000"]
    connection = OpenPGPWireConnection.new(script)
    expect(api.import_key(connection: connection, confirm: true, slot: :dec, key: key, admin_pin: '88888888')[:verified]).to be true
    expect(connection).to be_complete
  end

  {
    secp256r1: ['prime256v1', '132a8648ce3d030107', :sig],
    secp256k1: ['secp256k1', '132b8104000a', :sig],
    secp384r1: ['secp384r1', '132b81040022', :sig],
    secp521r1: ['secp521r1', '132b81040023', :sig],
    brainpoolp256r1: ['brainpoolP256r1', '132b2403030208010107', :sig],
    brainpoolp384r1: ['brainpoolP384r1', '132b240303020801010b', :sig],
    brainpoolp512r1: ['brainpoolP512r1', '122b240303020801010d', :dec],
    ed25519: ['ED25519', '162b06010401da470f01', :sig],
    x25519: ['X25519', '122b060104019755010501', :dec]
  }.each do |algorithm, (curve, encoded, slot)|
    it "generates advertised #{algorithm} keys and reconstructs the real OpenSSL public key" do
      key = %w[ED25519 X25519].include?(curve) ? OpenSSL::PKey.generate_key(curve) : OpenSSL::PKey::EC.generate(curve)
      tag = slot == :sig ? 'c1' : 'c2'
      crt = slot == :sig ? 'b600' : 'b800'
      connection = OpenPGPWireConnection.new(prelude('050701', tag => encoded) + [
        ['00ca00fa00', "#{hx(tagged('fa', tagged(tag, [encoded].pack('H*'))))}9000"],
        %w[00200083083838383838383838 9000], ["0047800002#{crt}", "#{public_wire(key)}9000"], ["0047810002#{crt}", "#{public_wire(key)}9000"]
      ])
      result = api.generate_key(connection: connection, confirm: true, slot: slot, algorithm: algorithm, admin_pin: '88888888')
      expect(result.public_to_der).to eq(key.public_to_der)
      expect(connection).to be_complete
    end
  end

  [3072, 4096].each do |bits|
    it "generates RSA#{bits} with the exact advertised modulus attributes" do
      key = OpenSSL::PKey::RSA.generate(bits)
      encoded = %w[010c00001100 011000001100][bits == 3072 ? 0 : 1]
      connection = OpenPGPWireConnection.new(prelude('050701', 'c3' => encoded) + [
        ['00ca00fa00', "#{hx(tagged('fa', tagged('c3', [encoded].pack('H*'))))}9000"],
        %w[00200083083838383838383838 9000], ['0047800002a400', "#{public_wire(key)}9000"], ['0047810002a400', "#{public_wire(key)}9000"]
      ])
      expect(api.generate_key(connection: connection, confirm: true, slot: :aut, algorithm: "rsa#{bits}", admin_pin: '88888888').n).to eq(key.n)
      expect(connection).to be_complete
    end
  end

  it 'imports a P521 scalar with 66-byte width rather than truncating the leading bit' do
    key = OpenSSL::PKey::EC.generate('secp521r1')
    scalar = key.private_key.to_s(2).rjust(66, "\0")
    template = tagged('4d', ['b6007f480292425f4842'].pack('H*') + scalar)
    script = prelude('050701', 'c1' => '132b81040023') + [
      %w[00ca00fa00 fa08c106132b810400239000], %w[00200083083838383838383838 9000]
    ]
    script += command_chunks('00db3fff', template).map { |command| [command, '9000'] }
    script << ['0047810002b600', "#{public_wire(key)}9000"]
    connection = OpenPGPWireConnection.new(script)
    expect(api.import_key(connection: connection, slot: :sig, key: key.private_to_der, confirm: true, admin_pin: '88888888')[:verified]).to be true
    expect(connection).to be_complete
  end

  it 'imports legacy NEO RSA CRT factors including iqmp, dp, dq and modulus' do
    key = OpenSSL::PKey::RSA.generate(2048)
    values = [key.e.to_s(2), *[key.p, key.q, key.iqmp, key.dmp1, key.dmq1].map { |num| num.to_s(2).rjust(128, "\0") }, key.n.to_s(2)].join
    template = tagged('4d', ['b600'].pack('H*') + tagged('7f48', ['910392818093818094818095818096818097820100'].pack('H*')) + tagged('5f48', values))
    script = prelude('010007', 'c1' => '010800001103') + [%w[00200083083838383838383838 9000]]
    script += command_chunks('00db3fff', template).map { |command| [command, '9000'] }
    script << ['0047810002b600', "#{public_wire(key)}9000"]
    connection = OpenPGPWireConnection.new(script)
    expect(api.import_key(connection: connection, confirm: true, slot: :sig, key: key, admin_pin: '88888888')[:verified]).to be true
    expect(connection).to be_complete
  end

  it 'imports NEO RSA CRT when algorithm attributes are fixed rather than writable' do
    key = OpenSSL::PKey::RSA.generate(2048)
    values = [key.e.to_s(2), *[key.p, key.q, key.iqmp, key.dmp1, key.dmq1].map { |num| num.to_s(2).rjust(128, "\0") }, key.n.to_s(2)].join
    template = tagged('4d', ['b600'].pack('H*') + tagged('7f48', ['910392818093818094818095818096818097820100'].pack('H*')) + tagged('5f48', values))
    script = prelude('010007', 'c0' => '70000020080000fe0000') + [%w[00200083083838383838383838 9000]]
    script += command_chunks('00db3fff', template).map { |command| [command, '9000'] }
    script << ['0047810002b600', "#{public_wire(key)}9000"]
    connection = OpenPGPWireConnection.new(script)
    expect(api.import_key(connection: connection, confirm: true, slot: :sig, key: key, admin_pin: '88888888')[:verified]).to be true
    expect(connection).to be_complete
  end

  it 'exports the public key as a typed read-only API without any authentication' do
    key = OpenSSL::PKey::RSA.generate(2048)
    connection = OpenPGPWireConnection.new(prelude + [['0047810002b600', "#{public_wire(key)}9000"]])
    expect(api.public_key(connection: connection, slot: :sig).public_to_der).to eq(key.public_to_der)
    expect(connection).to be_complete
  end

  it 'decrypts an actual encrypted PKCS8 key using only the required in-memory provider fields' do
    key = OpenSSL::PKey.generate_key('ED25519')
    pem = key.private_to_pem(OpenSSL::Cipher.new('aes-256-cbc'), 'offline fixture passphrase')
    seed = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(key.private_to_der).value[2].value).value
    template = tagged('4d', ['b6007f480292205f4820'].pack('H*') + seed)
    script = prelude('050701', 'c1' => '162b06010401da470f01') + [
      %w[00ca00fa00 fa0cc10a162b06010401da470f019000], %w[00200083083838383838383838 9000]
    ]
    script += command_chunks('00db3fff', template).map { |command| [command, '9000'] }
    script << ['0047810002b600', "#{public_wire(key)}9000"]
    connection = OpenPGPWireConnection.new(script)
    names = []
    provider = lambda do |name|
      names << name
      { key_password: 'offline fixture passphrase', admin_pin: '88888888' }.fetch(name)
    end
    expect(api.import_key(connection: connection, confirm: true, slot: :sig, key: pem, secret_provider: provider)[:verified]).to be true
    expect(names).to eq(%i[key_password admin_pin])
    expect(connection).to be_complete
  end

  it 'imports RSA private key factors with independent 7F48 length headers and chained PUT DATA ODD' do
    key = OpenSSL::PKey::RSA.generate(2048)
    components = key.e.to_s(2) + key.p.to_s(2).rjust(128, "\0") + key.q.to_s(2).rjust(128, "\0")
    template = tagged('4d', ['b6038401817f48089103928180938180'].pack('H*') + tagged('5f48', components))
    script = prelude('050701', 'da' => '010800001100') + [
      %w[00ca00fa00 fa08da060108000011009000], %w[00200083083838383838383838 9000]
    ]
    script += command_chunks('00db3fff', template).map { |command| [command, '9000'] }
    script << ['0047810005b603840181', "#{public_wire(key)}9000"]
    connection = OpenPGPWireConnection.new(script)
    result = api.execute(args: %w[keys import att -], connection: connection, key: key.private_to_pem, confirm: true, admin_pin: '88888888')
    expect(result).to include(imported: :key, verified: true)
    expect(connection.commands.any? { |command| command.start_with?('10db3fffff') }).to be true
    expect(connection).to be_complete
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'safety and firmware compatibility' do
  include_context 'OpenPGP native wire'

  it 'never replays an incorrect PIN or an uncertain signing command' do
    connection = OpenPGPWireConnection.new(prelude + [%w[0020008106313131313131 63c2]])
    expect { api.sign(connection: connection, confirm: true, pin: '111111', message: 'abc') }.to raise_error(described_class::Protocol::APDUError) { |error| expect(error.status).to eq(0x63C2) }
    expect(connection).to be_complete
    timeout = OpenPGPWireConnection.new(prelude + [
      %w[0020008106313131313131 9000],
      ["002a9e9a333031300d060960864801650304020105000420#{hx(OpenSSL::Digest.digest('SHA256', 'abc'))}", described_class::TimeoutError.new('uncertain')]
    ])
    expect { api.sign(connection: timeout, confirm: true, pin: '111111', message: 'abc') }.to raise_error(described_class::TimeoutError)
    expect(timeout).to be_complete
  end

  it 'obtains only required credentials from the in-memory provider without logging them' do
    names = []
    provider = lambda { |name|
      names << name
      '88888888'
    }
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00200083083838383838383838 9000], %w[00da00c40101 9000], %w[00ca00c400 017f7f7f0300039000]
    ])
    result = api.execute(args: %w[access set-signature-policy once], connection: connection, confirm: true, secret_provider: provider)
    expect(result[:verified]).to be true
    expect(result.inspect).not_to include('88888888')
    expect(names).to eq([:admin_pin])
    expect(connection).to be_complete
  end

  it 'rejects absent credentials without guessing factory PINs' do
    connection = OpenPGPWireConnection.new(prelude)
    expect { api.sign(connection: connection, confirm: true, message: 'abc') }.to raise_error(ArgumentError, /pin/)
    expect(connection).to be_complete
  end

  it 'rejects oversized Ed25519 messages before authenticating' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'c1' => '162b06010401da470f01'))
    expect { api.sign(connection: connection, confirm: true, pin: '111111', message: 'x' * 65_536) }.to raise_error(ArgumentError, /length/)
    expect(connection).to be_complete
  end

  it 'does not automatically activate a terminated application during an info call' do
    connection = OpenPGPWireConnection.new([%w[00a4040006d27600012401 6285]])
    expect { api.execute(args: ['info'], connection: connection) }.to raise_error(described_class::Protocol::APDUError)
    expect(connection).to be_complete
  end

  it 'activates a terminated application only as an explicitly confirmed reset and verifies it' do
    connection = OpenPGPWireConnection.new([
                                             %w[00a4040006d27600012401 6285], %w[0044000000 9000],
                                             %w[00a4040006d27600012401 9000], ['00ca006e00', "#{app_hex('de' => '010002000300')}9000"]
                                           ])
    expect(api.execute(args: ['reset'], connection: connection, confirm: true)[:key_slots_verified_empty]).to be true
    expect(connection).to be_complete
  end

  it 'recovers a corrupted application only on reset with bounded deliberate blocking' do
    connection = OpenPGPWireConnection.new([
                                             %w[00a4040006d27600012401 6581], %w[00200081080000000000000000 6982], %w[00200081080000000000000000 6983],
                                             %w[00200083080000000000000000 6983], %w[00e6000000 9000], %w[0044000000 9000],
                                             %w[00a4040006d27600012401 9000], ['00ca006e00', "#{app_hex('de' => '010002000300')}9000"]
                                           ])
    expect(api.execute(args: ['reset'], connection: connection, confirm: true)[:reset]).to be true
    expect(connection).to be_complete
  end

  it 'exposes PIN verification and reset-verification with their explicit reference and version gate' do
    connection = OpenPGPWireConnection.new(prelude + [%w[0020008206313131313131 9000]])
    expect(api.verify_pin(connection: connection, confirm: true, pin: '111111', mode: :extended)).to include(verified: true, mode: :extended)
    expect(connection).to be_complete
    unverify = OpenPGPWireConnection.new(prelude + [%w[0020ff8200 9000]])
    expect(api.unverify_pin(connection: unverify, confirm: true, mode: :extended)).to include(cleared: :extended)
    expect(unverify).to be_complete
  end

  it 'exposes algorithm information without assuming absent capabilities' do
    connection = OpenPGPWireConnection.new(prelude('040400'))
    result = api.algorithms(connection: connection)
    expect(result.keys).to eq(%i[sig dec aut])
    expect(result[:sig].map { |entry| entry[:bits] }).to eq([2048])
    expect(connection).to be_complete
  end

  it 'handles the documented pre-5.6.1 FA length and X25519 advertising errata narrowly' do
    # FA declares two bytes too many; DEC contains the historical invalid EdDSA/X25519 entry.
    connection = OpenPGPWireConnection.new(prelude('050403') + [%w[00ca00fa00 fa0fc20b162b0601040197550105019000]])
    result = api.algorithms(connection: connection)
    expect(result[:dec]).to include(include(algorithm: :ecdh, curve: :x25519))
    expect(result[:dec]).not_to include(include(algorithm: :eddsa))
    expect(connection).to be_complete
  end

  it 'rejects unrelated malformed FA lengths rather than inventing capabilities' do
    connection = OpenPGPWireConnection.new(prelude + [%w[00ca00fa00 fa20c1060108000011009000]])
    expect { api.algorithms(connection: connection) }.to raise_error(described_class::ResponseError)
    expect(connection).to be_complete
  end

  it 'reports whether the actual card KDF object enables PIN hashing' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'c0' => '75000020080000fe0000') + [
      %w[00ca007a00 7a0593030000009000], %w[00ca00f900 810103820108830400000020840873616c7473616c749000]
    ])
    expect(api.execute(args: ['info'], connection: connection)).to include(kdf_enabled: true)
    expect(connection).to be_complete
  end

  it 'reads legacy UIF separately when it is absent from application data' do
    raw = app_hex({ 'd6' => nil }, '0201')
    connection = OpenPGPWireConnection.new([%w[00a4040006d27600012401 9000], %w[00f1000000 0403059000], ['00ca006e00', "#{raw}9000"], %w[00ca00d600 01209000]])
    expect(api.execute(args: %w[keys info sig], connection: connection)[:touch]).to eq(:on)
    expect(connection).to be_complete
  end

  it 'rejects misleading EC signing attributes before authentication' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'c1' => '132b060104019755010501'))
    expect { api.sign(connection: connection, confirm: true, message: 'abc', pin: '111111') }.to raise_error(api::UnsupportedError, /curve/)
    expect(connection).to be_complete
  end

  it 'rejects empty slots before consuming a PIN attempt for crypto' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'de' => '010002000300'))
    expect { api.sign(connection: connection, confirm: true, message: 'abc', pin: '111111') }.to raise_error(api::UnsupportedError, /empty/)
    expect(connection).to be_complete
  end

  it 'rejects repeated format options and invalid certificates before authentication' do
    connection = OpenPGPWireConnection.new([])
    expect { api.execute(args: %w[keys attest sig - --format DER --format PEM], connection: connection, confirm: true) }.to raise_error(ArgumentError)
    expect { api.execute(args: %w[certificates import sig -], certificate: 'invalid certificate', connection: connection, confirm: true) }.to raise_error(ArgumentError)
    expect(connection.commands).to be_empty
  end

  it 'rejects oversized certificates and unsupported old certificate slots before admin verification' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'c0' => '74000020001000fe0000'))
    expect { api.execute(args: %w[certificates import sig -], certificate: fixture_certificate.to_der, connection: connection, confirm: true, admin_pin: '88888888') }.to raise_error(api::UnsupportedError, /certificate limit/)
    expect(connection).to be_complete
    old = OpenPGPWireConnection.new(prelude('040305'))
    expect { api.execute(args: %w[certificates delete sig], connection: old, confirm: true, admin_pin: '88888888') }.to raise_error(api::UnsupportedError, /firmware/)
    expect(old).to be_complete
  end

  it 'exports a certificate to an explicit exclusive output file through GET RESPONSE chaining' do
    cert = fixture_certificate
    der = cert.to_der
    connection = OpenPGPWireConnection.new(prelude + [
      %w[00a500040660045c027f21 9000], ['00ca7f2100', "#{hx(der[0, 128])}61ff"], ['00c00000ff', "#{hx(der[128..])}9000"]
    ])
    Dir.mktmpdir('openpgp-cert-') do |dir|
      output = File.join(dir, 'certificate.der')
      result = api.execute(args: ['certificates', 'export', 'aut', output, '--format', 'DER'], connection: connection)
      expect(File.binread(output)).to eq(result)
      expect(result).to eq(der)
      expect(File.stat(output).mode & 0o777).to eq(0o600)
    end
    expect(connection).to be_complete
  end

  it 'deciphers through the decrypt alias without changing its binary result' do
    connection = OpenPGPWireConnection.new(prelude + [%w[0020008206313131313131 9000]] + command_chunks('002a8086', "\0".b + ('x' * 256)).map.with_index { |command, index| [command, index.zero? ? '9000' : '0001ff9000'] })
    expect(api.decrypt(connection: connection, confirm: true, pin: '111111', value: 'x' * 256)).to eq("\0\x01\xFF".b)
    expect(connection).to be_complete
  end

  it 'uses the admin-specific S2K salt and SHA512 when advertised by the card' do
    digest = OpenSSL::Digest.digest('SHA512', 'adminslt88888888' * 4)
    connection = OpenPGPWireConnection.new(prelude('050701', 'c0' => '75000020080000fe0000') + [
      %w[00ca00f900 81010382010a83040000004084087573657273616c74860861646d696e736c749000],
      ["0020008340#{hx(digest)}", '9000']
    ])
    expect(api.verify_pin(connection: connection, confirm: true, admin_pin: '88888888', mode: :admin)[:verified]).to be true
    expect(connection).to be_complete
  end

  it 'rejects an unsupported KDF instead of sending plaintext PINs' do
    connection = OpenPGPWireConnection.new(prelude('050701', 'c0' => '75000020080000fe0000') + [%w[00ca00f900 81017f9000]])
    expect { api.verify_pin(connection: connection, confirm: true, pin: '111111') }.to raise_error(api::UnsupportedError, /KDF/)
    expect(connection).to be_complete
  end

  it 'disables unsupported touch or retry mutations before admin authentication' do
    touch = OpenPGPWireConnection.new(prelude('010007'))
    expect { api.execute(args: %w[keys set-touch sig on], connection: touch, confirm: true, admin_pin: '88888888') }.to raise_error(api::UnsupportedError)
    expect(touch).to be_complete
    retries = OpenPGPWireConnection.new(prelude('040300'))
    expect { api.execute(args: %w[access set-retries 3 3 3], connection: retries, confirm: true, admin_pin: '88888888') }.to raise_error(api::UnsupportedError)
    expect(retries).to be_complete
  end

  it 'documents every public method and preserves exact leaf coverage separately from groups' do
    output = StringIO.new
    original = $stdout
    begin
      $stdout = output
      api.help
    ensure
      $stdout = original
    end
    %i[execute operations generate_key import_key sign authenticate decipher decrypt algorithms public_key verify_pin unverify_pin authors].each do |method|
      expect(output.string).to include("#{api}.#{method}")
    end
    expect(api.operations.sort).to eq(['info', 'reset', 'access set-retries', 'access change-pin', 'access change-reset-code', 'access change-admin-pin', 'access unblock-pin', 'access set-signature-policy', 'keys info', 'keys set-touch', 'keys import', 'keys attest', 'certificates export', 'certificates delete', 'certificates import'].sort)
    expect(output.string).to include('no factory credentials', 'ECDH returns a raw shared secret')
  end
end
