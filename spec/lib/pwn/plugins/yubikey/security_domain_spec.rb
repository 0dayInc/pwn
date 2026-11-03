# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/yubikey/security_domain'
require_relative 'security_domain/support'

class SDCard
  attr_reader :commands

  def initialize(replies)
    @commands = []
    @replies = replies
  end

  def descriptor
    { protocol: :apdu }
  end

  def exchange(opts)
    @commands << opts.fetch(:data)
    raise 'unexpected APDU' if @replies.empty?

    @replies.shift
  end

  def close
    :closed
  end
end

RSpec.describe PWN::Plugins::YubiKey::SecurityDomain do
  def hex(string)
    [string].pack('H*')
  end

  def authenticated_card
    card = Scp03Card.new
    key = (0...16).to_a.pack('C*')
    connection = described_class.secure_connection(connection: card, scp: :scp03, kvn: 1, key_enc: key, key_mac: key, key_dek: key, confirm: true)
    [card, connection, key]
  end

  it 'imports SCP03 keys in memory with DEK wrapping and verifies all key check values' do
    card, connection, dek = authenticated_card
    keys = %w[A B C].map { |char| char.b * 16 }
    crypto = ReferenceCrypto.new
    card.handler = lambda do |header, data|
      expect(header).to eq(hex('84d80281'))
      expect(data.getbyte(0)).to eq(7)
      offset = 1
      checks = keys.map do |key|
        expect(data.byteslice(offset, 2)).to eq(hex('8810'))
        expect(crypto.aes(dek, data.byteslice(offset + 2, 16), "\0".b * 16, decrypt: true)).to eq(key)
        check = crypto.aes(key, "\1".b * 16, "\0".b * 16).byteslice(0, 3)
        expect(data.byteslice(offset + 18, 4)).to eq("\3".b + check)
        offset += 22
        check
      end
      expect(data.bytesize).to eq(offset)
      ["\7".b + checks.join, hex('9000')]
    end
    expect(described_class.execute(args: ['keys', 'import', '1', '7', '--replace-kvn', '2'], connection: connection, key_enc: keys[0], key_mac: keys[1], key_dek: keys[2], confirm: true)).to include(imported: true, kid: 1, kvn: 7)
    expect(card.commands.none? { |command| keys.any? { |key| command.include?(key) } }).to be(true)
  end

  it 'generates an SCP11 key with explicit curve and replacement KVN and returns only its public PEM' do
    card, connection = authenticated_card
    generated = OpenSSL::PKey::EC.generate('prime256v1')
    card.handler = lambda do |header, data|
      expect(header).to eq(hex('84f10213'))
      expect(data).to eq(hex('07f00100'))
      [hex('b041') + generated.public_key.to_octet_string(:uncompressed), hex('9000')]
    end
    pem = described_class.execute(args: %w[keys generate 0x13 7 --replace-kvn 2], connection: connection, confirm: true)
    expect(OpenSSL::PKey.read(pem).public_to_der).to eq(generated.public_to_der)
    expect(OpenSSL::PKey.read(pem).private?).to be(false)
  end

  it 'imports a private SCP11 EC key as a DEK-wrapped scalar and a public CA key as an EC point' do
    [0x13, 0x10].each do |kid|
      card, connection, dek = authenticated_card
      key = OpenSSL::PKey::EC.generate('prime256v1')
      card.handler = lambda do |header, data|
        expect(header).to eq([0x84, 0xd8, 0, kid].pack('C*'))
        expect(data.getbyte(0)).to eq(7)
        if kid == 0x13
          expect(data.byteslice(1, 2)).to eq(hex('b120'))
          scalar = ReferenceCrypto.new.aes(dek, data.byteslice(3, 32), "\0".b * 16, decrypt: true)
          expect(OpenSSL::BN.new(scalar, 2)).to eq(key.private_key)
        else
          expect(data.byteslice(1, 67)).to eq(hex('b041') + key.public_key.to_octet_string(:uncompressed))
        end
        expect(data.byteslice(-4, 4)).to eq(hex('f0010000'))
        [hex('07'), hex('9000')]
      end
      material = kid == 0x13 ? key : OpenSSL::PKey.read(key.public_to_der)
      expect(described_class.execute(args: ['keys', 'import', kid.to_s, '7'], connection: connection, key: material, confirm: true)).to include(imported: true)
    end
  end

  it 'deletes an SCP03 keyset by version without treating the key identifier as a wildcard' do
    card, connection = authenticated_card
    card.handler = lambda do |header, data|
      expect(header).to eq(hex('84e40000'))
      expect(data).to eq(hex('d20107'))
      [''.b, hex('9000')]
    end
    expect(described_class.execute(args: %w[keys delete 1 7], connection: connection, confirm: true)).to include(deleted: true)
  end

  it 'encodes allowlisted certificate serials as nonnegative ASN1 integers' do
    card, connection = authenticated_card
    card.handler = lambda do |header, data|
      expect(header).to eq(hex('04e29000'))
      expect(data).to eq(hex('a60483021007700a9301009302008093017f'))
      [''.b, hex('9000')]
    end
    expect(described_class.execute(args: %w[keys set-allowlist 0x10 7 0 128 127], connection: connection, confirm: true)).to include(stored: true)
  end

  it 'resets only with explicit consent and bounds each destructive authentication loop' do
    card = SDCard.new(%w[9000 c00401018810c00402018810c00403018810c0041301b0209000 6a80 6983 6982 c00401ff88109000].map { |data| hex(data) })
    expect(described_class.execute(args: ['reset'], connection: card, confirm: true)).to include(reset: true)
    expect(card.commands[2].byteslice(0, 4)).to eq(hex('80500000'))
    expect(card.commands[4].byteslice(0, 4)).to eq(hex('80880113'))
    expect(card.commands.length).to eq(6)
  end

  def test_certificate
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 9
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=Synthetic SD')
    cert.not_before = Time.utc(2020)
    cert.not_after = Time.utc(2090)
    cert.public_key = key
    factory = OpenSSL::X509::ExtensionFactory.new
    cert.extensions = [factory.create_extension('keyUsage', 'keyAgreement', true)]
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  it 'exports stored certificate chains without exporting private key material' do
    certificate = test_certificate
    card = SDCard.new([hex('9000'), certificate.to_der + hex('9000')])
    expect(described_class.execute(args: %w[keys export 0x13 7], connection: card)).to eq(certificate.to_pem.b)
    expect(card.commands.last.byteslice(0, 4)).to eq(hex('00cabf21'))
    expect(card.commands.last.byteslice(-6, 6)).to eq(hex('a60483021307'))
  end

  it 'stores a certificate bundle and CA issuer with native binary STORE DATA templates' do
    card, connection = authenticated_card
    certificate = test_certificate
    payloads = []
    card.handler = lambda do |header, data|
      expect(header).to eq(hex('04e29000'))
      payloads << data
      [''.b, hex('9000')]
    end
    expect(described_class.execute(args: %w[keys set-certificate 0x13 7], connection: connection, certificates: [certificate], confirm: true)).to include(stored: true)
    expect(payloads[0].byteslice(0, 6)).to eq(hex('a60483021307'))
    body = PWN::Plugins::YubiKey::Protocol.untlv(data: payloads[0]).last
    expect(body).to eq(tag: 0xbf21, value: certificate.to_der)
    described_class.execute(args: %w[keys set-ca-issuer 0x13 7], connection: connection, ski: 'abc'.b, confirm: true)
    expect(payloads[1]).to eq(hex('a60c800101420361626383021307'))
  end

  it 'rejects unsupported, malformed and unconfirmed operations before any I/O' do
    cases = [
      { args: %w[keys generate 1 7], confirm: true },
      { args: %w[keys import 1 7 argv-secret], confirm: true },
      { args: %w[keys import 1 256], confirm: true },
      { args: %w[keys delete 1 0], confirm: true },
      { args: %w[keys delete 0 0], confirm: true },
      { args: %w[keys set-allowlist 0x10 7 -1], confirm: true },
      { args: ['reset'], confirm: 'true' },
      { args: %w[keys delete 0x13 7 --force] },
      { args: ['invented'] }
    ]
    cases.each do |options|
      card = SDCard.new([])
      expect { described_class.execute(options.merge(connection: card)) }.to raise_error(StandardError)
      expect(card.commands).to be_empty
    end
    expect(described_class.execute(args: ['keys'])).to eq(operations: described_class.operations)
  end

  it 'does not trust forged authentication descriptors or allow SCP11b administration' do
    fake = SDCard.new([])
    allow(fake).to receive(:descriptor).and_return(protocol: :apdu, authenticated: true, secure_channel: :scp03)
    expect { described_class.execute(args: %w[keys delete 0x13 7], connection: fake, confirm: true) }.to raise_error(described_class::SCP::ChannelError)
    card = Scp11Card.new
    channel = described_class.secure_connection(connection: card, scp: :scp11b, kvn: 1, card_public_key: card.public_key, confirm: true)
    count = card.commands.length
    expect { described_class.execute(args: %w[keys generate 0x13 7], connection: channel, confirm: true) }.to raise_error(described_class::SCP::ChannelError)
    expect { described_class.execute(args: %w[reset], connection: channel, confirm: true) }.to raise_error(ArgumentError)
    expect(card.commands.length).to eq(count)
  end

  it 'refuses bad key check values without retrying an uncertain PUT KEY' do
    card, connection = authenticated_card
    card.handler = ->(_header, _data) { [hex('07'), hex('9000')] }
    keys = 'x'.b * 16
    expect { described_class.execute(args: %w[keys import 1 7], key_enc: keys, key_mac: keys, key_dek: keys, connection: connection, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /check value/)
    expect(card.commands.count { |command| command.getbyte(1) == 0xd8 }).to eq(1)
  end

  it 'rejects malformed or duplicate key metadata and missing certificate exports' do
    %w[c003010188 c00401018810c00401018810].each do |wire|
      card = SDCard.new([hex('9000'), hex(wire) + hex('9000')])
      expect { described_class.execute(args: ['info'], connection: card) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    end
    card = SDCard.new([hex('9000'), hex('9000')])
    expect { described_class.execute(args: %w[keys export 0x13 7], connection: card) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /No certificate/)
  end

  it 'bounds reset retries and rejects unexpected statuses without automatically retrying writes' do
    initial = [hex('9000'), hex('c0041301b0209000')]
    card = SDCard.new(initial + Array.new(65) { hex('6a80') })
    expect { described_class.execute(args: ['reset'], connection: card, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /bound/)
    expect(card.commands.count { |command| command.getbyte(1) == 0x88 }).to eq(65)
    card = SDCard.new(initial + [hex('6f00')])
    expect { described_class.execute(args: ['reset'], connection: card, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::Protocol::APDUError)
    expect(card.commands.count { |command| command.getbyte(1) == 0x88 }).to eq(1)
  end

  it 'imports a CA certificate in memory and stores its explicit issuer identifier' do
    card, connection = authenticated_card
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = test_certificate
    cert.public_key = key
    factory = OpenSSL::X509::ExtensionFactory.new
    cert.extensions = [factory.create_extension('basicConstraints', 'CA:TRUE', true), factory.create_extension('keyUsage', 'keyCertSign', true)]
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    calls = []
    card.handler = lambda do |header, data|
      calls << [header, data]
      [header.getbyte(1) == 0xd8 ? hex('07') : ''.b, hex('9000')]
    end
    expect(described_class.execute(args: %w[keys import 0x10 7], connection: connection, certificate: cert, ski: 'abc', confirm: true)).to include(imported: true)
    expect(calls[0][1].byteslice(1, 67)).to eq(hex('b041') + key.public_key.to_octet_string(:uncompressed))
    expect(calls[1][1]).to eq(hex('a60c800100420361626383021007'))
  end

  it 'validates an imported private key certificate before PUT KEY and stores the matching bundle' do
    card, connection = authenticated_card
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = test_certificate
    initial_count = card.commands.length
    expect { described_class.execute(args: %w[keys import 0x13 7], connection: connection, key: key, certificates: [cert], confirm: true) }.to raise_error(ArgumentError, /match/)
    expect(card.commands.length).to eq(initial_count)
    cert.public_key = key
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    calls = []
    card.handler = lambda do |header, data|
      calls << [header, data]
      [header.getbyte(1) == 0xd8 ? hex('07') : ''.b, hex('9000')]
    end
    expect(described_class.execute(args: %w[keys import 0x13 7], connection: connection, key: key, certificates: [cert], confirm: true)).to include(imported: true)
    expect(calls.map { |header, _data| header.getbyte(1) }).to eq([0xd8, 0xe2])
    expect(calls.last.last).to include(cert.to_der)
  end

  it 'encodes each documented EC curve identifier for native key generation' do
    { 'prime256v1' => 0, 'secp384r1' => 1, 'secp521r1' => 2, 'brainpoolP256r1' => 3, 'brainpoolP384r1' => 5, 'brainpoolP512r1' => 7 }.each do |curve, identifier|
      card, connection = authenticated_card
      public_key = OpenSSL::PKey::EC.generate(curve)
      card.handler = lambda do |_header, data|
        expect(data).to eq([7, 0xf0, 1, identifier].pack('C*'))
        encoded = public_key.public_key.to_octet_string(:uncompressed)
        size = encoded.bytesize < 128 ? [encoded.bytesize].pack('C') : [0x81, encoded.bytesize].pack('CC')
        ["\xb0".b + size + encoded, hex('9000')]
      end
      result = described_class.execute(args: %w[keys generate 0x13 7], curve: curve, connection: connection, confirm: true)
      expect(OpenSSL::PKey.read(result).public_to_der).to eq(public_key.public_to_der)
    end
  end

  it 'validates the complete reset inventory before blocking keys and checks post-reset state' do
    card = SDCard.new([hex('9000'), hex('c00401018810c004fe01b0209000')])
    expect { described_class.execute(args: ['reset'], connection: card, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /Unknown/)
    expect(card.commands.length).to eq(2)
    card = SDCard.new([hex('9000'), hex('c004010188109000'), hex('6983'), hex('c004010188109000')])
    expect { described_class.execute(args: ['reset'], connection: card, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /reset state/)
  end

  it 'lists native key types, CA identifiers and card recognition data' do
    card = SDCard.new(%w[9000 c006010188100100c0041301b0209000 73036162639000 4203616263830213019000 6a88].map { |data| hex(data) })
    info = described_class.execute(args: ['info'], connection: card)
    expect(info[:keys]).to eq([{ kid: 1, kvn: 1, types: { 0x88 => 16, 1 => 0 } }, { kid: 0x13, kvn: 1, types: { 0xb0 => 32 } }])
    expect(info[:ca_identifiers]).to eq([{ kid: 0x13, kvn: 1, ski: 'abc'.b, kind: :kloc }])
    expect(info[:card_recognition_data]).to eq('abc'.b)
    expect(card.commands.map { |command| command.byteslice(0, 4).unpack1('H*') }).to eq(%w[00a40400 00ca00e0 00ca0066 00caff33 00caff34])
  end
end
