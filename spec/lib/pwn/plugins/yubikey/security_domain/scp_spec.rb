# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/yubikey/security_domain/scp'

RSpec.describe PWN::Plugins::YubiKey::SecurityDomain::SCP do
  # NIST SP 800-38B / RFC 4493 examples. Public synthetic test material only.
  def hex(value)
    [value].pack('H*')
  end

  require_relative 'support'

  def scp03(card, **options)
    key = (0...16).to_a.pack('C*')
    described_class.open({ connection: card, scp: :scp03, kvn: 1, key_enc: key, key_mac: key, key_dek: key, confirm: true }.merge(options))
  end

  it 'verifies both SCP03 cryptograms and encrypted APDUs while retaining the authenticated status' do
    card = Scp03Card.new
    channel = scp03(card)
    expect(channel.exchange(protocol: :apdu, data: hex('00ca000003616263'), timeout: 1)).to eq("reply\x62\x82".b)
    expect(card.received).to eq('abc')
    expect(channel.descriptor).to include(secure_channel: :scp03, extended_apdu: true, authenticated: true)
    expect(channel.inspect).not_to include('key_', '@enc', '@chain')
    channel.close
    expect(card.closed).to be(true)
  end

  %i[mac status missing_mac truncated_ciphertext padding padding_long counter replay].each do |fault|
    it "fails closed and never passes data after #{fault}" do
      allow(SecureRandom).to receive(:random_bytes).with(8).and_return('HOSTRAND'.b)
      card = Scp03Card.new
      channel = scp03(card)
      channel.exchange(protocol: :apdu, data: hex('00ca0000')) if fault == :replay
      card.fault = fault
      expect { channel.exchange(protocol: :apdu, data: hex('00ca0000')) }.to raise_error(described_class::ChannelError)
      expect(card.closed).to be(true)
      count = card.commands.length
      expect { channel.exchange(protocol: :apdu, data: hex('00ca0000')) }.to raise_error(described_class::ChannelError, /closed/)
      expect(card.commands.length).to eq(count)
    end
  end

  it 'never sends host authentication after a wrong card cryptogram' do
    card = Scp03Card.new
    card.fault = :card_cryptogram
    expect { scp03(card) }.to raise_error(described_class::ChannelError, /cryptogram/)
    expect(card.commands.map { |data| data.getbyte(1) }).to eq([0xa4, 0x50])
    expect(card.closed).to be(true)
  end

  it 'validates consent, key lengths, protocol, key version and timeout before I/O' do
    [{ confirm: 'true' }, { key_enc: nil }, { key_mac: 'short' }, { kvn: 256 }, { kvn: -1 }, { timeout: Float::INFINITY }, { scp: :unknown }].each do |options|
      card = Scp03Card.new
      expect { scp03(card, **options) }.to raise_error(StandardError)
      expect(card.commands).to be_empty
    end
  end

  it 'supports extended command data and rejects malformed, wrapped and oversized APDUs' do
    card = Scp03Card.new
    channel = scp03(card)
    data = 'x'.b * 300
    command = hex('00da000000') + [data.bytesize].pack('n') + data + hex('0100')
    expect(channel.exchange(protocol: :apdu, data: command)).to eq("reply\x62\x82".b)
    expect(card.received).to eq(data)
    %w[00 00da00000001 00da00000200 04da0000].each do |malformed|
      expect { channel.exchange(protocol: :apdu, data: hex(malformed)) }.to raise_error(ArgumentError)
    end
    channel.instance_variable_set(:@enc_counter, 0x100000000)
    count = card.commands.length
    expect { channel.exchange(protocol: :apdu, data: hex('00ca0000')) }.to raise_error(described_class::ChannelError, /counter/)
    expect(card.commands.length).to eq(count)
  end

  it 'closes on uncertain transport failure and cancellation without retrying' do
    [IOError.new('synthetic'), Interrupt.new].each do |error|
      card = Scp03Card.new
      channel = scp03(card)
      allow(card).to receive(:exchange).and_raise(error)
      expect { channel.exchange(protocol: :apdu, data: hex('00ca0000')) }.to raise_error(error.class)
      expect(card.closed).to be(true)
    end
  end

  def certificate(key, issuer_key: key, issuer: nil, is_ca: false)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 7
    cert.subject = OpenSSL::X509::Name.parse(is_ca ? '/CN=Synthetic CA' : '/CN=Synthetic leaf')
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key
    cert.not_before = Time.utc(2020)
    cert.not_after = Time.utc(2090)
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.extensions = [factory.create_extension('basicConstraints', is_ca ? 'CA:TRUE' : 'CA:FALSE', true), factory.create_extension('keyUsage', is_ca ? 'keyCertSign,cRLSign' : 'keyAgreement', true)]
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  %i[scp11a scp11b scp11c].each do |variant|
    it "performs #{variant} receipt verification and encrypted exchange with an independent ECDH peer" do
      card = Scp11Card.new
      options = { connection: card, scp: variant, kvn: 1, card_public_key: card.public_key, confirm: true }
      unless variant == :scp11b
        ca_key = OpenSSL::PKey::EC.generate('prime256v1')
        ca = certificate(ca_key, is_ca: true)
        host_key = OpenSSL::PKey::EC.generate('prime256v1')
        leaf = certificate(host_key, issuer_key: ca_key, issuer: ca)
        options.merge!(oce_private_key: host_key, oce_certificates: [ca, leaf], oce_kid: 0x10, oce_kvn: 2)
      end
      channel = described_class.open(options)
      expect(channel.exchange(protocol: :apdu, data: hex('00ca0000'))).to eq("reply\x62\x82".b)
      expect(channel.authenticated?).to eq(variant == :scp11a)
      expect(card.commands.select { |c| c.getbyte(1) == 0x2a }.map { |c| c.byteslice(2, 2) }).to eq(["\x02\x90".b, "\x02\x10".b]) unless variant == :scp11b
    end
  end

  it 'authenticates a fetched leaf-last SCP11 bundle against explicit CA anchors' do
    card = Scp11Card.new
    ca_key = OpenSSL::PKey::EC.generate('prime256v1')
    ca = certificate(ca_key, is_ca: true)
    leaf = certificate(card.public_key, issuer_key: ca_key, issuer: ca)
    card.card_bundle = leaf.to_der
    channel = described_class.open(connection: card, scp: :scp11b, kvn: 1, ca_certificates: [ca], confirm: true)
    expect(channel.exchange(protocol: :apdu, data: hex('00ca0000'))).to eq("reply\x62\x82".b)
    expect(card.commands[1].unpack1('H*')).to eq('00cabf2106a60483021301')
  end

  it 'rejects untrusted, expired and pinned-mismatched card certificates before authentication' do
    card = Scp11Card.new
    ca_key = OpenSSL::PKey::EC.generate('prime256v1')
    ca = certificate(ca_key, is_ca: true)
    alien = certificate(OpenSSL::PKey::EC.generate('prime256v1'), is_ca: true)
    leaf = certificate(card.public_key, issuer_key: ca_key, issuer: ca)
    base = { connection: card, scp: :scp11b, kvn: 1, card_certificates: [leaf], confirm: true }
    expect { described_class.open(base.merge(ca_certificates: [alien])) }.to raise_error(described_class::ChannelError, /Untrusted/)
    expect { described_class.open(base.merge(card_public_key: alien.public_key)) }.to raise_error(described_class::ChannelError, /pin/)
    leaf.not_after = Time.utc(2021)
    leaf.sign(ca_key, OpenSSL::Digest.new('SHA256'))
    expect { described_class.open(base.merge(ca_certificates: [ca])) }.to raise_error(described_class::ChannelError, /validity/)
    expect(card.commands).to be_empty
  end

  it 'rejects a wrong SCP11 receipt and wrong card key without plaintext fallback' do
    %i[receipt pin].each do |fault|
      card = Scp11Card.new
      card.fault = fault
      key = fault == :pin ? OpenSSL::PKey::EC.generate('prime256v1') : card.public_key
      expect { described_class.open(connection: card, scp: :scp11b, kvn: 1, card_public_key: key, confirm: true) }.to raise_error(described_class::ChannelError, /receipt/)
      expect(card.closed).to be(true)
      expect(card.commands.map { |data| data.getbyte(1) }).to eq([0xa4, 0x88])
    end
  end

  it 'requires explicit card trust and valid OCE credentials before any authentication attempt' do
    card = Scp11Card.new
    expect { described_class.open(connection: card, scp: :scp11b, kvn: 1, confirm: true) }.to raise_error(ArgumentError, /pinned/)
    options = { connection: card, scp: :scp11a, kvn: 1, card_public_key: card.public_key, confirm: true }
    expect { described_class.open(options) }.to raise_error(KeyError)
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = certificate(OpenSSL::PKey::EC.generate('prime256v1'))
    expect { described_class.open(options.merge(oce_private_key: key, oce_certificates: [cert])) }.to raise_error(ArgumentError, /match/)
    expect(card.commands).to be_empty
  end

  it 'reassembles transport response fragments before one R-MAC verification without consuming another counter' do
    card = Scp03Card.new
    channel = scp03(card)
    calls = 0
    remainder = nil
    allow(card).to receive(:exchange).and_wrap_original do |original, opts|
      calls += 1
      if opts[:data] == hex('00c00000')
        remainder
      else
        reply = original.call(opts)
        remainder = reply.byteslice(7..)
        reply.byteslice(0, 7) + hex('6100')
      end
    end
    expect(channel.exchange(protocol: :apdu, data: hex('00ca0000'))).to eq("reply\x62\x82".b)
    expect(calls).to eq(2)
    expect(channel.instance_variable_get(:@enc_counter)).to eq(2)
  end

  it 'rejects conflicting KIDs, unsupported protocol metadata and truncated card cryptograms' do
    card = Scp03Card.new
    expect { scp03(card, kid: 0x13) }.to raise_error(ArgumentError, /KID/)
    expect(card.commands).to be_empty
    [->(reply) { reply.byteslice(0, 20) + hex('9000') }, lambda { |reply|
      reply.setbyte(11, 2)
      reply
    }, lambda { |reply|
         reply.setbyte(10, 7)
         reply
       }].each do |mutate|
      peer = Scp03Card.new
      allow(peer).to receive(:exchange).and_wrap_original do |original, options|
        reply = original.call(options)
        options[:data].getbyte(1) == 0x50 ? mutate.call(reply) : reply
      end
      expect { scp03(peer) }.to raise_error(described_class::ChannelError)
      expect(peer.commands.map { |data| data.getbyte(1) }).to eq([0xa4, 0x50])
    end
  end

  it 'rejects malformed peer EC points and repeated or truncated SCP11 receipt TLVs' do
    [->(response) { response.byteslice(0...-3) + hex('9000') }, lambda { |response|
      response.setbyte(3, 0)
      response
    }, ->(response) { response.byteslice(0...-2) + hex('8600') + hex('9000') }, ->(response) { response.byteslice(0, 2) + hex('8141') + response.byteslice(3..) }].each do |mutate|
      card = Scp11Card.new
      allow(card).to receive(:exchange).and_wrap_original do |original, options|
        response = original.call(options)
        options[:data].getbyte(1) == 0x88 ? mutate.call(response) : response
      end
      expect { described_class.open(connection: card, scp: :scp11b, kvn: 1, card_public_key: card.public_key, confirm: true) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
      expect(card.closed).to be(true)
    end
  end

  it 'carries Protocol SELECT and extended application APDUs through the real secure wrapper' do
    card = Scp03Card.new
    channel = scp03(card)
    card.handler = ->(_header, plaintext) { [plaintext, hex('9000')] }
    protocol = PWN::Plugins::YubiKey::Protocol
    aid = hex('a000000308')
    expect(protocol.select(connection: channel, aid: aid)).to eq(aid)
    payload = 'x'.b * 300
    expect(protocol.apdu(connection: channel, ins: 0xda, data: payload, extended: true)).to eq(payload)
    expect(card.commands.last.getbyte(4)).to eq(0)
    expect(card.commands.count { |command| command.getbyte(1) == 0xda }).to eq(1)
  end

  it 'bounds fragmented replies and closes without exposing an unauthenticated prefix' do
    card = Scp03Card.new
    channel = scp03(card)
    allow(card).to receive(:exchange).and_return(hex('006100'))
    expect { channel.exchange(protocol: :apdu, data: hex('00ca0000')) }.to raise_error(described_class::ChannelError, /fragmentation/)
    expect(card).to have_received(:exchange).exactly(64).times
    expect(card.closed).to be(true)
  end

  it 'implements all RFC 4493 AES-CMAC vectors, including empty and partial blocks' do
    crypto = described_class::Crypto.new
    key = hex('2b7e151628aed2a6abf7158809cf4f3c')
    message = hex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
    { 0 => 'bb1d6929e95937287fa37d129b756746', 16 => '070a16b46b4d4144f79bdd9dd04a287c', 40 => 'dfa66747de9ae63030ca32611497c827', 64 => '51f0bebf7e3b9d92fc49741779363cfe' }.each do |length, expected|
      expect(crypto.cmac(key, message.byteslice(0, length))).to eq(hex(expected))
    end
  end
end
