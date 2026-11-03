# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'pwn/plugins/yubikey'
require 'pwn/plugins/yubikey/protocol' if File.file?(File.expand_path('../../../../../lib/pwn/plugins/yubikey/protocol.rb', __dir__))
require 'pwn/plugins/yubikey/piv'

# Synthetic card boundary; independently frames TLV and ISO APDUs.
class PivWireCard # rubocop:disable Metrics/ClassLength
  attr_accessor :version, :management_key, :management_algorithm, :corrupt_auth, :pin_status, :bio
  attr_reader :commands, :objects, :keys

  def initialize
    @version = [5, 7, 1]
    @management_key = (1..24).to_a.pack('C*')
    @management_algorithm = 3
    @commands = []
    @objects = {}
    @keys = {}
    @chain = ''.b
    @pin_status = 0x9000
    @pin_tries = @pin_total = 3
    @puk_tries = @puk_total = 3
    @default_refs = false
  end

  def descriptor
    { protocol: :apdu }
  end

  def tlv(tag, value = ''.b)
    head = tag > 255 ? [tag].pack('n') : [tag].pack('C')
    length = value.bytesize
    head + (length < 128 ? [length].pack('C') : [0x82, length].pack('Cn')) + value.b
  end

  def fields(bytes)
    result = {}
    offset = 0
    while offset < bytes.bytesize
      tag = bytes.getbyte(offset)
      offset += 1
      if tag & 31 == 31
        tag = (tag << 8) | bytes.getbyte(offset)
        offset += 1
      end
      length = bytes.getbyte(offset)
      offset += 1
      if length >= 128
        size = length & 127
        length = bytes.byteslice(offset, size).bytes.reduce(0) { |n, b| (n << 8) | b }
        offset += size
      end
      result[tag] = bytes.byteslice(offset, length)
      offset += length
    end
    result
  end

  def exchange(opts)
    raise 'wrong boundary' unless opts[:protocol] == :apdu

    bytes = opts.fetch(:data)
    cla, ins, p1, param2 = bytes.bytes.first(4)
    length = bytes.bytesize > 5 ? bytes.getbyte(4) : 0
    offset = 5
    if length.zero? && bytes.bytesize > 7
      length = bytes.byteslice(5, 2).unpack1('n')
      offset = 7
    end
    data = @chain + (bytes.byteslice(offset, length) || ''.b)
    if cla.anybits?(16)
      @chain = data
      return ['9000'].pack('H*')
    end
    @chain = ''.b
    @commands << [ins, p1, param2, data]
    value = command(ins, p1, param2, data)
    value.is_a?(Integer) ? [value].pack('n') : value + ['9000'].pack('H*')
  end

  def command(ins, param1, param2, data)
    case ins
    when 0xa4, 0x24 then ''.b
    when 0xfa
      @pin_total = @pin_tries = param1
      @puk_total = @puk_tries = param2
      @default_refs = true
      ''.b
    when 0xfd then @version.pack('C*')
    when 0xf8 then [123].pack('N')
    when 0xf7
      case param2
      when 0x9b then tlv(1, [@management_algorithm].pack('C')) + tlv(2, "\x00\x01".b) + tlv(5, [@default_refs ? 1 : 0].pack('C'))
      when 0x80, 0x81 then tlv(5, [@default_refs ? 1 : 0].pack('C')) + tlv(6, (param2 == 0x80 ? [@pin_total, @pin_tries] : [@puk_total, @puk_tries]).pack('C*'))
      when 0x96 then @bio ? tlv(7, "\x01".b) + tlv(6, "\x03".b) + tlv(8, "\x00".b) : 0x6a88
      else
        record = @keys[param2]
        record ? tlv(1, [record[:algorithm]].pack('C')) + tlv(2, record.fetch(:policy, "\x02\x01".b)) + tlv(3, [record.fetch(:origin, 1)].pack('C')) + tlv(4, public_bytes(record.fetch(:key))) : 0x6a88
      end
    when 0x47
      values = fields(fields(data).fetch(0xac))
      id = values.fetch(0x80).getbyte(0)
      key = case id
            when 6, 7, 5, 0x16 then OpenSSL::PKey::RSA.generate({ 6 => 1024, 7 => 2048, 5 => 3072, 0x16 => 4096 }.fetch(id))
            when 0x11, 0x14 then OpenSSL::PKey::EC.generate(id == 0x11 ? 'prime256v1' : 'secp384r1')
            when 0xe0, 0xe1 then OpenSSL::PKey.generate_key(id == 0xe0 ? 'ED25519' : 'X25519')
            else raise 'invalid algorithm'
            end
      @keys[param2] = { key: key, algorithm: id, origin: 1, policy: values.fetch(0xaa, "\x02".b) + values.fetch(0xab, "\x01".b) }
      tlv(0x7f49, public_bytes(key))
    when 0xfe
      values = fields(data)
      key = import_key(param1, values)
      @keys[param2] = { key: key, algorithm: param1, origin: 2, policy: values.fetch(0xaa, "\x02".b) + values.fetch(0xab, "\x01".b) }
      ''.b
    when 0xf6
      return 0x6a88 unless @keys.key?(param2)
      return 0x6a80 if param1 != 0xff && @keys.key?(param1)

      removed = @keys.delete(param2)
      @keys[param1] = removed unless param1 == 0xff
      ''.b
    when 0xf9
      record = @keys[param1]
      return 0x6a80 unless record && record[:origin] == 1

      key = record.fetch(:key)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 17
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=synthetic attestation')
      cert.public_key = OpenSSL::PKey.read(key.public_to_der)
      cert.not_before = Time.now
      cert.not_after = Time.now + 3600
      cert.sign(OpenSSL::PKey::EC.generate('prime256v1'), 'SHA256')
      cert.to_der
    when 0x20
      if data == "\xff".b * 8
        @pin_tries = [@pin_tries - 1, 0].max
        0x63c0 | @pin_tries
      else
        @pin_status
      end
    when 0x2c
      if data == "\xff".b * 16
        @puk_tries = [@puk_tries - 1, 0].max
        0x63c0 | @puk_tries
      else
        ''.b
      end
    when 0xfb
      return 0x6985 unless @pin_tries.zero? && @puk_tries.zero?

      @objects.clear
      @keys.clear
      @pin_tries = @puk_tries = 3
      @default_refs = true
      ''.b
    when 0x87
      auth = fields(fields(data).fetch(0x7c))
      return private_operation(param2, auth) unless param2 == 0x9b

      size = @management_algorithm == 3 ? 8 : 16
      if auth.fetch(0x80).empty?
        tlv(0x7c, tlv(0x80, cipher("\xa5".b * size)))
      else
        raise 'incorrect witness' unless auth.fetch(0x80) == "\xa5".b * size

        tlv(0x7c, tlv(0x82, @corrupt_auth ? "\x00".b * size : cipher(auth.fetch(0x81))))
      end
    when 0xcb
      object_id = fields(data).fetch(0x5c).unpack1('H*').to_i(16)
      if @objects.key?(object_id)
        tlv(object_id == 0x7e ? 0x7e : 0x53, @objects.fetch(object_id))
      else
        0x6a82
      end
    when 0xdb
      values = fields(data)
      @objects[values.fetch(0x5c).unpack1('H*').to_i(16)] = values.fetch(0x53)
      ''.b
    when 0xff
      @management_algorithm = data.getbyte(0)
      @management_key = fields(data.byteslice(1..)).fetch(0x9b)
      ''.b
    else raise format('Unexpected PIV INS %02x', ins)
    end
  end

  def private_operation(slot, values)
    record = @keys.fetch(slot)
    key = record.fetch(:key)
    result = if values.key?(0x85)
               bytes = values.fetch(0x85)
               if key.is_a?(OpenSSL::PKey::EC)
                 peer = OpenSSL::PKey::EC::Point.new(key.group, OpenSSL::BN.new(bytes, 2))
                 key.dh_compute_key(peer)
               else
                 asn1 = OpenSSL::ASN1
                 peer = OpenSSL::PKey.read(asn1::Sequence.new([asn1::Sequence.new([asn1::ObjectId.new('X25519')]), asn1::BitString.new(bytes)]).to_der)
                 key.derive(peer)
               end
             elsif key.is_a?(OpenSSL::PKey::RSA)
               key.private_decrypt(values.fetch(0x81), OpenSSL::PKey::RSA::NO_PADDING)
             elsif key.is_a?(OpenSSL::PKey::EC)
               key.dsa_sign_asn1(values.fetch(0x81))
             else
               key.sign(nil, values.fetch(0x81))
             end
    tlv(0x7c, tlv(0x82, result))
  end

  def public_bytes(key)
    if key.is_a?(OpenSSL::PKey::RSA)
      tlv(0x81, key.n.to_s(2)) + tlv(0x82, key.e.to_s(2))
    elsif key.is_a?(OpenSSL::PKey::EC)
      tlv(0x86, key.public_key.to_octet_string(:uncompressed))
    else
      tlv(0x86, key.raw_public_key)
    end
  end

  def import_key(id, values)
    asn1 = OpenSSL::ASN1
    if [6, 7, 5, 0x16].include?(id)
      p, q, dmp, dmq, iqmp = (1..5).map { |tag| OpenSSL::BN.new(values.fetch(tag), 2) }
      e = OpenSSL::BN.new('65537')
      d = e.mod_inverse((p - 1) * (q - 1))
      OpenSSL::PKey.read(asn1::Sequence.new([0, p * q, e, d, p, q, dmp, dmq, iqmp].map { |n| asn1::Integer.new(n) }).to_der)
    elsif [0x11, 0x14].include?(id)
      OpenSSL::PKey.read(asn1::Sequence.new([asn1::Integer.new(1), asn1::OctetString.new(values.fetch(6)), asn1::ASN1Data.new([asn1::ObjectId.new(id == 0x11 ? 'prime256v1' : 'secp384r1')], 0, :CONTEXT_SPECIFIC)]).to_der)
    else
      OpenSSL::PKey.read(asn1::Sequence.new([asn1::Integer.new(0), asn1::Sequence.new([asn1::ObjectId.new(id == 0xe0 ? 'ED25519' : 'X25519')]), asn1::OctetString.new(asn1::OctetString.new(values.fetch(id == 0xe0 ? 7 : 8)).to_der)]).to_der)
    end
  end

  def cipher(data)
    cipher = OpenSSL::Cipher.new({ 3 => 'DES-EDE3-ECB', 8 => 'AES-128-ECB', 10 => 'AES-192-ECB', 12 => 'AES-256-ECB' }.fetch(@management_algorithm))
    cipher.encrypt
    cipher.padding = 0
    cipher.key = @management_key
    cipher.update(data) + cipher.final
  end
end

RSpec.describe 'Native PIV' do
  let(:piv) { PWN::Plugins::YubiKey::PIV }
  let(:card) { PivWireCard.new }
  let(:authorized) { { connection: card, confirm: true, management_key: card.management_key, pin: '765432' } }
  # Literal C/R-APDUs from the PIV wire specification, not the production codec.
  def wire_card(pairs)
    double('PCSC connection').tap do |card|
      pairs.each do |command, response|
        expect(card).to receive(:exchange).with(hash_including(protocol: :apdu, data: [command].pack('H*'))).ordered.and_return([response].pack('H*'))
      end
    end
  end

  it 'verifies a supplied PIN with an ISO padded VERIFY command' do
    card = wire_card([
                       %w[00a404000ba000000308000010000100 9000],
                       %w[0020008008373635343332ffff 9000]
                     ])
    expect(PWN::Plugins::YubiKey::PIV.verify_pin(connection: card, pin: '765432', confirm: true)).to eq(:verified)
  end

  { 3 => 24, 8 => 16, 10 => 24, 12 => 32 }.each do |algorithm, size|
    it "mutually authenticates algorithm #{algorithm} with a fresh verified challenge" do
      card.management_algorithm = algorithm
      card.management_key = (1..size).to_a.pack('C*')
      2.times { expect(piv.authenticate(authorized)).to eq(:authenticated) }
      challenges = card.commands.select { |ins, _, slot, data| ins == 0x87 && slot == 0x9b && data.bytesize > 4 }
      expect(challenges.size).to eq(2)
      expect(challenges.first.last).not_to eq(challenges.last.last)
    end
  end

  it 'rejects an invalid management witness response without performing a write' do
    card.corrupt_auth = true
    expect { piv.authenticate(authorized) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /authentication/)
  end

  it 'changes and unblocks references with literal ISO7816 command bytes' do
    [[%w[access change-pin], :new_pin, 0x24, 0x80, '765432'],
     [%w[access change-puk], :new_puk, 0x24, 0x81, '87654321'],
     [%w[access unblock-pin], :new_pin, 0x2c, 0x80, '87654321']].each do |args, field, instruction, reference, old|
      expect(piv.execute(authorized.merge(args: args, puk: '87654321', field => '246810'))).to include(status: :changed)
      expect(card.commands).to include([instruction, 0, reference, old.b.ljust(8, "\xff".b) + "246810\xff\xff".b])
    end
  end

  it 'reports remaining retries without echoing credentials or retrying' do
    card.pin_status = 0x63c2
    expect { piv.verify_pin(authorized) }.to raise_error(PWN::Plugins::YubiKey::PIV::PinError) { |error| expect(error.attempts_remaining).to eq(2) }
    expect(card.commands.count { |ins,| ins == 0x20 }).to eq(1)
  end

  it 'sets retry limits only after management and PIN authentication' do
    expect(piv.execute(authorized.merge(args: %w[access set-retries 5 0]))).to include(status: :changed)
    expect(card.commands.select { |ins,| [0x87, 0x20, 0xfa].include?(ins) }.map(&:first)).to eq([0x87, 0x87, 0x20, 0xfa])
    expect(card.commands).to include([0xfa, 5, 0, ''.b])
  end

  it 'rejects argv secrets and invalid retry limits before authenticating' do
    [%w[access change-pin --pin 123456], %w[access set-retries 0 3]].each do |args|
      expect { piv.execute(authorized.merge(args: args)) }.to raise_error(ArgumentError)
    end
    expect(card.commands).to be_empty
  end

  it 'round-trips raw objects without text conversion and guards the protected-key object' do
    data = "\x00\xffobject\x80".b
    expect(piv.execute(authorized.merge(args: %w[objects import 5f1234 -], input: data))).to include(status: :written)
    expect(piv.execute(connection: card, args: %w[objects export 5f1234 -])).to eq(data)
    expect(card.commands).to include([0xdb, 0x3f, 0xff, ['5c035f1234530900ff6f626a65637480'].pack('H*')])
    card.objects[0x5fff00] = ['8003810102'].pack('H*')
    expect { piv.execute(authorized.merge(args: %w[objects import printed -], input: 'not a key')) }.to raise_error(ArgumentError, /protected/)
  end

  it 'generates valid CHUID and CCC objects and verifies each persisted value' do
    %w[CHUID CCC].each do |object|
      expect(piv.execute(authorized.merge(args: ['objects', 'generate', object]))).to include(status: :written)
    end
    chuid = card.fields(card.objects.fetch(0x5fc102))
    expect(chuid.fetch(0x30)).to eq(['d4e739da739ced39ce739d836858210842108421c84210c3eb'].pack('H*'))
    expect(chuid.fetch(0x34).bytesize).to eq(16)
    expect(chuid.fetch(0x35)).to eq('20300101')
    expect(card.fields(card.objects.fetch(0x5fc107)).fetch(0xf0).bytesize).to eq(21)
    expect(card.commands.select { |ins,| ins == 0xdb }.size).to eq(2)
  end

  it 'rotates and stores an AES management key under PIN protection without returning it' do
    replacement = 'Z'.b * 32
    result = piv.execute(authorized.merge(args: %w[access change-management-key --algorithm AES256 --protect], new_management_key: replacement))
    expect(result).to include(status: :changed, protected: true)
    expect(result.inspect).not_to include(replacement)
    expect(card.management_key).to eq(replacement)
    expect(card.management_algorithm).to eq(12)
    expect(card.objects.fetch(0x5fc109)).to eq(card.tlv(0x88, card.tlv(0x89, replacement)))
    expect(card.objects.fetch(0x5fff00)).to eq(['8003810102'].pack('H*'))
    expect(piv.execute(connection: card, confirm: true, pin: '765432', args: %w[objects generate CCC], use_protected_key: true)).to include(status: :written)
  end

  it 'rejects AES management rotation on older firmware before authentication' do
    card.version = [5, 3, 1]
    expect { piv.execute(authorized.merge(args: %w[access change-management-key --algorithm AES128], new_management_key: 'Z' * 16)) }.to raise_error(piv::UnsupportedError)
    expect(!card.commands.map(&:first).intersect?([0x87, 0xff])).to be(true)
  end

  %w[RSA1024 RSA2048 RSA3072 RSA4096 ECCP256 ECCP384 ED25519 X25519].each do |algorithm|
    it "generates, exports and imports #{algorithm} with independent key reconstruction" do
      pem = piv.execute(authorized.merge(args: ['keys', 'generate', '9a', '-', '--algorithm', algorithm, '--pin-policy', 'ALWAYS', '--touch-policy', 'CACHED']))
      public_key = OpenSSL::PKey.read(pem)
      expect(public_key.public_to_der).to eq(card.keys.fetch(0x9a).fetch(:key).public_to_der)
      expect(piv.execute(connection: card, args: %w[keys info 9a])).to include(algorithm: algorithm, pin_policy: 'ALWAYS', touch_policy: 'CACHED', generated: true)
      expect(OpenSSL::PKey.read(piv.execute(connection: card, args: %w[keys export 9a -])).public_to_der).to eq(public_key.public_to_der)
      private_key = card.keys.fetch(0x9a).fetch(:key)
      expect(piv.execute(authorized.merge(args: %w[keys import 9c -], input: private_key.private_to_pem))).to include(status: :imported, algorithm: algorithm)
      expect(card.keys.fetch(0x9c).fetch(:key).public_to_der).to eq(public_key.public_to_der)
      expect(piv.execute(connection: card, args: %w[keys info 9c])).to include(generated: false)
    end
  end

  it 'attests, moves and deletes only the selected key with 5.7 wire commands' do
    pem = piv.execute(authorized.merge(args: %w[keys generate 9a - --algorithm ECCP256]))
    attestation = OpenSSL::X509::Certificate.new(piv.execute(connection: card, args: %w[keys attest 9a -]))
    expect(attestation.public_key.public_to_der).to eq(OpenSSL::PKey.read(pem).public_to_der)
    expect(piv.execute(authorized.merge(args: %w[keys move 9a 82]))).to include(status: :moved)
    expect(card.commands).to include([0xf6, 0x82, 0x9a, ''.b])
    expect(piv.execute(authorized.merge(args: %w[keys delete 82]))).to include(status: :deleted)
    expect(card.commands).to include([0xf6, 0xff, 0x82, ''.b])
    expect(card.keys).to be_empty
  end

  it 'applies version, ROCA, FIPS and biometric policy restrictions before key mutation' do
    [[[5, 6, 3], 'ED25519', []], [[4, 3, 4], 'RSA2048', []], [[3, 4, 0], 'ECCP384', []],
     [[4, 4, 1], 'RSA1024', []], [[5, 7, 0], 'ECCP256', %w[--pin-policy MATCH_ALWAYS]]].each do |version, algorithm, flags|
      card.version = version
      expect { piv.execute(authorized.merge(args: ['keys', 'generate', '9a', '-', '--algorithm', algorithm] + flags)) }.to raise_error(piv::UnsupportedError)
    end
    expect(!card.commands.map(&:first).intersect?([0x47, 0x87])).to be(true)
  end

  %w[RSA1024 RSA2048 RSA3072 RSA4096 ECCP256 ECCP384 ED25519].each do |algorithm|
    it "signs actual messages with card-backed #{algorithm} and validates with OpenSSL" do
      pem = piv.execute(authorized.merge(args: ['keys', 'generate', '9a', '-', '--algorithm', algorithm]))
      key = OpenSSL::PKey.read(pem)
      message = "device-backed signature\x00".b
      signature = piv.sign(authorized.merge(slot: '9a', algorithm: algorithm, message: message))
      expect(key.verify(algorithm == 'ED25519' ? nil : 'SHA256', signature, message)).to be(true)
      if algorithm.start_with?('RSA')
        signature = piv.sign(authorized.merge(slot: '9a', algorithm: algorithm, message: message, padding: :pss))
        expect(key.verify_pss('SHA256', signature, message, salt_length: :digest, mgf1_hash: 'SHA256')).to be(true)
      end
    end
  end

  it 'decrypts RSA OAEP and PKCS1 blocks through the real card operation' do
    key = OpenSSL::PKey.read(piv.execute(authorized.merge(args: %w[keys generate 9d - --algorithm RSA2048])))
    message = "encrypted by the host\x00".b
    ciphertext = key.encrypt(message, 'rsa_padding_mode' => 'oaep', 'rsa_oaep_md' => 'SHA256')
    expect(piv.decrypt(authorized.merge(slot: '9d', ciphertext: ciphertext, padding: :oaep, hash_algorithm: 'SHA256'))).to eq(message)
    ciphertext = key.public_encrypt(message)
    expect(piv.decrypt(authorized.merge(slot: '9d', ciphertext: ciphertext, padding: :pkcs1))).to eq(message)
  end

  %w[ECCP256 ECCP384 X25519].each do |algorithm|
    it "derives matching shared secrets with #{algorithm}" do
      key = OpenSSL::PKey.read(piv.execute(authorized.merge(args: ['keys', 'generate', '9d', '-', '--algorithm', algorithm])))
      peer = if algorithm == 'X25519'
               OpenSSL::PKey.generate_key('X25519')
             else
               OpenSSL::PKey::EC.generate(algorithm == 'ECCP256' ? 'prime256v1' : 'secp384r1')
             end
      actual = piv.calculate_secret(authorized.merge(slot: '9d', peer_public_key: peer.public_to_pem))
      expect(actual).to eq(peer.derive(key))
      expect(card.commands.select { |ins, _, slot,| ins == 0x87 && slot == 0x9d }.last.last).to include([0x85].pack('C'))
    end
  end

  %w[RSA2048 ECCP256 ECCP384 ED25519].each do |algorithm|
    it "builds verified certificates and CSRs signed by the #{algorithm} device key" do
      pem = piv.execute(authorized.merge(args: ['keys', 'generate', '9a', '-', '--algorithm', algorithm]))
      result = piv.execute(authorized.merge(args: ['certificates', 'generate', '9a', '-', '--subject', 'CN=Native PIV,O=Test', '--valid-days', '10'], input: pem))
      cert = OpenSSL::X509::Certificate.new(result.fetch(:certificate))
      expect(cert.verify(cert.public_key)).to be(true)
      expect(cert.subject.to_s).to include('CN=Native PIV')
      expect(cert.not_after - cert.not_before).to eq(864_000)
      exported = OpenSSL::X509::Certificate.new(piv.execute(connection: card, args: %w[certificates export 9a -]))
      expect(exported.to_der).to eq(cert.to_der)
      csr = OpenSSL::X509::Request.new(piv.execute(authorized.merge(args: ['certificates', 'request', '9a', '-', '-', '--subject', 'CN=Native CSR'], input: pem)))
      expect(csr.verify(csr.public_key)).to be(true)
      expect(csr.public_key.public_to_der).to eq(cert.public_key.public_to_der)
      expect(card.objects).to have_key(0x5fc102)
    end
  end

  it 'imports compressed certificates, verifies key ownership and deletes without deleting the key' do
    pem = piv.execute(authorized.merge(args: %w[keys generate 9a - --algorithm ECCP256]))
    generated = piv.execute(authorized.merge(args: ['certificates', 'generate', '9a', '-', '--subject', 'CN=test'], input: pem))
    cert = OpenSSL::X509::Certificate.new(generated.fetch(:certificate))
    expect(piv.execute(authorized.merge(args: %w[certificates import 9a - --compress --verify --no-update-chuid], input: cert.to_der))).to include(status: :written)
    body = card.fields(card.objects.fetch(0x5fc105))
    expect(body.fetch(0x71)).to eq("\x01".b)
    expect(OpenSSL::X509::Certificate.new(piv.execute(connection: card, args: %w[certificates export 9a - --format DER])).to_der).to eq(cert.to_der)
    expect(piv.execute(authorized.merge(args: %w[certificates delete 9a --no-update-chuid]))).to include(status: :written)
    expect(card.objects.fetch(0x5fc105)).to be_empty
    expect(card.keys).to have_key(0x9a)
  end

  it 'preserves signed or corrupt CHUID data rather than replacing it during certificate writes' do
    pem = piv.execute(authorized.merge(args: %w[keys generate 9a - --algorithm ECCP256]))
    ['broken'.b, card.tlv(0x34, 'x' * 16) + card.tlv(0x3e, 'signed')].each do |chuid|
      card.objects[0x5fc102] = chuid
      piv.execute(authorized.merge(args: ['certificates', 'generate', '9a', '-', '--subject', 'CN=test'], input: pem))
      expect(card.objects.fetch(0x5fc102)).to eq(chuid)
    end
  end

  it 'resets only after explicitly authorized blocking and verifies the reset metadata' do
    expect { piv.execute(connection: card, confirm: true, args: ['reset']) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    expect(!card.commands.map(&:first).intersect?([0x20, 0x2c])).to be(true)
    expect(piv.execute(connection: card, confirm: true, block_retries: true, args: ['reset'])).to include(status: :reset)
    expect(card.commands.count { |ins,| ins == 0x20 }).to eq(3)
    expect(card.commands.count { |ins,| ins == 0x2c }).to eq(3)
  end

  it 'refuses reset blocking on biometric devices with enrolled fingerprints' do
    card.bio = true
    expect { piv.execute(connection: card, confirm: true, block_retries: true, args: ['reset']) }.to raise_error(piv::UnsupportedError)
    expect(!card.commands.map(&:first).intersect?([0x20, 0x2c, 0xfb])).to be(true)
  end

  it 'returns a complete read-only PIV inventory and local group help' do
    %w[access keys certificates objects].each { |group| expect(piv.execute(args: [group])).to include(application: :piv) }
    expect(piv.execute(connection: card, args: ['info'])).to include(version: [5, 7, 1], serial: 123, pin: { default: false, total_attempts: 3, attempts_remaining: 3 }, slots: {})
    expect(!card.commands.map(&:first).intersect?([0x20, 0x87, 0xdb])).to be(true)
  end

  it 'preserves legacy PIN-derived management access when changing the PIN' do
    salt = 'S' * 16
    card.objects[0x5fff00] = card.tlv(0x80, card.tlv(0x82, salt))
    card.management_key = OpenSSL::PKCS5.pbkdf2_hmac('765432', salt, 10_000, 24, 'SHA1')
    expect(piv.execute(authorized.merge(args: %w[access change-pin], new_pin: '246810'))).to include(status: :changed)
    new_salt = card.fields(card.fields(card.objects.fetch(0x5fff00)).fetch(0x80)).fetch(0x82)
    expect(new_salt).not_to eq(salt)
    expect(card.management_key).to eq(OpenSSL::PKCS5.pbkdf2_hmac('246810', new_salt, 10_000, 24, 'SHA1'))
  end
end

RSpec.describe 'Native PIV safety and compatibility' do
  let(:piv) { PWN::Plugins::YubiKey::PIV }
  let(:card) { PivWireCard.new }
  let(:authorized) { { connection: card, confirm: true, management_key: card.management_key, pin: '765432' } }

  it 'preflights formats, names, secrets and policies before irreversible commands' do
    invalid = [
      { args: %w[keys generate 9a - --format junk] },
      { args: %w[keys generate 9a - --algorithm ECCP256], pin_policy: 'invented' },
      { args: %w[certificates delete 9a --update-chuid --no-update-chuid] },
      { args: %w[access change-management-key --generate], new_management_key: 'x' * 24 },
      { args: %w[keys import 9a -], input: 'not a private key' }
    ]
    invalid.each { |options| expect { piv.execute(authorized.merge(options)) }.to raise_error(ArgumentError) }
    expect(card.commands.select { |ins,| [0x20, 0x24, 0x47, 0x87, 0xdb, 0xff, 0xfe].include?(ins) }).to be_empty
  end

  it 'fails malformed private responses and invalid RSA padding without returning plausible bytes' do
    key = OpenSSL::PKey::RSA.generate(2048)
    card.keys[0x9d] = { key: key, algorithm: 7 }
    invalid = key.public_encrypt("\x00".b * 256, OpenSSL::PKey::RSA::NO_PADDING)
    expect { piv.decrypt(authorized.merge(slot: '9d', ciphertext: invalid, padding: :pkcs1)) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /decryption failed/)
  end

  it 'rejects unsupported padding parameters before using a private key' do
    expect { piv.decrypt(authorized.merge(slot: '9d', ciphertext: 'x' * 256, mgf1_hash: 'bad')) }.to raise_error(ArgumentError)
    expect(card.commands).to be_empty
  end

  it 'uses encrypted PEM and PKCS12 key imports without implicit password prompts' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    encrypted = key.private_to_pem(OpenSSL::Cipher.new('aes-256-cbc'), 'synthetic-passphrase')
    expect(piv.execute(authorized.merge(args: %w[keys import 9a -], input: encrypted, password: 'synthetic-passphrase'))).to include(status: :imported)
    cert = OpenSSL::X509::Certificate.new(piv.execute(authorized.merge(args: ['certificates', 'generate', '9a', '-', '--subject', 'CN=pkcs12'], input: key.public_to_pem)).fetch(:certificate))
    archive = OpenSSL::PKCS12.create('synthetic-passphrase', 'fixture', key, cert).to_der
    expect(piv.execute(authorized.merge(args: %w[keys import 9c -], input: archive, password: 'synthetic-passphrase'))).to include(status: :imported)
    expect(piv.execute(authorized.merge(args: %w[certificates import 9c - --no-update-chuid], input: archive, password: 'synthetic-passphrase'))).to include(status: :written)
  end

  it 'keeps retry metadata synchronized and refuses Bio and configured FIPS retry changes' do
    card.objects[0x5fff00] = ['8003810101'].pack('H*')
    piv.execute(authorized.merge(args: %w[access set-retries 4 2]))
    expect(card.fields(card.fields(card.objects.fetch(0x5fff00)).fetch(0x80)).fetch(0x81).getbyte(0) & 1).to eq(0)
    card.commands.clear
    card.bio = true
    expect { piv.execute(authorized.merge(args: %w[access set-retries 4 2])) }.to raise_error(piv::UnsupportedError)
    card.bio = false
    card.instance_variable_set(:@default_refs, false)
    expect { piv.execute(authorized.merge(args: %w[access set-retries 4 2], fips_restrictions: true)) }.to raise_error(piv::UnsupportedError)
    expect(card.commands.select { |ins,| [0x87, 0x20, 0xfa].include?(ins) }).to be_empty
  end

  it 'does not retry uncertain object writes or silently accept mismatched readback' do
    expect(card).to receive(:exchange).with(hash_including(protocol: :apdu)).at_least(:once).and_call_original
    allow(card).to receive(:command).and_wrap_original do |original, instruction, *rest|
      if instruction == 0xdb
        original.call(instruction, *rest)
        raise PWN::Plugins::YubiKey::TimeoutError, 'uncertain write'
      end
      original.call(instruction, *rest)
    end
    expect { piv.execute(authorized.merge(args: %w[objects import 5f1234 -], input: 'bytes')) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(card.commands.count { |ins,| ins == 0xdb }).to eq(1)
    expect(card.objects.fetch(0x5f1234)).to eq('bytes')
  end

  it 'rejects a timeout without trying another public key source' do
    allow(card).to receive(:command).and_wrap_original do |original, ins, *rest|
      raise PWN::Plugins::YubiKey::TimeoutError if ins == 0xf7

      original.call(ins, *rest)
    end
    expect { piv.execute(connection: card, args: %w[keys export 9a -]) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(card.commands.select { |ins,| [0xf9, 0xcb].include?(ins) }).to be_empty
  end

  it 'supports biometric verification and session-local temporary PIN verification' do
    card.bio = true
    allow(card).to receive(:command).and_wrap_original do |original, ins, first, second, data|
      if ins == 0x20 && second == 0x96
        data == ['0200'].pack('H*') ? ('T'.b * 16) : ''.b
      else
        original.call(ins, first, second, data)
      end
    end
    expect(piv.verify_uv(connection: card, confirm: true)).to eq(:verified)
    temporary = piv.verify_uv(connection: card, confirm: true, request_temporary_pin: true)
    expect(temporary).to eq('T' * 16)
    expect(piv.verify_temporary_pin(connection: card, confirm: true, temporary_pin: temporary)).to eq(:verified)
    expect(card.commands).to include([0x20, 0, 0x96, ['0110'].pack('H*') + ('T' * 16)])
  end

  it 'does not confuse the transport serial selector with the certificate serial' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    card.keys[0x9a] = { key: key, algorithm: 0x11 }
    result = piv.execute(authorized.merge(args: ['certificates', 'generate', '9a', '-', '--subject', 'CN=test'], input: key.public_to_pem, serial: '00123', certificate_serial: 987))
    expect(OpenSSL::X509::Certificate.new(result.fetch(:certificate)).serial.to_i).to eq(987)
  end

  it 'publishes exact public output with mode 0600 and refuses occupied destinations before device mutation' do
    Dir.mktmpdir('piv-output-') do |directory|
      path = File.join(directory, 'public.pem')
      output = piv.execute(authorized.merge(args: ['keys', 'generate', '9a', path, '--algorithm', 'ECCP256']))
      expect(File.binread(path)).to eq(output)
      expect(File.stat(path).mode & 0o777).to eq(0o600)
      card.commands.clear
      expect { piv.execute(authorized.merge(args: ['keys', 'generate', '9a', path])) }.to raise_error(Errno::EEXIST)
      expect(card.commands).to be_empty
    end
  end

  it 'generates and delivers a management key to an explicit sink and applies touch policy' do
    delivered = {}
    result = piv.execute(authorized.merge(args: %w[access change-management-key --algorithm AES128 --generate --touch], secret_sink: ->(field, bytes) { delivered[field] = bytes }))
    expect(result).to include(status: :changed, algorithm: 'AES128', protected: false)
    expect(delivered.fetch(:new_management_key)).to eq(card.management_key)
    expect(delivered.fetch(:new_management_key).bytesize).to eq(16)
    expect(card.commands.select { |ins,| ins == 0xff }.last[1..2]).to eq([0xff, 0xfe])
    expect(card.objects).not_to have_key(0x5fc109)
  end

  it 'selects legacy public-key sources explicitly rather than falling back on failure' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    card.keys[0x9a] = { key: key, algorithm: 0x11, origin: 1 }
    card.version = [5, 2, 0]
    expect { piv.execute(connection: card, args: %w[keys export 9a -]) }.to raise_error(piv::UnsupportedError)
    expect(card.commands.select { |ins,| [0xf9, 0xcb].include?(ins) }).to be_empty
    pem = piv.execute(connection: card, args: %w[keys export 9a -], public_key_source: :attestation)
    expect(OpenSSL::PKey.read(pem).public_to_der).to eq(key.public_to_der)
    expect { piv.execute(connection: card, args: %w[keys export 9a -], public_key_source: :private) }.to raise_error(ArgumentError, /private keys cannot be exported/)
  end

  it 'decodes Net ID compressed certificates and rejects mismatched declared lengths' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    card.keys[0x9a] = { key: key, algorithm: 0x11 }
    result = piv.execute(authorized.merge(args: ['certificates', 'generate', '9a', '-', '--subject', 'CN=netid'], input: key.public_to_pem))
    der = OpenSSL::X509::Certificate.new(result.fetch(:certificate)).to_der
    compressed = "\x01\x00".b + [der.bytesize].pack('v') + Zlib.deflate(der)
    card.objects[0x5fc105] = card.tlv(0x70, compressed) + card.tlv(0x71, "\x01".b)
    expect(piv.execute(connection: card, args: %w[certificates export 9a - --format DER])).to eq(der)
    compressed.setbyte(2, 0)
    compressed.setbyte(3, 0)
    card.objects[0x5fc105] = card.tlv(0x70, compressed) + card.tlv(0x71, "\x01".b)
    expect { piv.execute(connection: card, args: %w[certificates export 9a -]) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /length mismatch/)
  end

  it 'refuses an authentication attempt without literal consent before device IO' do
    card = double('untouched connection')
    expect(card).not_to receive(:exchange)
    [nil, false, 'true', 1].each do |consent|
      expect { PWN::Plugins::YubiKey::PIV.verify_pin(connection: card, pin: '765432', confirm: consent) }.to raise_error(PWN::Plugins::YubiKey::ConfirmationRequired)
    end
  end
end
