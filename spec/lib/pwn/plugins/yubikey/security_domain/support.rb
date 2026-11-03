# frozen_string_literal: true

require 'openssl'

# Independent reference uses CBC reduction, rather than the implementation's
# block-by-block ECB chain. Never uses implementation helpers or actual devices.
class ReferenceCrypto
  def aes(key, input, vector = nil, decrypt: false)
    cipher = OpenSSL::Cipher.new(vector ? 'aes-128-cbc' : 'aes-128-ecb')
    decrypt ? cipher.decrypt : cipher.encrypt
    cipher.padding = 0
    cipher.key = key
    cipher.iv = vector if vector
    cipher.update(input) + cipher.final
  end

  def cmac(key, message)
    n = aes(key, "\0".b * 16).unpack1('H*').to_i(16)
    subkeys = 2.times.map do
      n = ((n << 1) ^ (n >= (1 << 127) ? 0x87 : 0)) & ((1 << 128) - 1)
      n
    end
    complete = !message.empty? && message.bytesize.modulo(16).zero?
    padded = complete ? message.dup : (message + "\x80".b).ljust(((message.bytesize / 16) + 1) * 16, "\0".b)
    last = padded.byteslice(-16, 16).unpack1('H*').to_i(16) ^ subkeys[complete ? 0 : 1]
    padded[-16, 16] = [last.to_s(16).rjust(32, '0')].pack('H*')
    aes(key, padded, "\0".b * 16).byteslice(-16, 16)
  end

  def derive(key, type, context, bits = 128)
    cmac(key, [0, 0, 0, 0, type, 0, bits, 1].pack('NNnCCCnC') + context).byteslice(0, bits / 8)
  end

  def crypt(key, counter, message, response: false, decrypt: false)
    iv = aes(key, [(response ? 128 : 0)].pack('C') + [counter.to_s(16).rjust(30, '0')].pack('H*'))
    aes(key, message, iv, decrypt: decrypt)
  end
end

class Scp03Card
  attr_reader :commands, :closed, :received
  attr_accessor :fault, :handler

  def initialize
    @crypto = ReferenceCrypto.new
    @commands = []
    @static = (0...16).to_a.pack('C*')
    @card = 'CARDRAND'.b
    @counter = 0
  end

  def descriptor
    { protocol: :apdu, reader: 'synthetic' }
  end

  def close
    @closed = true
  end

  def exchange(opts)
    command = opts.fetch(:data)
    @commands << command
    ins = command.getbyte(1)
    return "\x90\0".b if ins == 0xa4 && command.getbyte(0).zero?

    if ins == 0x50
      context = command.byteslice(5, 8) + @card
      @enc = @crypto.derive(@static, 4, context)
      @mac = @crypto.derive(@static, 6, context)
      @rmac = @crypto.derive(@static, 7, context)
      @host = @crypto.derive(@mac, 1, context, 64)
      @chain = "\0".b * 16
      cryptogram = @crypto.derive(@mac, 0, context, 64)
      cryptogram.setbyte(0, cryptogram.getbyte(0) ^ 1) if fault == :card_cryptogram
      return ("\0".b * 10) + "\x01\x03\x70".b + @card + cryptogram + "\x90\0".b
    end
    start = command.getbyte(4).zero? ? 7 : 5
    length = start == 7 ? command.byteslice(5, 2).unpack1('n') : command.getbyte(4)
    ciphertext = command.byteslice(start, length - 8)
    full_mac = @crypto.cmac(@mac, @chain + command.byteslice(0, start) + ciphertext)
    raise 'synthetic card rejected command MAC' unless full_mac.byteslice(0, 8) == command.byteslice(start + length - 8, 8)

    @chain = full_mac
    if ins == 0x82
      raise 'synthetic card rejected host cryptogram' unless ciphertext == @host && command.byteslice(0, 4) == "\x84\x82\x33\0".b

      return "\x90\0".b
    end
    @counter += 1
    @received = @crypto.crypt(@enc, @counter, ciphertext, decrypt: true).sub(/\x80\x00*\z/n, ''.b)
    return @last_reply if fault == :replay
    return "\x90\0".b if fault == :missing_mac

    payload, sw = handler ? handler.call(command.byteslice(0, 4), @received) : ['reply'.b, "\x62\x82".b]
    padding = fault == :padding ? 'x' * 16 : (payload + "\x80".b).ljust(((payload.bytesize / 16) + 1) * 16, "\0".b)
    padding = "data\x80".b.ljust(32, "\0".b) if fault == :padding_long
    encrypted = @crypto.crypt(@enc, fault == :counter ? @counter + 1 : @counter, padding, response: true)
    encrypted = encrypted.byteslice(0, 15) if fault == :truncated_ciphertext
    mac = @crypto.cmac(@rmac, @chain + encrypted + sw).byteslice(0, 8)
    mac.setbyte(0, mac.getbyte(0) ^ 1) if fault == :mac
    sw = "\x90\0".b if fault == :status
    @last_reply = encrypted + mac + sw
  end
end

class Scp11Card < Scp03Card
  attr_reader :public_key, :certificates
  attr_accessor :card_bundle

  def initialize
    super
    @private_key = OpenSSL::PKey::EC.generate('prime256v1')
    @public_key = OpenSSL::PKey.read(@private_key.public_to_der)
    @certificates = []
  end

  def exchange(opts)
    command = opts.fetch(:data)
    ins = command.getbyte(1)
    if ins == 0xca && command.getbyte(0) == 0 && card_bundle
      @commands << command
      return card_bundle + "\x90\0".b
    end
    return super unless [0x2a, 0x88, 0x82].include?(ins)

    @commands << command
    start = command.getbyte(4).zero? ? 7 : 5
    length = start == 7 ? command.byteslice(5, 2).unpack1('n') : command.getbyte(4)
    data = command.byteslice(start, length)
    if ins == 0x2a
      cert = OpenSSL::X509::Certificate.new(data)
      raise 'synthetic OCE signature rejected' if !@certificates.empty? && !cert.verify(@certificates.last.public_key)

      @certificates << cert
      return "\x90\0".b
    end
    variant = { 0x11 => 1, 0x13 => 0, 0x15 => 3 }.fetch(command.getbyte(3))
    raise 'invalid SCP11 control template' unless data.byteslice(0, 15) == ["a60d900211#{variant.to_s(16).rjust(2, '0')}95013c800188810110"].pack('H*')
    raise 'invalid SCP11 point tag' unless data.byteslice(15, 3) == "\x5f\x49\x41".b

    point = OpenSSL::PKey::EC::Point.new(@private_key.group, OpenSSL::BN.new(data.byteslice(18, 65), 2))
    host_point = variant.zero? ? point : @certificates.last.public_key.public_key
    ephemeral = OpenSSL::PKey::EC.generate('prime256v1')
    z = ephemeral.dh_compute_key(point) + @private_key.dh_compute_key(host_point)
    key_bytes = (1..3).map { |counter| OpenSSL::Digest::SHA256.digest(z + [counter].pack('N') + "\x3c\x88\x10".b) }.join.byteslice(0, 80)
    receipt_key, @enc, @mac, @rmac, @dek = key_bytes.scan(/.{16}/mn)
    peer = "\x5f\x49\x41".b + ephemeral.public_key.to_octet_string(:uncompressed)
    @chain = @crypto.cmac(receipt_key, data + peer)
    receipt = @chain.dup
    receipt.setbyte(0, receipt.getbyte(0) ^ 1) if fault == :receipt
    peer + "\x86\x10".b + receipt + "\x90\0".b
  end
end
