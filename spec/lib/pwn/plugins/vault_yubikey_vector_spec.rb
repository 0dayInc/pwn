# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Vault, 'independent hardware envelope vector' do
  # Offline fixture: key bytes 00..13, challenge 00..1f, salt 00..0f,
  # nonce 20..2b. Independently computed with Python hmac, manual RFC 5869
  # extract/expand, and cryptography AESGCM, not the production Vault encoder.
  let(:envelope) do
    {
      'version' => 1, 'cipher' => 'aes-256-gcm', 'kdf' => 'yubikey-hmac-sha1-hkdf-sha256',
      'key_id' => 'pwn-ai-credentials', 'iterations' => 600_000,
      'salt' => 'AAECAwQFBgcICQoLDA0ODw==',
      'yubikey' => { 'slot' => 2, 'serial' => '12345678', 'challenge' => 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=' },
      'iv' => 'ICEiIyQlJicoKSor', 'ct' => '3SNJ2cNhpHZ2I/o6/9fiAE9MeMop+YfsWrGP',
      'tag' => 'w4t/Vmz98ro9opHAmz472Q=='
    }
  end

  before do
    arguments = { slot: 2, serial: '12345678', challenge: (0...32).to_a.pack('C*') }
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response).with(arguments).and_return(['533bd067d1bbf825ed021f8f278adbb571c51627'].pack('H*'))
  end

  it 'opens independently produced authenticated ciphertext without re-encoding it' do
    ciphertext = "#{described_class::YUBIKEY_HEADER}#{JSON.generate(envelope)}\n"
    expect(described_class.decrypt_data(data: ciphertext)).to eq("offline:\x00\xff\n".b)
  end

  it 'matches the independent envelope with fixed public randomness' do
    allow(OpenSSL::Random).to receive(:random_bytes).with(16).and_return((0...16).to_a.pack('C*'))
    allow(OpenSSL::Random).to receive(:random_bytes).with(32).and_return((0...32).to_a.pack('C*'))
    allow(OpenSSL::Cipher).to receive(:new).and_wrap_original do |build, *args|
      cipher = build.call(*args)
      allow(cipher).to receive(:random_iv) do
        nonce = (32...44).to_a.pack('C*')
        cipher.iv = nonce
        nonce
      end
      cipher
    end
    ciphertext = described_class.encrypt_data(data: "offline:\x00\xff\n".b, yubikey: { slot: 2, serial: '12345678' })
    expect(JSON.parse(ciphertext.delete_prefix(described_class::YUBIKEY_HEADER))).to eq(envelope)
  end
end
