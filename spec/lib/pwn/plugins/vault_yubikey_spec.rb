# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::Vault, 'YubiKey credential envelopes' do
  before do
    @device = double('YubiKey HMAC fixture')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) do |opts|
      expect(opts[:slot]).to eq(2)
      expect(opts[:challenge].bytesize).to eq(32)
      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts[:challenge])
    end
  end

  it 'round trips credentials with a hardware-derived key and no software key material in the envelope' do
    envelope = described_class.seal_credentials(credentials: { 'token' => 'fixture-token' }, yubikey: { slot: 2 })
    expect(envelope['kdf']).to eq('yubikey-hmac-sha1-hkdf-sha256')
    expect(envelope.fetch('yubikey')).to include('slot' => 2)
    expect(JSON.generate(envelope)).not_to include('fixture-token', 'synthetic-slot-secret')
    expect(described_class.open_credentials(envelope: envelope)).to eq('token' => 'fixture-token')
    expect(@device).to have_received(:challenge_response).twice
  end

  it 'encrypts a binary file and dumps or decrypts it without a software decryptor' do
    Dir.mktmpdir('vault-yubikey-') do |root|
      path = File.join(root, 'fixture')
      bytes = "binary\x00\xff\n".b
      File.binwrite(path, bytes)
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      described_class.encrypt(file: path, yubikey: { slot: 2 })
      ciphertext = File.binread(path)
      expect(ciphertext).to start_with(described_class::YUBIKEY_HEADER)
      expect(described_class.file_encrypted?(file: path)).to be(true)
      expect(described_class.dump(file: path, yaml: false)).to eq(bytes)
      expect(File.binread(path)).to eq(ciphertext)
      described_class.decrypt(file: path)
      expect(File.binread(path)).to eq(bytes)
    end
  end

  it 'updates a hardware configuration without requiring a sidecar or ever writing plaintext' do
    Dir.mktmpdir('vault-update-') do |root|
      path = File.join(root, 'pwn.yaml')
      File.write(path, YAML.dump(ai: { active: 'ollama', ollama: { model: 'before' } }, retained: 'fixture'))
      described_class.encrypt(file: path, yubikey: { slot: 2 })
      before = File.binread(path)
      expect(described_class.access_options(file: path)).to eq(yubikey: { slot: 2 })
      expect(described_class.update(file: path) { |cfg| cfg[:ai][:ollama][:model] = 'after' }).to eq(:saved)
      expect(File.binread(path)).not_to eq(before)
      expect(described_class.dump(file: path)).to include(ai: { active: 'ollama', ollama: { model: 'after' } }, retained: 'fixture')
      before = File.binread(path)
      allow(@device).to receive(:challenge_response).and_raise(IOError, 'Device unavailable')
      expect { described_class.update(file: path, &:clear) }.to raise_error(IOError, 'Device unavailable')
      expect(File.binread(path)).to eq(before)
      expect(Dir.children(root)).to eq(['pwn.yaml'])
    end
  end

  it 'creates and rotates a hardware vault without printing or persisting a software decryptor' do
    Dir.mktmpdir('vault-create-') do |root|
      path = File.join(root, 'secret.yaml')
      File.write(path, "token: fixture-only\n")
      expect { described_class.create(file: path, yubikey: { slot: 2 }) }.not_to output.to_stdout
      before = File.binread(path)
      described_class.refresh_encryption_secrets(file: path)
      expect(File.binread(path)).not_to eq(before)
      expect(described_class.dump(file: path)).to eq(token: 'fixture-only')
      expect(Dir.children(root)).to eq(['secret.yaml'])
    end
  end

  it 'edits only a private temporary copy and retains ciphertext if the key disappears before save' do
    Dir.mktmpdir('vault-edit-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      path = File.join(root, 'vault')
      File.write(path, "token: original\n")
      described_class.create(file: path, yubikey: { slot: 2 })
      before = File.binread(path)
      edited = nil
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      allow(described_class).to receive(:system) do |editor, temporary|
        expect(editor).to eq('/usr/bin/true')
        expect(temporary).not_to eq(path)
        expect(File.stat(temporary).mode & 0o777).to eq(0o600)
        expect(File.binread(path)).to eq(before)
        edited = temporary
        File.write(temporary, "token: changed\n")
        allow(@device).to receive(:challenge_response).and_raise(IOError, 'Device removed')
        true
      end
      expect { described_class.edit(file: path, editor: '/usr/bin/true') }.to raise_error(IOError, 'Device removed')
      expect(File.binread(path)).to eq(before)
      expect(File).not_to exist(edited)
    end
  end

  it 'protects engagement loot and its offer, expansion and redaction consumers without a disk master key' do
    Dir.mktmpdir('vault-loot-hardware-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      selector = { slot: 2 }
      described_class.store(label: 'hardware', secret: 'fixture-password', host: 'login.example.test', username: 'fixture-user', yubikey: selector)
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
      expect(described_class.fetch(label: 'hardware')).to eq('fixture-password')
      expect(described_class.offer(host: 'login.example.test').first[:secret]).to eq('fixture-password')
      expect(described_class.expand(text: '{{vault:hardware}}', yubikey: selector)).to eq('fixture-password')
      expect(described_class.redact(text: 'fixture-password', yubikey: selector)).to eq('{{vault:hardware}}')
      expect(PWN::Plugins::BasicAuth.encode(host: 'login.example.test', yubikey: selector)).to eq(Base64.strict_encode64('fixture-user:fixture-password'))
      before = File.binread(File.join(root, '.pwn', 'engagements', 'default', 'loot.json'))
      allow(@device).to receive(:challenge_response).and_raise(IOError, 'Device unavailable')
      expect { described_class.fetch(label: 'hardware') }.to raise_error(IOError, 'Device unavailable')
      expect { described_class.store(label: 'hardware', secret: 'replacement', yubikey: selector) }.to raise_error(IOError)
      expect(File.binread(File.join(root, '.pwn', 'engagements', 'default', 'loot.json'))).to eq(before)
    end
  end

  it 'allows redaction capture to explicitly use the hardware loot backend' do
    Dir.mktmpdir('redaction-yubikey-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      capture = PWN::Redaction.capture(value: 'password=fixture-password', yubikey: { slot: 2 })
      label = capture[:refs].first.fetch(:token)
      expect(capture[:redacted]).not_to include('fixture-password')
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
      expect(described_class.fetch(label: label)).to eq('password=fixture-password')
    end
  end
end
