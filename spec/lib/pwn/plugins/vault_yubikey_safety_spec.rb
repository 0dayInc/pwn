# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::Vault, 'YubiKey failure safety' do
  before do
    @device = double('offline YubiKey')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) { |opts| OpenSSL::HMAC.digest('SHA1', 'fixture-slot', opts[:challenge]) }
    @legacy = { key: Base64.strict_encode64('k' * 32), iv: Base64.strict_encode64('i' * 16) }
    allow(described_class).to receive(:note_mission_loot)
  end

  it 'never ignores explicit hardware selection when editing or rotating a legacy vault' do
    Dir.mktmpdir('vault-no-fallback-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      path = File.join(root, 'vault')
      original = described_class.encrypt_data(@legacy.merge(data: "token: fixture\n"))
      File.binwrite(path, original)
      expect(described_class).not_to receive(:system)
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      %i[edit refresh_encryption_secrets].each do |method|
        expect { described_class.public_send(method, @legacy.merge(file: path, yubikey: {})) }.to raise_error(ArgumentError, /YubiKey/)
        expect(File.binread(path)).to eq(original)
      end
    end
  end

  it 'rejects software credentials combined with hardware creation rather than discarding them' do
    Dir.mktmpdir('vault-conflict-') do |root|
      path = File.join(root, 'vault')
      File.write(path, 'original')
      expect { described_class.create(@legacy.merge(file: path, yubikey: {})) }.to raise_error(ArgumentError, /software/)
      expect(File.read(path)).to eq('original')
    end
  end

  it 'does not accept false as a hardware selector during unsealing' do
    envelope = described_class.seal_credentials(credentials: { token: 'fixture' }, yubikey: {})
    expect { described_class.open_credentials(envelope: envelope, yubikey: false) }.to raise_error(ArgumentError, /selector/)
  end

  [false, { slot: 3 }, { slot: 1.0 }, { slot: 2.0 }, { unexpected: true }, { serial: false }, { serial: 123 },
   { timeout: false }, { timeout: 0 }, { timeout: Float::INFINITY }, { ykman: '' }, { ykman: false },
   { ykman: '/fixture/unsupported-executable' }, { device_path: false }, { device_path: '' }, { device_path: "bad\npath" },
   { reader: false }, { reader: '' }, { reader: "bad\0reader" }, { reader: 'Fixture reader', serial: '123' },
   { connection: false }, { connection: Object.new }, { reader: 'Fixture reader', device_path: '/fixture/native-device' }, { 123 => 'invalid key' }].each do |selector|
    %i[legacy hardware].each do |backend|
      it "rejects destination selector #{selector.inspect} before opening a #{backend} vault" do
        Dir.mktmpdir('vault-invalid-destination-') do |root|
          allow(Dir).to receive(:home).and_return(root)
          path = File.join(root, 'vault')
          access = backend == :legacy ? @legacy : { yubikey: {} }
          original = described_class.encrypt_data(access.merge(data: "token: fixture\n"))
          File.binwrite(path, original)
          expect(described_class).not_to receive(:decrypt_data)
          expect(@device).not_to receive(:challenge_response)
          expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
          expect do
            expect { described_class.refresh_encryption_secrets(access.merge(file: path, new_yubikey: selector)) }.to raise_error(ArgumentError, /yubikey/i)
          end.not_to output.to_stdout
          expect(File.binread(path)).to eq(original)
          expect(Dir.children(root)).to eq(['vault'])
        end
      end
    end
  end

  it 'keeps entropy redacted when the hardware loot write fails' do
    secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    allow(@device).to receive(:challenge_response).and_raise(IOError, 'Device unavailable')
    Dir.mktmpdir('capture-no-device-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      result = PWN::Redaction.capture(value: secret, entropy: true, yubikey: {})
      expect(result[:redacted]).not_to include(secret)
      expect(result[:redacted]).to start_with('[REDACTED:entropy:')
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
    end
  end

  it 'authenticates ciphertext and public metadata and rejects a wrong device response' do
    envelope = described_class.seal_credentials(credentials: { value: 'fixture' }, yubikey: { slot: 1, serial: '12345678' })
    %w[ct tag salt iv key_id].each do |field|
      changed = Marshal.load(Marshal.dump(envelope))
      changed[field] = field == 'key_id' ? 'different-context' : Base64.strict_encode64('x' * Base64.strict_decode64(changed[field]).bytesize)
      expect { described_class.open_credentials(envelope: changed) }.to raise_error(ArgumentError)
    end
    expect(described_class.open_credentials(envelope: envelope, yubikey: { serial: '87654321' })).to eq('value' => 'fixture')
    expect { described_class.open_credentials(envelope: envelope, yubikey: { slot: 2 }) }.to raise_error(ArgumentError, /slot/)
    allow(@device).to receive(:challenge_response) { 'w' * 20 }
    expect { described_class.open_credentials(envelope: envelope) }.to raise_error(ArgumentError, /authentication/)
  end

  it 'rejects caller-only native controls injected into envelope metadata before contacting hardware' do
    original = described_class.seal_credentials(credentials: {}, yubikey: {})
    expect(@device).not_to receive(:challenge_response)
    %w[ykman reader device_path connection timeout].each do |field|
      envelope = Marshal.load(Marshal.dump(original))
      envelope['yubikey'][field] = '/untrusted/backend'
      expect { described_class.open_credentials(envelope: envelope) }.to raise_error(ArgumentError, /metadata/)
    end
  end

  it 'preserves ciphertext when the device disappears on the encryption half of an update' do
    Dir.mktmpdir('vault-save-failure-') do |root|
      path = File.join(root, 'vault')
      File.write(path, "token: original\n")
      described_class.create(file: path, yubikey: {})
      before = File.binread(path)
      calls = 0
      allow(@device).to receive(:challenge_response) do |opts|
        calls += 1
        raise IOError, 'Device removed' if calls > 1

        OpenSSL::HMAC.digest('SHA1', 'fixture-slot', opts[:challenge])
      end
      expect do
        described_class.update(file: path) do |cfg|
          cfg[:token] = 'changed'
          expect(File.binread(path)).to eq(before)
        end
      end.to raise_error(IOError, 'Device removed')
      expect(File.binread(path)).to eq(before)
      expect(Dir.children(root)).to eq(['vault'])
    end
  end

  it 'converts a legacy vault in memory and never downgrades a hardware loot label on replacement' do
    Dir.mktmpdir('vault-conversion-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      path = File.join(root, 'vault')
      File.binwrite(path, described_class.encrypt_data(@legacy.merge(data: "token: original\n")))
      described_class.refresh_encryption_secrets(@legacy.merge(file: path, new_yubikey: {}))
      expect(described_class.dump(file: path)).to eq(token: 'original')
      expect(File.stat(path).mode & 0o777).to eq(0o600)
      described_class.store(label: 'fixed', secret: 'first', yubikey: {})
      described_class.store(label: 'fixed', secret: 'second')
      expect(described_class.fetch(label: 'fixed')).to eq('second')
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
    end
  end

  %i[legacy hardware].each do |backend|
    it "preserves untouched multiline YAML scalars during a #{backend} update" do
      Dir.mktmpdir('vault-yaml-scalars-') do |root|
        path = File.join(root, 'vault')
        original = {
          banner: ":first\n:second\n\n  :indented\nlast:\n",
          nested: { values: [":array-line\n:next\n", :symbol, false, nil, 123], unicode: "é\n:行\n" }
        }
        access = backend == :legacy ? @legacy : { yubikey: {} }
        File.binwrite(path, described_class.encrypt_data(access.merge(data: YAML.dump(original))))
        expect(described_class.update(access.merge(file: path)) { |cfg| cfg[:changed] = true }).to eq(:saved)
        expect(described_class.dump(access.merge(file: path))).to eq(original.merge(changed: true))
      end
    end
  end

  it 'supports empty binary data with independent challenge, salt and nonce on every encryption' do
    first = described_class.encrypt_data(data: ''.b, yubikey: {})
    second = described_class.encrypt_data(data: ''.b, yubikey: {})
    expect(described_class.decrypt_data(data: first)).to eq(''.b)
    a, b = [first, second].map { |ciphertext| JSON.parse(ciphertext.delete_prefix(described_class::YUBIKEY_HEADER)) }
    %w[salt iv].each { |field| expect(a[field]).not_to eq(b[field]) }
    expect(a['yubikey']['challenge']).not_to eq(b['yubikey']['challenge'])
  end
end
