# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::REPL, 'mesh vault persistence' do
  before do
    @home = Dir.mktmpdir('pwn-mesh-vault-')
    allow(Dir).to receive(:home).and_return(@home)
    @path = File.join(@home, 'custom-vault')
    @decryptor = File.join(@home, 'independent-decryptor')
    stub_const('PWN::Env', { driver_opts: { pwn_env_path: @path, pwn_dec_path: @decryptor }, plugins: {} })
    @device = double('offline YubiKey')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) do |opts|
      expect(opts).to include(slot: 2, serial: '123456')
      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts.fetch(:challenge))
    end
    @cfg = {
      unrelated: 'keep', plugins: {
        meshtastic: {
          transport: 'mqtt', channel: { active: 'LongFast', LongFast: { psk: 'fixture-psk', topic: '2/e/LongFast/#' } },
          mqtt: { username: 'fixture-user', password: 'fixture-password' }, serial: { port: '/dev/fixture-old', baud: 115_200 }
        }
      }
    }
    File.write(@path, YAML.dump(@cfg))
    PWN::Plugins::Vault.encrypt(file: @path, yubikey: { slot: 2, serial: '123456' })
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    allow(described_class).to receive(:mesh_ui_puts)
    allow(ENV).to receive(:fetch).and_call_original
    allow(ENV).to receive(:fetch).with('PWN_DECRYPTOR_KEY', nil).and_return(nil)
    allow(ENV).to receive(:fetch).with('PWN_DECRYPTOR_IV', nil).and_return(nil)
  end

  after { FileUtils.remove_entry(@home) }

  it 'merges menu settings into a hardware vault without a decryptor or plaintext rewrite' do
    expect(PWN::Plugins::Vault).to receive(:update).with(file: @path, decryptor_file: @decryptor).and_call_original
    expect(PWN::Plugins::Vault).not_to receive(:decrypt)
    expect(PWN::Plugins::Vault).not_to receive(:encrypt)
    expect(File).not_to receive(:write)
    mesh = { 'transport' => 'serial', 'serial' => { 'port' => '/dev/fixture-new' }, 'channel' => { 'active' => 'LongFast' } }

    expect(described_class.persist_mesh_env(mesh: mesh)).to be(true)
    persisted = PWN::Plugins::Vault.dump(file: @path)
    expect(persisted.dig(:plugins, :meshtastic)).to eq(@cfg.dig(:plugins, :meshtastic).merge(transport: 'serial', serial: { port: '/dev/fixture-new', baud: 115_200 }))
    expect(persisted[:unrelated]).to eq('keep')
    expect(File.binread(@path)).to start_with(PWN::Plugins::Vault::YUBIKEY_HEADER)
    expect(File.stat(@path).mode & 0o777).to eq(0o600)
    expect(Dir.children(@home)).to eq(['custom-vault'])
    expect(described_class).not_to have_received(:mesh_ui_puts)
  end

  it 'keeps legacy credentials and nested mesh settings while staging ciphertext only' do
    credentials = { key: Base64.strict_encode64('k' * 32), iv: Base64.strict_encode64('i' * 16) }
    File.write(@decryptor, YAML.dump(credentials))
    File.chmod(0o400, @decryptor)
    File.write(@path, YAML.dump(@cfg))
    PWN::Plugins::Vault.encrypt({ file: @path }.merge(credentials))
    before = File.binread(@path)
    sidecar_before = File.binread(@decryptor)
    expect(File).not_to receive(:write)
    expect(PWN::Plugins::Vault).not_to receive(:decrypt)
    expect(PWN::Plugins::Vault).not_to receive(:encrypt)
    expect(Tempfile).to receive(:create).and_wrap_original do |create, *args, &block|
      create.call(*args) do |temp|
        expect(temp).to receive(:write).and_wrap_original do |write, bytes|
          plaintext = PWN::Plugins::Vault.decrypt_data(credentials.merge(data: bytes))
          expect(YAML.safe_load(plaintext, permitted_classes: [Symbol], symbolize_names: true).dig(:plugins, :meshtastic, :serial)).to eq(port: '/dev/fixture-new', baud: 115_200)
          expect(bytes).not_to include('fixture-password', 'fixture-psk')
          expect(File.binread(@path)).to eq(before)
          expect(temp.stat.mode & 0o777).to eq(0o600)
          write.call(bytes)
        end
        block.call(temp)
      end
    end

    expect(described_class.persist_mesh_env(mesh: { serial: { port: '/dev/fixture-new' } })).to be(true)
    persisted = PWN::Plugins::Vault.dump({ file: @path }.merge(credentials))
    expect(persisted.dig(:plugins, :meshtastic)).to eq(@cfg.dig(:plugins, :meshtastic).merge(serial: { port: '/dev/fixture-new', baud: 115_200 }))
    expect(persisted[:unrelated]).to eq('keep')
    expect(File.binread(@decryptor)).to eq(sidecar_before)
    expect(File.stat(@decryptor).mode & 0o777).to eq(0o400)
    expect(File.stat(@path).mode & 0o777).to eq(0o600)
    expect(Dir.children(@home)).to match_array(%w[custom-vault independent-decryptor])
  end

  it 'uses the default vault and live mesh settings when no overrides are supplied' do
    default_path = File.join(@home, '.pwn', 'pwn.yaml')
    FileUtils.mkdir_p(File.dirname(default_path))
    FileUtils.cp(@path, default_path)
    before = File.binread(@path)
    PWN::Env[:driver_opts] = {}
    PWN::Env[:plugins][:meshtastic] = { transport: 'serial' }

    expect(described_class.persist_mesh_env).to be(true)
    expect(PWN::Plugins::Vault.dump(file: default_path).dig(:plugins, :meshtastic)).to eq(@cfg.dig(:plugins, :meshtastic).merge(transport: 'serial'))
    expect(File.binread(@path)).to eq(before)
    expect(Dir.children(File.dirname(default_path))).to eq(['pwn.yaml'])
  end

  it 'does not overwrite a concurrent ciphertext change' do
    concurrent = PWN::Plugins::Vault.encrypt_data(data: YAML.dump(@cfg.merge(unrelated: 'newer')), yubikey: { slot: 2, serial: '123456' })
    allow(PWN::Plugins::Vault).to receive(:encrypt_data).and_wrap_original do |encrypt, opts|
      ciphertext = encrypt.call(opts)
      File.binwrite(@path, concurrent)
      ciphertext
    end

    expect(described_class.persist_mesh_env(mesh: { transport: 'serial' })).to be(false)
    expect(File.binread(@path)).to eq(concurrent)
    expect(Dir.children(@home)).to eq(['custom-vault'])
    expect(described_class).to have_received(:mesh_ui_puts).with(text: '[pwn-mesh] persist skipped: IOError')
  end

  it 'does not use a software sidecar when the hardware device is unavailable' do
    File.write(@decryptor, YAML.dump(key: Base64.strict_encode64('k' * 32), iv: Base64.strict_encode64('i' * 16)))
    before = File.binread(@path)
    sidecar_before = File.binread(@decryptor)
    allow(@device).to receive(:challenge_response).and_raise(IOError, 'synthetic-private-error')
    expect(PWN::Plugins::Vault).not_to receive(:encrypt_data)

    expect(described_class.persist_mesh_env(mesh: { transport: 'serial' })).to be(false)
    expect(File.binread(@path)).to eq(before)
    expect(File.binread(@decryptor)).to eq(sidecar_before)
    expect(described_class).to have_received(:mesh_ui_puts).with(text: '[pwn-mesh] persist skipped: IOError')
  end

  it 'leaves hardware ciphertext untouched when the device disappears during re-encryption' do
    before = File.binread(@path)
    calls = 0
    allow(@device).to receive(:challenge_response) do |opts|
      calls += 1
      raise IOError, 'synthetic-private-error' if calls > 1

      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts.fetch(:challenge))
    end
    expect(PWN::Plugins::Vault).not_to receive(:decrypt)
    expect(File).not_to receive(:write)
    expect(Tempfile).not_to receive(:create)

    expect(described_class.persist_mesh_env(mesh: { transport: 'serial' })).to be(false)
    expect(described_class).to have_received(:mesh_ui_puts).with(text: '[pwn-mesh] persist skipped: IOError')
    expect(File.binread(@path)).to eq(before)
    expect(Dir.children(@home)).to eq(['custom-vault'])
  end
end
