# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Config, 'hardware vault configuration' do
  around do |example|
    Dir.mktmpdir('config-yubikey-') do |root|
      @root = root
      example.run
    end
  end

  before do
    allow(Dir).to receive(:home).and_return(@root)
    stub_const('PWN::Env', {})
    stub_const('PWN::EnvRedacted', {})
    stub_const('PWN::Plugins::YubiKey', double('synthetic YubiKey'))
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response) do |opts|
      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts[:challenge])
    end
    allow(described_class).to receive(:install_default_skills)
    allow(described_class).to receive(:load_skills)
    allow(PWN::Memory).to receive(:load)
    allow(PWN::Cron).to receive(:install_defaults)
    allow(PWN::Migrate).to receive(:needed?).and_return(false)
    @path = File.join(@root, 'pwn.yaml')
  end

  it 'rejects an invalid hardware selector rather than falling back to a software sidecar' do
    expect { described_class.default_env(pwn_env_path: @path, yubikey: false) }.to raise_error(ArgumentError)
    expect(File).not_to exist(@path)
    expect(File).not_to exist("#{@path}.decryptor")
  end

  it 'creates the default hardware configuration path when called directly' do
    described_class.default_env(yubikey: { slot: 2 })
    path = File.join(@root, '.pwn', 'pwn.yaml')
    expect(PWN::Plugins::Vault.dump(file: path)).to eq(described_class.env_template)
    expect(File).not_to exist("#{path}.decryptor")
  end

  it 'preserves multiline template values containing leading colons during creation' do
    template = Marshal.load(Marshal.dump(described_class.env_template))
    text = "before\n:leading-colon\nafter\n"
    template[:ai][:ollama][:system_role_content] = text
    allow(described_class).to receive(:env_template).and_return(template)
    described_class.default_env(pwn_env_path: @path, yubikey: {})
    expect(PWN::Plugins::Vault.dump(file: @path).dig(:ai, :ollama, :system_role_content)).to eq(text)
  end

  it 'retains software creation by default and honors the explicitly selected legacy decryptor' do
    sidecar = File.join(@root, 'custom-sidecar')
    expect(PWN::Plugins::YubiKey).not_to receive(:challenge_response)
    described_class.refresh_env(pwn_env_path: @path, pwn_dec_path: sidecar)
    expect(PWN::Plugins::Vault.hardware_encrypted?(file: @path)).to be(false)
    credentials = YAML.safe_load_file(sidecar, symbolize_names: true)
    expect(PWN::Plugins::Vault.dump(credentials.merge(file: @path))).to eq(described_class.env_template)
    described_class.refresh_env(pwn_env_path: @path, pwn_dec_path: sidecar)
    expect(PWN::Env.dig(:driver_opts, :pwn_dec_path)).to eq(sidecar)
    expect(File).not_to exist("#{@path}.decryptor")
  end

  it 'creates a hardware vault only on explicit opt-in, without staging plaintext or making a sidecar' do
    described_class.refresh_env(pwn_env_path: @path, yubikey: { slot: 2 })
    expect(PWN::Plugins::Vault.hardware_encrypted?(file: @path)).to be(true)
    expect(PWN::Plugins::Vault.dump(file: @path)).to eq(described_class.env_template)
    expect(File).not_to exist("#{@path}.decryptor")
    expect(File.stat(@path).mode & 0o777).to eq(0o600)
    expect(PWN::Env).not_to have_key(:yubikey)
  end

  it 'leaves no plaintext configuration behind when opted-in hardware creation fails' do
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response).and_raise(IOError, 'synthetic device unavailable')
    expect { described_class.default_env(pwn_env_path: @path, yubikey: { slot: 2 }) }.to raise_error(IOError)
    expect(File).not_to exist(@path)
    expect(File).not_to exist("#{@path}.decryptor")
  end

  it 'refreshes a self-describing hardware vault without a decryptor or software-key prompt' do
    original = { ai: { active: 'ollama', ollama: { model: 'fixture-model' } }, retained: 'fixture-value' }
    bytes = PWN::Plugins::Vault.encrypt_data(data: YAML.dump(original), yubikey: { slot: 2, serial: '12345678' })
    File.binwrite(@path, bytes)
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    described_class.refresh_env(pwn_env_path: @path)
    expect(PWN::Env.dig(:ai, :ollama, :model)).to eq('fixture-model')
    expect(PWN::Env[:retained]).to eq('fixture-value')
    expect(PWN::Env.dig(:driver_opts, :pwn_env_path)).to eq(@path)
    expect(File.binread(@path)).to eq(bytes)
    expect(File).not_to exist("#{@path}.decryptor")
  end
end
