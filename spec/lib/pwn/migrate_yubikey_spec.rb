# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'stringio'

RSpec.describe PWN::Migrate, 'hardware vault migrations' do
  around do |example|
    Dir.mktmpdir('migrate-yubikey-') do |root|
      @root = root
      example.run
    end
  end

  before do
    allow(Dir).to receive(:home).and_return(@root)
    stub_const('PWN::Migrate::PWN_ROOT', @root)
    stub_const('PWN::Env', { driver_opts: {} })
    stub_const('PWN::Plugins::YubiKey', double('synthetic YubiKey'))
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response) do |opts|
      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts[:challenge])
    end
    @path = File.join(@root, 'pwn.yaml')
    @original = { ai: { active: 'ollama', ollama: { model: 'fixture-model' } }, retained: 'fixture-value' }
    File.binwrite(@path, PWN::Plugins::Vault.encrypt_data(data: YAML.dump(@original), yubikey: { slot: 2 }))
    @io = StringIO.new
  end

  it 'backfills through an atomic encrypted update, preserving the hardware format and user choices' do
    expect(File).not_to receive(:write).with(@path, anything)
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    result = described_class.backfill_vault(io: @io)
    expect(result[:added]).to be_positive
    expect(PWN::Plugins::Vault.hardware_encrypted?(file: @path)).to be(true)
    document = PWN::Plugins::Vault.dump(file: @path)
    expect(document.dig(:ai, :ollama, :model)).to eq('fixture-model')
    expect(document[:retained]).to eq('fixture-value')
    expect(document.dig(:ai, :agent)).to eq(PWN::Config.env_template.dig(:ai, :agent))
    bytes = File.binread(@path)
    expect(described_class.backfill_vault(io: @io)[:added]).to eq(0)
    expect(File.binread(@path)).to eq(bytes)
    expect(Dir.children(@root)).to eq(['pwn.yaml'])
  end

  it 'uses driver-selected hardware vault paths without touching the canonical vault' do
    custom = File.join(@root, 'selected-vault')
    FileUtils.cp(@path, custom)
    PWN::Env[:driver_opts] = { pwn_env_path: custom, pwn_dec_path: File.join(@root, 'absent-sidecar') }
    canonical = File.binread(@path)
    expect(described_class.backfill_vault(io: @io)[:added]).to be_positive
    expect(described_class.vault_drift[:missing]).to be_empty
    expect(File.binread(@path)).to eq(canonical)
    expect(PWN::Plugins::Vault.hardware_encrypted?(file: custom)).to be(true)
  end

  it 'honors an explicit independent legacy decryptor and vault over driver defaults' do
    custom = File.join(@root, 'legacy-vault')
    sidecar = File.join(@root, 'separate-legacy-decryptor')
    File.write(custom, YAML.dump(@original))
    PWN::Plugins::Vault.create(file: custom, decryptor_file: sidecar)
    canonical = File.binread(@path)
    credentials = YAML.safe_load_file(sidecar, symbolize_names: true)
    result = described_class.backfill_vault(pwn_env_path: custom, pwn_dec_path: sidecar, io: @io)
    expect(result[:added]).to be_positive
    expect(PWN::Plugins::Vault.dump(credentials.merge(file: custom)).dig(:ai, :agent)).to be_a(Hash)
    expect(File.binread(@path)).to eq(canonical)
  end

  it 'forwards explicit vault selection and hardware overrides through numbered migrations and fix runs' do
    custom = File.join(@root, 'selected-vault')
    FileUtils.cp(@path, custom)
    canonical = File.binread(@path)
    allow(PWN::Backups).to receive(:active?).and_return(true)
    allow(described_class).to receive(:status).and_return(schema_installed: 3, schema_current: 4, pwn_version: 'fixture', incompatible: [])
    allow(described_class).to receive(:stamp!)
    stub_const('PWN::Migrate::SCHEMA_VERSION', 4)
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response) do |opts|
      raise IOError, 'selector was not forwarded' unless opts[:device_path] == '/fixture/native-device'

      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts[:challenge])
    end
    [false, true].each do |fix|
      File.binwrite(custom, canonical)
      allow(described_class).to receive(:status).and_return(schema_installed: fix ? 4 : 3, schema_current: 4, pwn_version: 'fixture', incompatible: [])
      result = described_class.run(fix: fix, backup: false, io: @io, pwn_env_path: custom, yubikey: { device_path: '/fixture/native-device' })
      expect(result[:applied_migrations]).to eq(fix ? [] : [4])
      document = PWN::Plugins::Vault.dump(file: custom, yubikey: { device_path: '/fixture/native-device' })
      expect(document.dig(:ai, :agent)).to be_a(Hash)
      expect(File.binread(@path) == canonical).to be(true)
    end
  end

  it 'reports the explicitly selected vault rather than a missing canonical file during migration' do
    custom = File.join(@root, 'selected-vault')
    File.rename(@path, custom)
    stub_const('PWN::Migrate::SCHEMA_FILE', File.join(@root, '.schema'))
    File.write(described_class::SCHEMA_FILE, JSON.generate(schema: described_class::SCHEMA_VERSION))
    allow(PWN::Backups).to receive(:active?).and_return(true)
    result = described_class.run(fix: true, backup: false, io: @io, pwn_env_path: custom)
    expect(result[:before][:incompatible]).to be_empty
    expect(result[:after][:incompatible]).to be_empty
    expect(result[:after][:files].find { |row| row[:rel] == 'pwn.yaml' }[:path]).to eq(custom)
    expect(File).not_to exist(@path)
  end

  it 'does not write during a dry run or when hardware encryption fails or is interrupted' do
    bytes = File.binread(@path)
    expect(described_class.backfill_vault(dry_run: true, io: @io)[:added]).to be_positive
    expect(File.binread(@path)).to eq(bytes)
    allow(PWN::Plugins::Vault).to receive(:encrypt_data).and_raise(IOError, 'synthetic device unavailable')
    expect(described_class.backfill_vault(io: @io)).to be_nil
    expect(File.binread(@path)).to eq(bytes)
    allow(PWN::Plugins::Vault).to receive(:encrypt_data).and_raise(Interrupt)
    expect { described_class.backfill_vault(io: @io) }.to raise_error(Interrupt)
    expect(File.binread(@path)).to eq(bytes)
    expect(Dir.children(@root)).to eq(['pwn.yaml'])
  end

  it 'reports missing keys in a hardware vault without a software decryptor' do
    bytes = File.binread(@path)
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    result = described_class.vault_drift
    expect(result).to include(user: @original)
    expect(result[:missing]).to include('ai.agent')
    expect(File.binread(@path)).to eq(bytes)
    expect(File).not_to exist("#{@path}.decryptor")
  end
end
