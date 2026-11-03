# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'stringio'

RSpec.describe PWN::Setup, 'hardware vault doctor' do
  around do |example|
    Dir.mktmpdir('setup-yubikey-') do |root|
      @root = root
      example.run
    end
  end

  before do
    allow(Dir).to receive(:home).and_return(@root)
    @pwn_root = File.join(@root, '.pwn')
    FileUtils.mkdir_p(@pwn_root)
    stub_const('PWN::Env', {})
    stub_const('PWN::Migrate::PWN_ROOT', @pwn_root)
    stub_const('PWN::Migrate::SCHEMA_FILE', File.join(@pwn_root, '.schema'))
    stub_const('PWN::Setup::NATIVE_GEMS', {})
    stub_const('PWN::Setup::TOOLCHAIN', {})
    stub_const('PWN::Setup::NATIVE_LIBRARIES', {})
    allow(described_class).to receive(:pkg_manager).and_return(key: :fixture)
    allow(described_class).to receive(:detect_os_attr).and_return('fixture')
    stub_const('PWN::Plugins::YubiKey', double('synthetic YubiKey'))
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response) do |opts|
      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts[:challenge])
    end
    @path = File.join(@pwn_root, 'pwn.yaml')
    File.binwrite(@path, PWN::Plugins::Vault.encrypt_data(data: YAML.dump(ai: { active: 'ollama' }), yubikey: { slot: 2 }))
    @io = StringIO.new
  end

  it 'uses Config driver paths consistently in setup and the migration state verifier' do
    custom = File.join(@root, 'custom-vault')
    File.rename(@path, custom)
    PWN::Env[:driver_opts] = { pwn_env_path: custom, pwn_dec_path: File.join(@root, 'custom-sidecar') }
    expect(PWN::Plugins::YubiKey).not_to receive(:challenge_response)
    report = described_class.check(io: @io)
    expect(report[:ok]).to be(true)
    expect(report.dig(:state, :files).find { |row| row[:rel] == 'pwn.yaml' }).to include(ok: true, path: custom)
    expect(@io.string).to include('YubiKey', 'no software decryptor required')
    expect(File).not_to exist(@path)
    expect(File).not_to exist(PWN::Env.dig(:driver_opts, :pwn_dec_path))
  end

  it 'recognizes hardware vaults without a missing-decryptor warning or a device operation' do
    bytes = File.binread(@path)
    expect(PWN::Plugins::YubiKey).not_to receive(:challenge_response)
    expect(PWN::Plugins::Vault).not_to receive(:create)
    report = described_class.check(io: @io)
    expect(report[:ok]).to be(true)
    expect(report.dig(:state, :incompatible)).to be_empty
    expect(@io.string).to include('YubiKey', 'no software decryptor required')
    expect(@io.string).not_to include('decryptor MISSING')
    expect(File.binread(@path)).to eq(bytes)
    expect(Dir.children(@pwn_root)).to eq(['pwn.yaml'])
  end
end
