# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'stringio'

RSpec.describe PWN::Plugins::REPL::Vault, 'hardware pwn-vault command' do
  around do |example|
    Dir.mktmpdir('repl-vault-yubikey-') do |root|
      @root = root
      example.run
    end
  end

  before do
    allow(Dir).to receive(:home).and_return(@root)
    stub_const('PWN::Plugins::YubiKey', double('synthetic YubiKey'))
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response) do |opts|
      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts[:challenge])
    end
    @path = File.join(@root, 'selected-vault')
    original = { ai: { active: 'ollama', ollama: { model: 'fixture-model' } } }
    File.binwrite(@path, PWN::Plugins::Vault.encrypt_data(data: YAML.dump(original), yubikey: { slot: 2 }))
    stub_const('PWN::Env', { driver_opts: { pwn_env_path: @path } })
    described_class.add_commands
    @command = Pry::Commands.find_command('pwn-vault').new(pry_instance: Pry.new, output: StringIO.new)
  end

  it 'edits and refreshes a hardware vault without requiring a sidecar or passing software keys' do
    expect(PWN::Plugins::Vault).to receive(:edit).with({ file: @path, yubikey: { slot: 2 } }) do |opts|
      PWN::Plugins::Vault.update(opts) { |cfg| cfg[:ai][:ollama][:model] = 'new-model' }
    end
    expect(PWN::Config).to receive(:refresh_env).with({ pwn_env_path: @path, pwn_dec_path: "#{@path}.decryptor", yubikey: { slot: 2 } })
    @command.process
    expect(PWN::Plugins::Vault.dump(file: @path).dig(:ai, :ollama, :model)).to eq('new-model')
    expect(PWN::Plugins::Vault.hardware_encrypted?(file: @path)).to be(true)
    expect(Dir.children(@root)).to eq(['selected-vault'])
  end
end
