# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'stringio'

RSpec.describe PWN::Plugins::REPL::AIConsole::VaultEdit, 'hardware vault editing' do
  around do |example|
    Dir.mktmpdir('vault-edit-yubikey-') do |root|
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
    @original = { ai: { active: 'ollama', ollama: { model: 'fixture-model', key: 'synthetic-private-value' } }, retained: ['fixture-value'] }
    File.binwrite(@path, PWN::Plugins::Vault.encrypt_data(data: YAML.dump(@original), yubikey: { slot: 2, serial: '12345678' }))
    File.chmod(0o600, @path)
    stub_const('PWN::Env', @original.merge(driver_opts: { pwn_env_path: @path, pwn_dec_path: File.join(@root, 'absent-sidecar') }))
    stub_const('PWN::EnvRedacted', {})
    allow(Pry).to receive(:history).and_return(Pry::History.new(file_path: File.join(@root, 'history')))
  end

  it 'keeps malformed YAML and cancellation private and leaves hardware ciphertext untouched' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    bytes = File.binread(@path)
    console.submit('/vault edit')
    console.instance_variable_get(:@vault_editor).replace('synthetic-private-value: [')
    console.handle("\u0013")
    expect(console.instance_variable_get(:@vault_error)).to include('Invalid YAML')
    expect(console.instance_variable_get(:@vault_error)).not_to include('synthetic-private-value')
    console.handle("\e")
    expect(console.instance_variable_get(:@vault_editor)).to be_nil
    expect(console.instance_variable_get(:@timeline).inspect).not_to include('synthetic-private-value', 'Invalid YAML')
    expect(Pry.history.to_a.join).not_to include('synthetic-private-value')
    expect(File.binread(@path)).to eq(bytes)
  end

  it 'preserves hardware ciphertext and Env when encryption fails or is interrupted' do
    edit = described_class.new(%w[ai ollama model])
    bytes = File.binread(@path)
    env = PWN::Env
    allow(PWN::Plugins::Vault).to receive(:encrypt_data).and_raise(IOError, 'synthetic-private-value')
    expect { edit.save('new-model') }.to raise_error(described_class::Error, /Vault not saved/)
    expect(File.binread(@path)).to eq(bytes)
    expect(PWN::Env).to equal(env)
    allow(PWN::Plugins::Vault).to receive(:encrypt_data).and_raise(Interrupt)
    expect { edit.save('new-model') }.to raise_error(Interrupt)
    expect(File.binread(@path)).to eq(bytes)
    expect(PWN::Env).to equal(env)
    expect(Dir.children(@root)).to eq(['selected-vault'])
  end

  it 'merges unrelated hardware edits and refuses a changed selected scope' do
    edit = described_class.new(%w[ai ollama model])
    described_class.new(['retained']).save("- changed\n")
    edit.save('new-model')
    expect(PWN::Plugins::Vault.dump(file: @path)[:retained]).to eq(['changed'])
    bytes = File.binread(@path)
    expect { edit.save('stale-model') }.to raise_error(described_class::Error, /scope changed/)
    expect(File.binread(@path)).to eq(bytes)
  end

  it 'rejects a final ciphertext conflict without leaving a staging file' do
    edit = described_class.new(%w[ai ollama model])
    other = PWN::Plugins::Vault.encrypt_data(data: YAML.dump(@original.merge(retained: ['concurrent'])), yubikey: { slot: 2 })
    allow(edit).to receive(:atomic_write).and_wrap_original do |method, encrypted, previous|
      File.binwrite(@path, other)
      method.call(encrypted, previous)
    end
    expect { edit.save('new-model') }.to raise_error(described_class::Error, /changed during save/)
    expect(File.binread(@path)).to eq(other)
    expect(Dir.children(@root)).to eq(['selected-vault'])
  end

  it 'fails closed with a different device response and redacted open errors' do
    bytes = File.binread(@path)
    allow(PWN::Plugins::YubiKey).to receive(:challenge_response).and_return('x' * 20)
    expect { described_class.new([]) }.to raise_error(described_class::Error, /Cannot open vault/)
    expect(File.binread(@path)).to eq(bytes)
  end

  it 'opens and saves the selected hardware scope without requiring or creating a decryptor' do
    expect(PWN::Config).not_to receive(:refresh_env)
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    edit = described_class.new(%w[ai ollama model])
    expect(edit.text).to include('fixture-model')
    expect(edit.save('new-model')).to eq(:saved)
    expect(PWN::Plugins::Vault.hardware_encrypted?(file: @path)).to be(true)
    document = PWN::Plugins::Vault.dump(file: @path)
    expect(document.dig(:ai, :ollama, :model)).to eq('new-model')
    expect(document[:retained]).to eq(['fixture-value'])
    expect(PWN::Env.dig(:ai, :ollama, :model)).to eq('new-model')
    expect(PWN::EnvRedacted.dig(:ai, :ollama, :key)).to include('REDACTED')
    expect(Dir.children(@root)).to eq(['selected-vault'])
  end
end
