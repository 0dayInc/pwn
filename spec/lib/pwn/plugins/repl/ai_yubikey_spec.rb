# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::REPL, 'hardware vault settings persistence' do
  around do |example|
    Dir.mktmpdir('ai-yubikey-') do |root|
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
    @original = { ai: { active: 'ollama', ollama: { model: 'fixture-model', system_role_content: 'fixture-role' } }, retained: 'fixture-value' }
    File.binwrite(@path, PWN::Plugins::Vault.encrypt_data(data: YAML.dump(@original), yubikey: { slot: 2 }))
    stub_const('PWN::Env', @original.merge(driver_opts: { pwn_env_path: @path, pwn_dec_path: File.join(@root, 'absent-sidecar') }))
  end

  it 'preserves ciphertext and Env on encryption failure without logging private exception content' do
    bytes = File.binread(@path)
    env = Marshal.dump(PWN::Env)
    allow(PWN::Plugins::Vault).to receive(:encrypt_data).and_raise(IOError, 'synthetic-private-exception')
    expect do
      expect(described_class.persist_ai_selection(engine: 'ollama', model: 'new-model')).to be(false)
    end.to output(/settings persist failed: IOError/).to_stderr
    expect(File.binread(@path)).to eq(bytes)
    expect(Marshal.dump(PWN::Env)).to eq(env)
    expect(Dir.children(@root)).to eq(['selected-vault'])
    expect do
      described_class.persist_ai_selection(engine: 'ollama', model: 'new-model')
    end.not_to output(/synthetic-private-exception/).to_stderr
  end

  it 'persists model and effort into the hardware vault without converting its format or losing other settings' do
    expect(described_class.persist_ai_selection(engine: 'ollama', model: 'new-model', reasoning_effort: 'high')).to be(true)
    expect(PWN::Plugins::Vault.hardware_encrypted?(file: @path)).to be(true)
    expected = { ai: { active: 'ollama', ollama: { model: 'new-model', system_role_content: 'fixture-role', reasoning_effort: 'high' } }, retained: 'fixture-value' }
    expect(PWN::Plugins::Vault.dump(file: @path)).to eq(expected)
    expect(Dir.children(@root)).to eq(['selected-vault'])
  end
end
