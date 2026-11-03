# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'stringio'

RSpec.describe PWN::AI::Anthropic, 'hardware vault enrollment persistence' do
  it 'persists initial enrollment as well as refresh without printing returned credentials' do
    Dir.mktmpdir('anthropic-yubikey-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      path = File.join(root, 'vault')
      config = { ai: { active: :anthropic, anthropic: { model: 'fixture-model', oauth: {} } }, driver_opts: { pwn_env_path: path } }
      stub_const('PWN::Env', config)
      device = double('offline YubiKey')
      stub_const('PWN::Plugins::YubiKey', device)
      allow(device).to receive(:challenge_response) { |opts| OpenSSL::HMAC.digest('SHA1', 'fixture-slot', opts[:challenge]) }
      File.write(path, YAML.dump(config.except(:driver_opts)))
      PWN::Plugins::Vault.create(file: path, yubikey: {})
      allow(RestClient).to receive(:post).and_return(double(body: JSON.generate(access_token: 'synthetic-access-token', refresh_token: 'synthetic-refresh-token', expires_in: 3600)))
      previous_input = $stdin
      previous_output = $stdout
      begin
        $stdin = StringIO.new("synthetic-authorization-code\n")
        $stdout = StringIO.new
        expect(described_class.obtain_oauth_bearer_token).to eq('synthetic-access-token')
        expect($stdout.string).not_to include('synthetic-access-token', 'synthetic-refresh-token')
        expect(PWN::Env.dig(:ai, :anthropic, :oauth)).to include(bearer_token: 'synthetic-access-token')
        persisted = PWN::Plugins::Vault.dump(file: path)
        expect(persisted.dig(:ai, :anthropic, :oauth)).to include(bearer_token: 'synthetic-access-token', refresh_token: 'synthetic-refresh-token')
        expect(File.binread(path)).to start_with(PWN::Plugins::Vault::YUBIKEY_HEADER)
      ensure
        $stdin = previous_input
        $stdout = previous_output
      end
    end
  end
end
