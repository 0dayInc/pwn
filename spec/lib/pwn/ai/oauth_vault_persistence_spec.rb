# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'OAuth vault persistence' do
  before do
    @home = Dir.mktmpdir('pwn-oauth-vault-')
    allow(Dir).to receive(:home).and_return(@home)
    @path = File.join(@home, 'custom-vault')
    @decryptor = File.join(@home, 'independent-decryptor')
    stub_const('PWN::Env', { driver_opts: { pwn_env_path: @path, pwn_dec_path: @decryptor }, ai: {}, plugins: {} })
    @runtime = Thread.current[:pwn_request_runtime]
    Thread.current[:pwn_request_runtime] = nil
    @cfg = { unrelated: 'keep', ai: {}, plugins: {} }
    @key = Base64.strict_encode64('k' * 32)
    @iv = Base64.strict_encode64('i' * 16)
    allow(ENV).to receive(:fetch).and_call_original
    allow(ENV).to receive(:fetch).with('PWN_DECRYPTOR_KEY', nil).and_return(nil)
    allow(ENV).to receive(:fetch).with('PWN_DECRYPTOR_IV', nil).and_return(nil)
    @selector = { yubikey: { slot: 2, serial: '123456' } }
    @device = double('offline YubiKey')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) do |opts|
      expect(opts).to include(@selector[:yubikey])
      OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts.fetch(:challenge))
    end
    File.write(@path, YAML.dump(@cfg))
    PWN::Plugins::Vault.encrypt(file: @path, key: @key, iv: @iv)
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
  end

  after do
    Thread.current[:pwn_request_runtime] = @runtime
    FileUtils.remove_entry(@home)
  end

  {
    PWN::AI::OpenAI => %i[ai openai],
    PWN::AI::Anthropic => %i[ai anthropic],
    PWN::AI::Grok => %i[ai grok],
    PWN::Plugins::GoogleWorkspace => %i[plugins google_workspace]
  }.each do |provider, config_path|
    describe provider do
      before do
        @cfg[config_path.first][config_path.last] = { model: 'fixture-model', oauth: { refresh_token: 'previous-refresh' } }
      end

      it 'merges OAuth fields through the shared updater without requiring a sidecar' do
        oauth = { bearer_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_at: 123, ignored: 'do-not-persist' }
        expect(PWN::Plugins::Vault).not_to receive(:decrypt)
        expect(PWN::Plugins::Vault).not_to receive(:encrypt)
        expect(PWN::Plugins::Vault).to receive(:update).with(file: @path, decryptor_file: @decryptor).and_yield(@cfg).and_return(:saved)

        expect(described_class.send(:persist_oauth_to_vault, oauth: oauth)).to be(true)
        expect(@cfg.dig(*config_path, :oauth)).to eq(oauth.except(:ignored))
        expect(@cfg.dig(*config_path, :model)).to eq('fixture-model')
        expect(@cfg[:unrelated]).to eq('keep')
        expect(File).not_to exist(@decryptor)
      end

      %i[legacy hardware].each do |format|
        it "preserves #{format} credentials and field merge semantics with ciphertext-only staging" do
          access = format == :hardware ? @selector : { key: @key, iv: @iv }
          File.write(@decryptor, YAML.dump(key: @key, iv: @iv)) if format == :legacy
          @cfg.dig(*config_path, :oauth).merge!(expires_at: 42, keep: 'unchanged')
          File.write(@path, YAML.dump(@cfg))
          PWN::Plugins::Vault.encrypt({ file: @path }.merge(access))
          before = File.binread(@path)
          sidecar_before = File.binread(@decryptor) if format == :legacy
          oauth = { bearer_token: 'rotated-access', refresh_token: nil, expires_at: nil,
                    id_token: 'rotated-id', account_id: 'rotated-account', client_id: 'fixture-client-id',
                    client_secret: 'fixture-client-secret', redirect_uri: 'https://example.invalid/callback', scope: 'fixture-scope', ignored: 'ignored' }
          accepted = %i[bearer_token]
          accepted += %i[id_token account_id] if config_path.last == :openai
          accepted += %i[client_id client_secret redirect_uri scope] if config_path.last == :google_workspace
          expected = Marshal.load(Marshal.dump(@cfg))
          expected.dig(*config_path, :oauth).merge!(oauth.slice(*accepted))
          expect(PWN::Plugins::Vault).not_to receive(:decrypt)
          expect(PWN::Plugins::Vault).not_to receive(:encrypt)
          expect(File).not_to receive(:write)
          expect(Tempfile).to receive(:create).and_wrap_original do |create, *args, &block|
            create.call(*args) do |temp|
              expect(temp).to receive(:write).and_wrap_original do |write, bytes|
                plaintext = PWN::Plugins::Vault.decrypt_data(access.merge(data: bytes))
                expect(YAML.safe_load(plaintext, permitted_classes: [Symbol], symbolize_names: true)).to eq(expected)
                expect(bytes).not_to include('rotated-access', 'fixture-client-secret')
                expect(File.binread(@path)).to eq(before)
                expect(temp.stat.mode & 0o777).to eq(0o600)
                write.call(bytes)
              end
              block.call(temp)
            end
          end

          expect(described_class.send(:persist_oauth_to_vault, oauth: oauth)).to be(true)
          expect(PWN::Plugins::Vault.dump({ file: @path }.merge(access))).to eq(expected)
          expect(File.stat(@path).mode & 0o777).to eq(0o600)
          if format == :legacy
            expect(File.binread(@decryptor)).to eq(sidecar_before)
            expect(Dir.children(@home)).to match_array(%w[custom-vault independent-decryptor])
          else
            expect(File.binread(@path)).to start_with(PWN::Plugins::Vault::YUBIKEY_HEADER)
            expect(Dir.children(@home)).to eq(['custom-vault'])
          end
        end
      end

      it 'fails closed without prompting when legacy credentials are missing' do
        before = File.binread(@path)
        expect(PWN::Plugins::Vault).not_to receive(:decrypt_data)
        expect(PWN::Plugins::Vault).not_to receive(:encrypt_data)
        expect(described_class.send(:persist_oauth_to_vault, oauth: { bearer_token: 'rotated-access' })).to be(false)
        expect(File.binread(@path)).to eq(before)
        expect(Dir.children(@home)).to eq(['custom-vault'])
      end

      it 'keeps ciphertext unchanged and excludes secret-bearing exception text on encryption failure' do
        File.write(@decryptor, YAML.dump(key: @key, iv: @iv))
        before = File.binread(@path)
        allow(PWN::Plugins::Vault).to receive(:encrypt_data).and_raise(IOError, 'synthetic-private-error')
        expect(PWN::Plugins::Vault).not_to receive(:decrypt)
        expect(File).not_to receive(:write)
        expect(Tempfile).not_to receive(:create)
        result = nil

        expect do
          result = described_class.send(:persist_oauth_to_vault, oauth: { bearer_token: 'rotated-access' })
        end.to output(/\A\[!\] .* OAuth vault persistence failed \(session tokens still updated\): IOError\n\z/).to_stderr
        expect(result).to be(false)
        expect(File.binread(@path)).to eq(before)
        expect(Dir.children(@home)).to match_array(%w[custom-vault independent-decryptor])
      end

      it 'uses the default vault path with hardware metadata and no sidecar' do
        default_path = File.join(@home, '.pwn', 'pwn.yaml')
        FileUtils.mkdir_p(File.dirname(default_path))
        File.write(default_path, YAML.dump(@cfg))
        PWN::Plugins::Vault.encrypt({ file: default_path }.merge(@selector))
        custom_before = File.binread(@path)
        PWN::Env[:driver_opts] = {}

        expect(described_class.send(:persist_oauth_to_vault, oauth: { bearer_token: 'rotated-access' })).to be(true)
        expect(PWN::Plugins::Vault.dump(file: default_path).dig(*config_path, :oauth, :bearer_token)).to eq('rotated-access')
        expect(File.binread(@path)).to eq(custom_before)
        expect(Dir.children(File.dirname(default_path))).to eq(['pwn.yaml'])
      end

      it 'leaves hardware ciphertext unchanged when the device disappears after decryption' do
        File.write(@path, YAML.dump(@cfg))
        PWN::Plugins::Vault.encrypt({ file: @path }.merge(@selector))
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
        result = nil

        expect do
          result = described_class.send(:persist_oauth_to_vault, oauth: { bearer_token: 'rotated-access' })
        end.to output(/\A\[!\] .* OAuth vault persistence failed \(session tokens still updated\): IOError\n\z/).to_stderr
        expect(result).to be(false)
        expect(calls).to eq(2)
        expect(File.binread(@path)).to eq(before)
        expect(Dir.children(@home)).to eq(['custom-vault'])
      end

      it 'persists a rotated provider refresh token during a request runtime to a hardware vault' do
        File.write(@path, YAML.dump(@cfg))
        PWN::Plugins::Vault.encrypt({ file: @path }.merge(@selector))
        runtime = double('request runtime')
        Thread.current[:pwn_request_runtime] = runtime
        expect(runtime).to receive(:update_provider_oauth).with(config_path.last, hash_including(bearer_token: 'rotated-access', refresh_token: 'rotated-refresh')).and_return(:updated) if config_path.first == :ai
        allow(RestClient).to receive(:post).and_return(double(body: { access_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_in: 3600 }.to_json))
        expect(PWN::Plugins::Vault).not_to receive(:decrypt)
        expect(PWN::Plugins::Vault).not_to receive(:encrypt)

        expect(described_class.refresh_oauth_bearer_token(refresh_token: 'previous-refresh', client_id: 'fixture-id', client_secret: 'fixture-secret')).to eq('rotated-access')
        persisted = PWN::Plugins::Vault.dump(file: @path)
        expect(persisted.dig(*config_path, :oauth)).to include(bearer_token: 'rotated-access', refresh_token: 'rotated-refresh')
        expect(persisted.dig(*config_path, :model)).to eq('fixture-model')
        expect(persisted[:unrelated]).to eq('keep')
        expect(File.binread(@path)).to start_with(PWN::Plugins::Vault::YUBIKEY_HEADER)
        expect(File.stat(@path).mode & 0o777).to eq(0o600)
        expect(Dir.children(@home)).to eq(['custom-vault'])
      end
    end
  end
end
