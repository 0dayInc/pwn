# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::GoogleWorkspace, 'PR-GATE-01 explicit OAuth revocation' do
  before do
    @home = Dir.mktmpdir('pwn-provider-oauth-')
    allow(Dir).to receive(:home).and_return(@home)
    @path = File.join(@home, 'vault')
    @decryptor = File.join(@home, 'decryptor')
    stub_const('PWN::Plugins::GoogleWorkspace::PENDING_FILE', File.join(@home, 'pending'))
    @oauth = { bearer_token: 'fixture-access', refresh_token: 'fixture-refresh', expires_at: 42,
               client_id: 'fixture-client', client_secret: 'fixture-secret', scope: 'fixture-scope' }
    @config = { unrelated: 'keep', plugins: { google_workspace: { oauth: @oauth.dup, other: 'keep' } } }
    stub_const('PWN::Env', Marshal.load(Marshal.dump(@config)).merge(driver_opts: { pwn_env_path: @path, pwn_dec_path: @decryptor }))
    allow(ENV).to receive(:fetch).and_call_original
    allow(ENV).to receive(:fetch).with('PWN_DECRYPTOR_KEY', nil).and_return(nil)
    allow(ENV).to receive(:fetch).with('PWN_DECRYPTOR_IV', nil).and_return(nil)
    @device = double('synthetic hardware boundary')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) do |opts|
      expect(opts).to include(slot: 2, serial: '123456')
      OpenSSL::HMAC.digest('SHA1', 'synthetic-fixture-secret', opts.fetch(:challenge))
    end
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
  end

  after { FileUtils.remove_entry(@home) }

  %i[legacy hardware].each do |format|
    context "with #{format} ciphertext" do
      before do
        @access = if format == :legacy
                    { key: Base64.strict_encode64('k' * 32), iv: Base64.strict_encode64('i' * 16) }
                  else
                    { yubikey: { slot: 2, serial: '123456' } }
                  end
        File.write(@decryptor, YAML.dump(@access)) if format == :legacy
        File.binwrite(@path, PWN::Plugins::Vault.encrypt_data(@access.merge(data: YAML.dump(@config))))
      end

      [{}, { refresh_token: nil, expires_at: nil, client_secret: nil }].each do |fields|
        it "retains existing values for #{fields.empty? ? 'omitted' : 'nil'} OAuth fields" do
          expect(described_class.send(:persist_oauth_to_vault, oauth: fields.merge(bearer_token: 'fixture-rotated'))).to be(true)
          persisted = PWN::Plugins::Vault.dump(@access.merge(file: @path))
          expect(persisted.dig(:plugins, :google_workspace, :oauth)).to eq(@oauth.merge(bearer_token: 'fixture-rotated'))
          expect(File.binread(@path)).not_to include('fixture-rotated', 'fixture-refresh', 'fixture-secret')
        end
      end

      it 'revokes persisted tokens through the public entrypoint without clearing client metadata' do
        expect(RestClient).to receive(:post).with(described_class::REVOKE_URI, { token: 'fixture-refresh' }, content_type: 'application/x-www-form-urlencoded').and_return('')
        expect(PWN::Plugins::Vault).not_to receive(:decrypt)
        expect(PWN::Plugins::Vault).not_to receive(:encrypt)
        expect(File).not_to receive(:write)
        expect(Tempfile).to receive(:create).and_wrap_original do |create, *args, &block|
          create.call(*args) do |temp|
            expect(temp).to receive(:write).and_wrap_original do |write, bytes|
              plaintext = PWN::Plugins::Vault.decrypt_data(@access.merge(data: bytes))
              expect(YAML.safe_load(plaintext, permitted_classes: [Symbol], symbolize_names: true).dig(:plugins, :google_workspace, :oauth)).to eq(@oauth.merge(bearer_token: '', refresh_token: nil, expires_at: nil))
              expect(bytes).not_to include('fixture-access', 'fixture-refresh', 'fixture-secret')
              write.call(bytes)
            end
            block.call(temp)
          end
        end
        expect(described_class.revoke).to be(true)
        expect(PWN::Env.dig(:plugins, :google_workspace, :oauth)).to eq(@oauth.merge(bearer_token: nil, refresh_token: nil, expires_at: nil))
        persisted = PWN::Plugins::Vault.dump(@access.merge(file: @path))
        expect(persisted.dig(:plugins, :google_workspace, :oauth)).to eq(@oauth.merge(bearer_token: '', refresh_token: nil, expires_at: nil))
        expect(persisted[:unrelated]).to eq('keep')
        expect(persisted.dig(:plugins, :google_workspace, :other)).to eq('keep')
        expect(File.stat(@path).mode & 0o777).to eq(0o600)
        expect(Dir.children(@home)).to match_array(format == :legacy ? %w[vault decryptor] : ['vault'])
        expect(described_class.authenticated?).to be(false)
      end
    end
  end
end
