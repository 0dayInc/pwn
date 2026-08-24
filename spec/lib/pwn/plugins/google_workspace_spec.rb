# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::GoogleWorkspace do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'is wired into PWN::Env[:plugins][:google_workspace]' do
    tmpl = PWN::Config.env_template
    gw = tmpl.dig(:plugins, :google_workspace)
    expect(gw).to be_a(Hash)
    oauth = gw[:oauth]
    expect(oauth).to be_a(Hash)
    %i[client_id client_secret refresh_token bearer_token redirect_uri services].each do |k|
      expect(oauth).to have_key(k)
    end
  end

  it 'exposes OAuth enroll / refresh / check and service CRUD' do
    %i[
      obtain_oauth_auth_url
      exchange_oauth_code
      refresh_oauth_bearer_token
      bearer_token
      authenticated?
      revoke
      gmail_search
      gmail_get
      gmail_send
      gmail_reply
      gmail_labels
      gmail_modify
      calendar_list
      calendar_create
      calendar_update
      calendar_delete
      drive_search
      drive_get
      drive_upload
      drive_download
      drive_create_folder
      drive_share
      drive_delete
      docs_get
      docs_create
      docs_append
      sheets_create
      sheets_get
      sheets_update
      sheets_append
    ].each do |m|
      expect(described_class).to respond_to(m)
    end
  end

  it 'builds Google scopes from a services list' do
    scopes = described_class.scopes(services: 'email,calendar')
    expect(scopes).to include('https://www.googleapis.com/auth/gmail.modify')
    expect(scopes).to include('https://www.googleapis.com/auth/calendar')
    expect(scopes).not_to include('https://www.googleapis.com/auth/drive')

    all = described_class.scopes(services: 'all')
    %w[gmail.modify calendar drive documents spreadsheets].each do |s|
      expect(all.join(' ')).to include(s)
    end
  end

  it 'extracts an OAuth code from a redirect URL or raw code' do
    url = 'http://127.0.0.1:1/?code=4/0AXyz&scope=https://www.googleapis.com/auth/gmail.modify'
    expect(described_class.parse_oauth_code(code: url)).to eq('4/0AXyz')
    expect(described_class.parse_oauth_code(code: '4/0AXyz')).to eq('4/0AXyz')
  end

  it 'does not mention third-party agent product names in source' do
    src = File.read(described_class.method(:bearer_token).source_location.first)
    expect(src).not_to match(/hermes/i)
  end

  it 'writes refresh and bearer into Env and pwn.yaml when oauth_auth_url is authorized' do
    Dir.mktmpdir('pwn-gw-oauth-') do |dir|
      env_path = File.join(dir, 'pwn.yaml')
      dec_path = "#{env_path}.decryptor"
      key = '0' * 32
      iv = '1' * 16
      File.write(env_path, "plugins:\n  google_workspace:\n    oauth:\n      client_id: cid\n      client_secret: sec\n")
      File.write(dec_path, YAML.dump(key: key, iv: iv))
      allow(PWN::Plugins::Vault).to receive(:decrypt)
      allow(PWN::Plugins::Vault).to receive(:encrypt)
      allow(RestClient).to receive(:post).and_return(
        instance_double(RestClient::Response, body: {
          access_token: 'live-bearer',
          refresh_token: 'live-refresh',
          expires_in: 3600,
          scope: 'https://www.googleapis.com/auth/gmail.modify'
        }.to_json)
      )

      PWN::Env[:plugins] ||= {}
      PWN::Env[:plugins][:google_workspace] ||= {}
      PWN::Env[:plugins][:google_workspace][:oauth] ||= {}
      slot = PWN::Env[:plugins][:google_workspace][:oauth]
      prev = slot.dup
      slot[:client_id] = 'cid'
      slot[:client_secret] = 'sec'
      slot[:bearer_token] = nil
      slot[:refresh_token] = nil
      PWN::Env[:driver_opts] ||= {}
      PWN::Env[:driver_opts][:pwn_env_path] = env_path
      PWN::Env[:driver_opts][:pwn_dec_path] = dec_path

      result = described_class.obtain_oauth_auth_url(
        client_id: 'cid',
        client_secret: 'sec',
        services: 'email',
        wait: true,
        probe: ->(_redirect) { 'AUTHCODE' }
      )

      expect(result[:bearer_token]).to eq('live-bearer')
      expect(result[:refresh_token]).to eq('live-refresh')
      expect(slot[:bearer_token]).to eq('live-bearer')
      expect(slot[:refresh_token]).to eq('live-refresh')
      vault = YAML.load_file(env_path, symbolize_names: true)
      expect(vault.dig(:plugins, :google_workspace, :oauth, :bearer_token)).to eq('live-bearer')
      expect(vault.dig(:plugins, :google_workspace, :oauth, :refresh_token)).to eq('live-refresh')
    ensure
      if prev
        slot.clear
        slot.merge!(prev)
      end
      PWN::Env[:driver_opts].delete(:pwn_env_path) if PWN::Env[:driver_opts].is_a?(Hash)
      PWN::Env[:driver_opts].delete(:pwn_dec_path) if PWN::Env[:driver_opts].is_a?(Hash)
    end
  end

  it 'captures a loopback authorize hit without a paste step' do
    require 'net/http'
    server = described_class.send(:open_oauth_listener, redirect_uri: 'http://127.0.0.1:0/')
    redir = described_class.send(:listener_redirect, server: server, fallback: 'http://127.0.0.1/')
    hit = Thread.new do
      sleep 0.05
      Net::HTTP.get(URI("#{redir}?code=FROMBROWSER"))
    end
    code = described_class.send(
      :await_oauth_redirect,
      redirect_uri: redir,
      timeout: 5,
      server: server
    )
    expect(code).to eq('FROMBROWSER')
    expect(hit.value).to include('authorized')
  ensure
    begin
      server&.close
    rescue StandardError
      nil
    end
  end
end
