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
end
