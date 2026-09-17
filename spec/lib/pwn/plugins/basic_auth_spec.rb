# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::BasicAuth do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::BasicAuth
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::BasicAuth
    expect(help_response).to respond_to :help
  end

  it 'offers recon loot when a service prompts for auth' do
    Dir.mktmpdir('pwn-basic-auth-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      PWN::Plugins::Vault.ingest(
        text: "username=admin\npassword=hunter2\n",
        host: 'app.example.test',
        source: 'recon',
        where: 'banner:80',
        engagement: 'lab'
      )
      encoded = described_class.encode(host: 'app.example.test', engagement: 'lab', service: 'http')
      expect(described_class.decode(base64_str: encoded)).to eq('admin:hunter2')
    end
  end
end
