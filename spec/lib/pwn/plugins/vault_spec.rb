# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::Vault do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Vault
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Vault
    expect(help_response).to respond_to :help
  end

  it 'expands vault tokens and redacts stored secrets' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      described_class.store(label: 'api', secret: 's3cret-value')
      expect(described_class.fetch(label: 'api')).to eq('s3cret-value')
      expect(described_class.expand(text: 'tok={{vault:api}}')).to include('s3cret-value')
      expect(described_class.redact(text: 'tok=s3cret-value')).to include('{{vault:api}}')
    end
  end

  it 'stores engagement-scoped creds with provenance and offers them for auth' do
    Dir.mktmpdir('pwn-loot-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      row = described_class.store(
        secret: 'hunter2',
        username: 'admin',
        host: 'app.example.test',
        service: 'http',
        kind: 'password',
        source: 'recon',
        where: 'https://app.example.test/.env',
        finding_id: 'f00bar',
        engagement: 'lab'
      )
      expect(row[:engagement]).to eq('lab')
      expect(row[:finding_id]).to eq('f00bar')
      expect(row[:where]).to include('.env')
      hits = described_class.query(host: 'app.example.test', engagement: 'lab')
      expect(hits.first[:username]).to eq('admin')
      expect(hits.first[:finding_id]).to eq('f00bar')
      offered = described_class.offer(host: 'app.example.test', service: 'http', engagement: 'lab')
      expect(offered.first[:username]).to eq('admin')
      expect(offered.first[:secret]).to eq('hunter2')
    end
  end

  it 'ingests recon banner creds into the loot store' do
    Dir.mktmpdir('pwn-loot-ingest-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      described_class.ingest(
        text: "username=admin\npassword=hunter2\n",
        host: 'app.example.test',
        source: 'recon',
        where: 'banner:22',
        engagement: 'lab'
      )
      offered = described_class.offer(host: 'app.example.test', engagement: 'lab')
      expect(offered.first[:secret]).to eq('hunter2')
    end
  end
end
