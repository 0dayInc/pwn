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
end
