# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::Fuzz do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Fuzz
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Fuzz
    expect(help_response).to respond_to :help
  end

  it 'http mutates a request with dictionary payloads' do
    reqs = described_class.http(
      request: "GET /FUZZ HTTP/1.1\r\nHost: x\r\n\r\n",
      dictionary: %w[admin ../]
    )
    expect(reqs.length).to eq(2)
    expect(reqs.first).to include('admin')
  end

  it 'file_format mutates a seed with dictionary blobs' do
    Dir.mktmpdir do |dir|
      seed = File.join(dir, 'seed.bin')
      File.binwrite(seed, 'AAAA')
      out = described_class.file_format(path: seed, dictionary: ["\xff\xff"])
      expect(out).to be_an(Array)
      expect(out.first).to be_a(String)
    end
  end
end
