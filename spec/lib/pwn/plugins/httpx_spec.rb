# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe PWN::Plugins::Httpx do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'parses httpx JSONL tech stack without a live probe' do
    jsonl = "#{JSON.generate('url' => 'https://wp.example.test', 'status_code' => 200, 'title' => 'WordPress', 'tech' => %w[nginx PHP WordPress], 'webserver' => 'nginx')}\n"
    row = described_class.probe(jsonl: jsonl)
    expect(row[:hosts].first['url']).to include('wp.example.test')
    expect(row[:techs].join).to match(/wordpress/i)
    expect(row[:techs].join).to match(/nginx/i)
  end
end
