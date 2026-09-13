# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Github do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Github
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Github
    expect(help_response).to respond_to :help
  end

  it 'opens a fix pull request from verified findings without calling a live GitHub host' do
    calls = []
    allow(described_class).to receive(:api) do |opts|
      calls << opts
      { 'html_url' => 'https://github.com/example/app/pull/7', 'number' => 7 }
    end
    out = described_class.open_fix_pr(
      owner: 'example',
      repo: 'app',
      title: 'Fix fixture exposure',
      body: 'Retest the same path after the patch.',
      head: 'pwn-fix-fixture',
      base: 'main',
      sarif_path: '/tmp/does-not-need-to-exist-for-this-unit.sarif.json'
    )
    expect(out[:number]).to eq(7)
    expect(out[:html_url]).to include('/pull/7')
    expect(calls.last[:method].to_s.downcase).to eq('post')
    expect(calls.last[:path]).to eq('repos/example/app/pulls')
  end
end
