# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Extrospection (osint/social)' do
  it 'should expose SOCIAL_FEEDS and the vendored SOCIAL_SITES_FILE' do
    e = PWN::AI::Agent::Extrospection
    expect(e.const_get(:SOCIAL_FEEDS)).to include(
      :keybase, :gravatar, :mastodon, :bluesky, :hackernews,
      :stackexchange, :npm, :pypi, :rubygems, :crates,
      :dockerhub, :codeberg, :sourcehut, :chesscom, :lichess,
      :steam, :telegram, :social_sweep
    )
    expect(File.exist?(e.const_get(:SOCIAL_SITES_FILE))).to be true
  end

  it 'should surface a social config with sites_file / max_threads / timeout' do
    sc = PWN::AI::Agent::Extrospection.send(:osint_social_config)
    expect(sc).to include(:sites_file, :max_threads, :timeout)
  end

  it 'should load the vendored social_sites.json into structured entries' do
    sites = PWN::AI::Agent::Extrospection.send(:load_social_sites)
    expect(sites).to be_an(Array)
    expect(sites).not_to be_empty
    expect(sites.first).to include(:name, :url, :method)
  end

  it 'should classify sweep verdicts (present / absent / error)' do
    e = PWN::AI::Agent::Extrospection
    site = { absent_status: [404], absent_body: ['not found'] }
    expect(e.send(:social_sweep_verdict, site: site, resp: { error: 'x' })).to eq :error
    expect(e.send(:social_sweep_verdict, site: site, resp: { code: 404, body: '' })).to eq :absent
    expect(e.send(:social_sweep_verdict, site: site, resp: { code: 200, body: '<html>ok</html>' })).to eq :present
  end
end
