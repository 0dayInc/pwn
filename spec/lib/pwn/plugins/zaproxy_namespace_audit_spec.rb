# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::Plugins::Zaproxy, 'namespace audit regressions' do
  it 'filters returned HAR entries by keyword' do
    allow(described_class).to receive(:stop)
    response = double('HAR response', body: { log: { entries: [{ request: { url: 'https://example.invalid/keep' } }, { request: { url: 'https://example.invalid/drop' } }] } }.to_json)
    empty = double('empty page', body: { log: { entries: [] } }.to_json)
    allow(described_class).to receive(:zap_rest_call).and_return(response, empty)
    result = described_class.get_sitemap(zap_obj: { api_key: 'fixture-token' }, keyword: '/keep', return_as: :har)
    expect(result).to eq([{ request: { url: 'https://example.invalid/keep' } }])
  end

  it 'does not retry shutdown recursively when the shutdown request fails' do
    allow(PWN::Plugins::TransparentBrowser).to receive(:close)
    allow(RestClient::Request).to receive(:execute).and_raise(Errno::ECONNREFUSED)
    calls = 0
    allow(described_class).to receive(:stop).and_wrap_original do |original, options|
      calls += 1
      raise 'recursive shutdown' if calls > 1

      original.call(options)
    end
    zap = { api_key: 'fixture-token', rest_browser: RestClient, mitm_rest_api: 'zap.invalid' }
    expect { described_class.stop(zap_obj: zap) }.to raise_error(Errno::ECONNREFUSED)
    expect(calls).to eq(1)
  end
end
