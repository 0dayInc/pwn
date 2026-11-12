# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::Plugins::BurpSuite, 'namespace audit regressions' do
  let(:browser) { double('offline Burp REST browser') }
  let(:burp) { { rest_browser: browser, mitm_rest_api: 'burp.invalid' } }

  before { allow(described_class).to receive(:stop) }

  %i[get_sitemap get_proxy_history].each do |method|
    it "returns a HAR object from #{method}" do
      entry = { request: Base64.strict_encode64("GET /items HTTP/1.1\r\nHost: example.invalid\r\n\r\n"), http_service: { protocol: 'https' } }
      allow(browser).to receive(:get).and_return([entry].to_json)
      result = described_class.public_send(method, burp_obj: burp, return_as: :har)
      expect(result).to be_a(Hash)
      expect(result.dig(:log, :entries).length).to eq(1)
    end

    it "preserves HTTPS in HAR from #{method}" do
      entry = { request: Base64.strict_encode64("GET /items HTTP/1.1\r\nHost: example.invalid\r\n\r\n"), http_service: { protocol: 'https' } }
      allow(browser).to receive(:get).and_return([entry].to_json)
      result = described_class.public_send(method, burp_obj: burp, return_as: :har)
      expect(result.dig(:log, :entries, 0, :request, :url)).to eq('https://example.invalid/items')
    end
  end

  it 'honors enabled false when updating an enabled proxy listener' do
    allow(browser).to receive(:get).and_return([{ id: '0', enabled: true, port: 8080, bindAddress: '127.0.0.1' }].to_json)
    expect(browser).to receive(:put) do |_url, body, _headers|
      expect(JSON.parse(body)['enabled']).to be(false)
      body
    end
    described_class.update_proxy_listener(burp_obj: burp, enabled: false)
  end
end
