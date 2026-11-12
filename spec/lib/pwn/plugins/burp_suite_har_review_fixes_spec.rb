# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'tmpdir'

RSpec.describe PWN::Plugins::BurpSuite, 'review HAR authority regressions' do
  let(:burp) { { rest_browser: RestClient, mitm_rest_api: 'burp.invalid' } }

  def capture_rest(entries)
    allow(RestClient::Request).to receive(:execute) do |request|
      expect(request[:url]).to eq('http://burp.invalid/sitemap')
      expect(request[:method]).to eq(:post)
      entries << JSON.parse(request.fetch(:payload), symbolize_names: true)
      RestClient::Response.create('{}', Net::HTTPResponse.new('1.1', '200', 'OK'),
                                  RestClient::Request.new(method: :post, url: 'http://burp.invalid/sitemap'))
    end
    allow(RestClient).to receive(:get) do |url, _headers|
      expect(url).to match(%r{\Ahttp://burp\.invalid/(sitemap|proxy/history)\?})
      JSON.generate(entries)
    end
  end

  ['https://example.invalid:8443', 'https://[2001:db8::1]:8443', 'https://example.invalid', 'http://example.invalid:8080'].each do |server|
    %i[get_sitemap get_proxy_history].each do |exporter|
      it "PSR-L08 retains #{server} through actual import and #{exporter} HAR export" do
        Dir.mktmpdir('burp-har-roundtrip') do |dir|
          path = File.join(dir, 'api.json')
          File.write(path, JSON.generate(openapi: '3.0.3', servers: [{ url: server }],
                                         paths: { '/probe' => { get: { responses: { '200' => { description: 'OK' } } } } }))
          entries = []
          capture_rest(entries)
          result = described_class.import_openapi_to_sitemap(burp_obj: burp, openapi_spec: path)
          expect(result).to eq(entries)
          expect(result.length).to eq(1)
          exported = described_class.public_send(exporter, burp_obj: burp, return_as: :har)
          expect(exported.dig(:log, :entries, 0, :request, :url)).to eq("#{server}/probe")
          expect(Base64.strict_decode64(entries.first[:request])).to include("Host: #{server.split('://').last}\r\n")
        end
      end
    end
  end

  %i[get_sitemap get_proxy_history].each do |exporter|
    [
      ['example.invalid', 8443, 'example.invalid:8443'],
      ['[2001:db8::1]', 8443, '[2001:db8::1]:8443'],
      ['example.invalid:9443', 8443, 'example.invalid:9443'],
      ['example.invalid', nil, 'example.invalid']
    ].each do |host, service_port, expected|
      it "PSR-L08 preserves captured authority #{host}/#{service_port.inspect} via #{exporter}" do
        entries = [{ request: Base64.strict_encode64("GET /probe?q=1 HTTP/1.1\r\nHost: #{host}\r\n\r\n"),
                     http_service: { host: 'example.invalid', port: service_port, protocol: 'https' } }]
        capture_rest(entries)
        exported = described_class.public_send(exporter, burp_obj: burp, return_as: :har)
        expect(exported.dig(:log, :entries, 0, :request, :url)).to eq("https://#{expected}/probe?q=1")
      end
    end
  end
end
