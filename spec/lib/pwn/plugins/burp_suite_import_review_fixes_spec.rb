# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'tmpdir'

RSpec.describe PWN::Plugins::BurpSuite, 'review import delivery regressions' do
  def response(body, code = 200)
    RestClient::Response.create(body, Net::HTTPResponse.new('1.1', code.to_s, 'Fixture'),
                                RestClient::Request.new(method: :post, url: 'http://burp.invalid/sitemap'))
  end

  def with_spec
    Dir.mktmpdir('burp-import-review') do |dir|
      path = File.join(dir, 'api.json')
      paths = %w[/one /two /three].to_h { |endpoint| [endpoint, { get: { responses: { '200' => { description: 'OK' } } } }] }
      File.write(path, JSON.generate(openapi: '3.0.3', servers: [{ url: 'https://example.invalid' }], paths: paths))
      yield path, { rest_browser: RestClient, mitm_rest_api: 'burp.invalid' }
    end
  end

  [1, 2].each do |failure_at|
    it "PSR-L07 propagates insertion failure at entry #{failure_at} without returning generated entries as successful" do
      with_spec do |path, burp|
        calls = []
        error = RestClient::BadRequest.new(response('{"error":"rejected"}', 400))
        allow(RestClient::Request).to receive(:execute) do |request|
          expect(request[:url]).to eq('http://burp.invalid/sitemap')
          expect(request[:method]).to eq(:post)
          calls << JSON.parse(request[:payload], symbolize_names: true)
          raise error if calls.length == failure_at

          response('{}')
        end
        expect do
          described_class.import_openapi_to_sitemap(burp_obj: burp, openapi_spec: path)
        end.to(raise_error { |raised| expect(raised).to equal(error) })
        expect(calls.length).to eq(failure_at)
        expect(calls.map { |entry| Base64.strict_decode64(entry[:request]).lines.first.strip })
          .to eq(['GET /one HTTP/1.1', 'GET /two HTTP/1.1'].first(failure_at))
      end
    end
  end

  it 'preserves the successful array return and actual sitemap readback without changing cwd' do
    with_spec do |path, burp|
      entries = []
      allow(RestClient::Request).to receive(:execute) do |request|
        expect(request[:url]).to eq('http://burp.invalid/sitemap')
        entries << JSON.parse(request[:payload], symbolize_names: true)
        response('{}')
      end
      allow(RestClient).to receive(:get).with('http://burp.invalid/sitemap?limit=200&offset=0&highlight=NONE', anything) { JSON.generate(entries) }
      cwd = Dir.pwd
      result = described_class.import_openapi_to_sitemap(burp_obj: burp, openapi_spec: path)
      expect(result).to eq(entries)
      expect(result.length).to eq(3)
      expect(described_class.get_sitemap(burp_obj: burp)).to eq(result)
      expect(Dir.pwd).to eq(cwd)
    end
  end
end
