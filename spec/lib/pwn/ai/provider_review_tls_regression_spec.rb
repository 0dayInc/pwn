# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'net/http'
require 'stringio'

{
  PWN::AI::OpenAI => %i[openai open_ai_rest_call],
  PWN::AI::Gemini => %i[gemini gemini_rest_call],
  PWN::AI::Grok => %i[grok grok_rest_call],
  PWN::AI::Anthropic => %i[anthropic anthropic_rest_call],
  PWN::AI::Ollama => %i[ollama ollama_rest_call],
  PWN::AI::OpenWebUI => %i[openwebui openwebui_rest_call]
}.each do |provider, (key, helper)|
  RSpec.describe provider, 'PR-SEC-01 peer verification' do
    before do
      stub_const('PWN::Env', { ai: { key => { model: 'fixture', key: 'fixture-key', base_uri: 'https://example.invalid' } } })
      allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
      @modes = []
      allow_any_instance_of(Net::HTTP).to receive(:start) do |http, &block|
        @modes << http.verify_mode
        block.call(http)
      end
      allow_any_instance_of(Net::HTTP).to receive(:request) do |_http, _request, _body = nil, &block|
        body = '{"models":[],"data":[],"message":{"role":"assistant","content":"ok"},"done":true}'
        io = Net::BufferedIO.new(StringIO.new("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\n\r\n#{body}"))
        response = Net::HTTPResponse.read_new(io)
        response.reading_body(io, true) { block&.call(response) }
        response
      end
    end

    it 'authenticates HTTPS model-list peers through installed RestClient' do
      described_class.get_models
      expect(@modes).not_to be_empty
      expect(@modes).to all(eq(OpenSSL::SSL::VERIFY_PEER))
    end

    [{}, { multipart: true, fixture: 'value' }, { stream: true }].each do |body|
      next if key == :gemini && body.key?(:multipart)

      it "authenticates HTTPS POST peers for #{body.keys.inspect}" do
        described_class.send(helper, rest_call: 'fixture', http_method: :post, http_body: body, timeout: 1)
        expect(@modes).to eq([OpenSSL::SSL::VERIFY_PEER])
      end
    end

    it 'propagates certificate rejection without an insecure fallback' do
      error = OpenSSL::SSL::SSLError.new('fixture certificate verify failed')
      allow_any_instance_of(Net::HTTP).to receive(:start) do |http|
        @modes << http.verify_mode
        raise error
      end
      expect { described_class.get_models }.to raise_error(RestClient::SSLCertificateNotVerified, /fixture certificate verify failed/) do |raised|
        expect(raised.cause).to equal(error)
      end
      expect(@modes).not_to be_empty
      expect(@modes).to all(eq(OpenSSL::SSL::VERIFY_PEER))
    end
  end
end
