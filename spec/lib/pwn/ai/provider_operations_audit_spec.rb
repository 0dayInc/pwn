# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'tmpdir'

RSpec.describe PWN::AI::OpenAI, 'file API regressions' do
  before do
    stub_const('PWN::Env', { ai: { openai: { model: 'gpt-4o', key: 'fixture-key' } } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(RestClient::Request).to receive(:execute).and_raise('Unexpected fixture HTTP request')
  end

  describe 'provider failure propagation' do
    [false, true].each do |quiet|
      %i[chat chat_with_tools].each do |operation|
        it "preserves an HTTP rejection for #{operation} (quiet=#{quiet})" do
          response = instance_double(RestClient::Response, code: 400, body: 'fixture invalid schema', to_s: 'fixture invalid schema')
          failure = RestClient::BadRequest.new(response)
          allow(RestClient::Request).to receive(:execute).and_raise(failure)
          args = operation == :chat ? { request: 'fixture' } : { messages: [{ role: 'user', content: 'fixture' }] }
          expect { described_class.public_send(operation, args.merge(quiet: quiet)) }.to raise_error(RestClient::BadRequest) { |error|
            expect(error).to equal(failure)
            expect(error.response).to equal(response)
            expect(error.message).to include('OpenAI', '400', 'fixture invalid schema')
          }
        end
      end
    end

    it 'preserves a transport error in quiet mode instead of calling its absent response method' do
      failure = IOError.new('fixture connection interrupted')
      allow(RestClient::Request).to receive(:execute).and_raise(failure)
      expect { described_class.chat(request: 'fixture', quiet: true) }.to(raise_error { |error| expect(error).to equal(failure) })
    end
  end

  %i[get_file delete_file].each do |operation|
    it "#{operation} resolves the uploaded filename and forwards the timeout" do
      Dir.mktmpdir('provider-file-audit-') do |dir|
        path = File.join(dir, 'training.jsonl')
        File.write(path, "{}\n")
        expect(RestClient::Request).to receive(:execute).with(hash_including(method: :get, url: 'https://api.openai.com/v1/files', timeout: 7)).ordered.and_return(
          { data: [{ filename: 'other.jsonl', id: 'file-other' }, { filename: 'training.jsonl', id: 'file-fixture' }] }.to_json
        )
        expect(RestClient::Request).to receive(:execute).with(hash_including(method: operation == :delete_file ? :delete : :get, url: 'https://api.openai.com/v1/files/file-fixture', timeout: 7)).ordered.and_return(
          { id: 'file-fixture' }.to_json
        )
        expect(described_class.public_send(operation, file: path, timeout: 7)).to eq(id: 'file-fixture')
      end
    end
  end
end
