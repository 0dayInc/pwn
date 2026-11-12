# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'net/http'
require 'stringio'

RSpec.shared_context 'provider review synthetic stream transport' do |key|
  before do
    stub_const('PWN::Env', { ai: { key => { model: 'fixture', key: 'fixture-key', base_uri: 'https://example.invalid', system_role_content: 'FIXTURE SYSTEM' } } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    described_class.instance_variable_set(:@strict_system_cache, nil)
    @show = JSON.generate(template: "raise_exception('System message must be at the beginning')")
    @stream = "data: #{JSON.generate(choices: [{ delta: { content: 'Fixture answer' }, finish_reason: 'stop' }])}\n\ndata: [DONE]\n\n"
    @wire = []
    @status = '200'
    allow_any_instance_of(Net::HTTP).to receive(:start) { |http, &block| block.call(http) }
    allow_any_instance_of(Net::HTTP).to receive(:request) do |_http, request, body = nil, &block|
      payload = request.body_stream ? request.body_stream.read : (body || request.body)
      @wire << { path: request.path, body: payload }
      content = request.path.end_with?('/show') ? @show : @stream
      code = request.path.end_with?('/show') ? '200' : @status
      io = Net::BufferedIO.new(StringIO.new("HTTP/1.1 #{code} Fixture\r\nContent-Length: #{content.bytesize}\r\n\r\n#{content}"))
      response = Net::HTTPResponse.read_new(io)
      response.reading_body(io, true) { block&.call(response) }
      response
    end
  end

  after { described_class.instance_variable_set(:@strict_system_cache, nil) }
end

{ PWN::AI::Ollama => :ollama, PWN::AI::OpenWebUI => :openwebui }.each do |provider, key|
  RSpec.describe provider, 'PR-LOG-02 stream framing' do
    include_context 'provider review synthetic stream transport', key

    ["\n", "\r\n", "\r"].each do |newline|
      it "joins multiline SSE data at event boundaries with #{newline.inspect}" do
        @stream = [': heartbeat', '', 'id: fixture', 'event: message', 'retry: 1000',
                   'data: {"choices":', 'data: [{"delta":{"content":"Complete"},"finish_reason":"length"}],',
                   'data: "usage":{"total_tokens":7}}', '', 'data: [DONE]', '', ''].join(newline)
        result = described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1)
        expect(result.dig(:assistant_message, :content)).to eq('Complete')
        expect(result.dig(:choices, 0, :finish_reason)).to eq('length')
        expect(result.dig(:usage, :total_tokens)).to eq(7)
      end
    end

    it 'preserves a multiline SSE error and provider endpoint instead of partial output' do
      @stream = +"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"
      @stream << "data: {\"error\":\ndata: {\"message\":\"fixture backend failed\"}}\n\ndata: [DONE]\n\n"
      expect { described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1) }.to raise_error(RuntimeError, /stream error.*chat.*fixture backend failed/)
    end

    it 'preserves an earlier provider error even when a later SSE event is incomplete' do
      @stream = "data: {\"error\":{\"message\":\"fixture original failure\"}}\n\ndata: {truncated"
      expect { described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1) }.to raise_error(RuntimeError, /stream error.*fixture original failure/)
    end

    it 'honors an SSE error event without a redundant error wrapper' do
      @stream = "event: error\ndata: {\"message\":\"fixture event rejected\"}\n\n"
      expect { described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1) }.to raise_error(RuntimeError, /stream error.*fixture event rejected/)
    end

    ["{\"message\":{\"content\":\"partial\"},\"done\":false}\n{\"error\":\"truncated",
     "{\"message\":{\"content\":\"partial\"},\"done\":false}\n",
     "{\"message\":{\"content\":\"partial\"},\"done\":\"true\"}\n",
     "{\"message\":{\"content\":\"partial\"},\"done\":true}\n{\"done\":false}\n",
     "{\"message\":{\"content\":\"partial\"},\"done\":true}\ngarbage\n",
     "{\"done\":true}\n",
     "{\"message\":\"not an object\",\"done\":true}\n",
     "[]\n"].each_with_index do |stream, index|
      it "rejects malformed or incomplete native stream #{index}" do
        @stream = stream
        expect { described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1) }.to raise_error(RuntimeError, /(?:malformed|incomplete).*stream.*chat/)
      end
    end

    ["data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n",
     "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\ndata: {bad}\n\ndata: [DONE]\n\n",
     "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\ndata: [DONE]"].each_with_index do |stream, index|
      it "rejects malformed or incomplete SSE stream #{index}" do
        @stream = stream
        expect { described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1) }.to raise_error(RuntimeError, /(?:malformed|incomplete).*stream.*chat/)
      end
    end

    it 'keeps the JSON parse exception as the cause of a malformed record' do
      @stream = "{\"message\":{\"content\":\"partial\"},\"done\":false}\n{bad}\n"
      expect { described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1) }.to raise_error(RuntimeError, /malformed.*stream.*chat/) do |error|
        expect(error.cause).to be_a(JSON::ParserError)
      end
    end

    it 'preserves a complete native terminal record without a final newline' do
      @stream = "{\"message\":{\"content\":\"complete\"},\"done\":false}\n{\"done\":true,\"done_reason\":\"length\",\"eval_count\":7}"
      result = described_class.chat_with_tools(messages: [{ role: 'user', content: 'fixture' }], timeout: 1)
      expect(result).to include(done: true, done_reason: 'length', eval_count: 7)
      expect(result.dig(:assistant_message, :content)).to eq('complete')
    end
  end

  RSpec.describe provider, 'PR-LOG-01 strict-template history' do
    include_context 'provider review synthetic stream transport', key

    [false, true].each do |frozen_history|
      [false, true].each do |string_keys|
        it "folds once over three turns without mutating history (frozen=#{frozen_history}, string_keys=#{string_keys})" do
          first = described_class.chat(request: 'First request', timeout: 1)
          first = JSON.parse(JSON.generate(first)) if string_keys
          if frozen_history
            freeze_tree = lambda do |value|
              if value.is_a?(Hash)
                value.each do |k, v|
                  freeze_tree.call(k)
                  freeze_tree.call(v)
                end
              end
              value.each { |v| freeze_tree.call(v) } if value.is_a?(Array)
              value.freeze
            end
            freeze_tree.call(first)
          end
          original = Marshal.dump(first)
          second = described_class.chat(request: 'Second request', response_history: first, timeout: 1)
          expect(Marshal.dump(first)).to eq(original)
          second_original = Marshal.dump(second)
          third = described_class.chat(request: 'Third request', response_history: second, timeout: 1)
          expect(Marshal.dump(second)).to eq(second_original)
          users = third[:choices].select { |row| (row[:role] || row['role']) == 'user' }
          expect(users.map { |row| row[:content] || row['content'] }).to eq(["FIXTURE SYSTEM\n\nFirst request", 'Second request', 'Third request'])
          requests = @wire.reject { |row| row[:path].end_with?('/show') }
          expect(requests.length).to eq(3)
          requests.each do |row|
            messages = JSON.parse(row[:body]).fetch('messages')
            expect(messages.none? { |m| %w[system developer].include?(m['role']) }).to be(true)
            expect(messages.first.fetch('content')).to eq("FIXTURE SYSTEM\n\nFirst request")
          end
        end
      end
    end
  end
end
