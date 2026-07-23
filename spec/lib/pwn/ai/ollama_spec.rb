# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Ollama do
  it 'should display information for authors' do
    authors_response = PWN::AI::Ollama
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Ollama
    expect(help_response).to respond_to :help
  end

  it 'omits format:json when tools present unless engine[:format] set (0.2)' do
    engine = { model: 'test', num_ctx: 2048, keep_alive: '1m', temp: 0.1, tool_temp: 0.1 }
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:ai).and_return({ ollama: engine, active: 'ollama' })
    captured = nil
    allow(described_class).to receive(:ollama_rest_call) do |**kwargs|
      captured = kwargs[:http_body]
      '{"message":{"role":"assistant","content":"ok","tool_calls":[]}}'
    end
    described_class.chat_with_tools(
      messages: [{ role: 'user', content: 'hi' }],
      tools: [{ type: 'function', function: { name: 'shell', parameters: { type: 'object', properties: {} } } }],
      model: 'test'
    )
    expect(captured).to be_a(Hash)
    expect(captured[:tools]).not_to be_nil
    expect(captured.key?(:format)).to be false
  end

  it 'requests stream: true from chat_with_tools and chat' do
    engine = {
      model: 'test',
      num_ctx: 2048,
      keep_alive: '1m',
      temp: 0.1,
      tool_temp: 0.1,
      system_role_content: 'sys'
    }
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:ai).and_return({ ollama: engine, active: 'ollama' })

    captured = nil
    allow(described_class).to receive(:ollama_rest_call) do |**kwargs|
      captured = kwargs[:http_body]
      '{"message":{"role":"assistant","content":"ok","tool_calls":[]},"done":true}'
    end
    described_class.chat_with_tools(
      messages: [{ role: 'user', content: 'hi' }],
      model: 'test'
    )
    expect(captured[:stream]).to be true
    expect(captured.dig(:options, :num_predict)).to eq(4096)
    expect(captured.dig(:options, :num_ctx)).to eq(2048)

    captured_chat = nil
    allow(described_class).to receive(:ollama_rest_call) do |**kwargs|
      captured_chat = kwargs[:http_body]
      '{"choices":[{"message":{"role":"assistant","content":"hi"}}]}'
    end
    described_class.chat(request: 'hello', model: 'test')
    expect(captured_chat[:stream]).to be true
  end

  it 'assembles native /api/chat NDJSON stream into a single message' do
    body = [
      { model: 'm', message: { role: 'assistant', content: 'Hel' }, done: false }.to_json,
      { model: 'm', message: { role: 'assistant', content: 'lo!' }, done: false }.to_json,
      {
        model: 'm',
        message: { role: 'assistant', content: '' },
        done: true,
        done_reason: 'stop',
        eval_count: 2
      }.to_json
    ].join("\n")

    out = described_class.send(
      :assemble_ollama_stream,
      body: body,
      rest_call: 'ollama/api/chat'
    )
    parsed = JSON.parse(out, symbolize_names: true)
    expect(parsed.dig(:message, :content)).to eq('Hello!')
    expect(parsed[:done]).to be true
    expect(parsed[:eval_count]).to eq(2)
  end

  it 'assembles native tool_calls across NDJSON chunks' do
    body = [
      {
        message: {
          role: 'assistant',
          content: '',
          tool_calls: [{ function: { name: 'shell', arguments: { command: 'id' } } }]
        },
        done: false
      }.to_json,
      {
        message: { role: 'assistant', content: '' },
        done: true,
        done_reason: 'stop'
      }.to_json
    ].join("\n")

    out = described_class.send(
      :assemble_ollama_stream,
      body: body,
      rest_call: 'ollama/api/chat'
    )
    parsed = JSON.parse(out, symbolize_names: true)
    tc = parsed.dig(:message, :tool_calls, 0)
    expect(tc.dig(:function, :name)).to eq('shell')
    expect(tc.dig(:function, :arguments, :command)).to eq('id')
  end

  it 'assembles OpenAI-compat SSE stream into chat.completion shape' do
    chunks = [
      { id: 'x', model: 'm', choices: [{ delta: { role: 'assistant', content: 'Hi' } }] },
      { choices: [{ delta: { content: ' there' } }] },
      { choices: [{ delta: {}, finish_reason: 'stop' }], usage: { total_tokens: 3 } }
    ]
    sse_lines = chunks.map { |c| "data: #{JSON.generate(c)}" }
    sse_lines << 'data: [DONE]'
    body = "#{sse_lines.join("\n")}\n"

    out = described_class.send(
      :assemble_ollama_stream,
      body: body,
      rest_call: 'ollama/v1/chat/completions'
    )
    parsed = JSON.parse(out, symbolize_names: true)
    expect(parsed[:object]).to eq('chat.completion')
    expect(parsed.dig(:choices, 0, :message, :content)).to eq('Hi there')
    expect(parsed.dig(:choices, 0, :finish_reason)).to eq('stop')
    expect(parsed.dig(:usage, :total_tokens)).to eq(3)
  end

  it 'assembles OpenAI-compat streamed tool_calls by index' do
    chunks = [
      {
        choices: [{
          delta: {
            role: 'assistant',
            tool_calls: [{
              index: 0,
              id: 'call_1',
              type: 'function',
              function: { name: 'shell', arguments: '' }
            }]
          }
        }]
      },
      {
        choices: [{
          delta: {
            tool_calls: [{ index: 0, function: { arguments: '{"c' } }]
          }
        }]
      },
      {
        choices: [{
          delta: {
            tool_calls: [{ index: 0, function: { arguments: 'md":"id"}' } }]
          },
          finish_reason: 'tool_calls'
        }]
      }
    ]
    sse_lines = chunks.map { |c| "data: #{JSON.generate(c)}" }
    sse_lines << 'data: [DONE]'
    body = "#{sse_lines.join("\n")}\n"

    out = described_class.send(
      :assemble_ollama_stream,
      body: body,
      rest_call: 'ollama/v1/chat/completions'
    )
    parsed = JSON.parse(out, symbolize_names: true)
    tc = parsed.dig(:choices, 0, :message, :tool_calls, 0)
    expect(tc[:id]).to eq('call_1')
    expect(tc.dig(:function, :name)).to eq('shell')
    expect(tc.dig(:function, :arguments)).to eq('{"cmd":"id"}')
  end

  it 'promotes thinking to content when native stream has empty content and no tool_calls' do
    body = [
      {
        message: { role: 'assistant', content: '', thinking: 'Reasoning... Final Answer: Hello there' },
        done: false
      }.to_json,
      {
        message: { role: 'assistant', content: '', thinking: '' },
        done: true,
        done_reason: 'stop'
      }.to_json
    ].join("\n")

    out = described_class.send(
      :assemble_ollama_stream,
      body: body,
      rest_call: 'ollama/api/chat'
    )
    parsed = JSON.parse(out, symbolize_names: true)
    expect(parsed.dig(:message, :content)).to eq('Hello there')
    expect(parsed.dig(:message, :thinking)).to include('Reasoning')
  end

  it 'does not promote thinking when tool_calls are present' do
    body = [
      {
        message: {
          role: 'assistant',
          content: '',
          thinking: 'I will call shell',
          tool_calls: [{ function: { name: 'shell', arguments: { command: 'id' } } }]
        },
        done: true,
        done_reason: 'stop'
      }.to_json
    ].join("\n")

    out = described_class.send(
      :assemble_ollama_stream,
      body: body,
      rest_call: 'ollama/api/chat'
    )
    parsed = JSON.parse(out, symbolize_names: true)
    expect(parsed.dig(:message, :content)).to eq('')
    expect(parsed.dig(:message, :tool_calls, 0, :function, :name)).to eq('shell')
  end

  it 'raises a clear error on non-2xx stream instead of NoMethodError/nil' do
    engine = { model: 'test', base_uri: 'http://127.0.0.1:9', key: 'k', num_ctx: 2048, keep_alive: '1m', temp: 0.1 }
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:ai).and_return({ ollama: engine, active: 'ollama' })

    # Simulate the stream path's error object without needing a live HTTP stack:
    # ollama_rest_call must raise (not return nil) so chat_with_tools cannot
    # collapse into a silent empty agent reply.
    allow(described_class).to receive(:ollama_rest_call).and_return(nil)

    expect do
      described_class.chat_with_tools(
        messages: [{ role: 'user', content: 'hi' }],
        model: 'missing',
        tools: []
      )
    end.to raise_error(RuntimeError, /empty response|ERROR/)
  end

  it 'marks empty stream payloads instead of returning bare {}' do
    out = described_class.send(
      :assemble_ollama_stream,
      body: '',
      rest_call: 'ollama/api/chat'
    )
    parsed = JSON.parse(out, symbolize_names: true)
    expect(parsed[:done_reason]).to eq('error')
    expect(parsed.dig(:message, :error)).to eq('empty_stream_payloads')
  end
end
