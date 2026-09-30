# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Anthropic do
  it 'should display information for authors' do
    authors_response = PWN::AI::Anthropic
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Anthropic
    expect(help_response).to respond_to :help
  end

  describe 'chat response handling (bug fix for empty response)' do
    before do
      allow(PWN::Env).to receive(:[]).with(:ai).and_return(
        anthropic: {
          key: 'test-key',
          model: 'claude-3-haiku-20240307',
          temp: 0.7,
          system_role_content: 'You are a helpful assistant.',
          base_uri: 'https://api.anthropic.com/v1',
          max_prompt_length: 200_000
        }
      )
    end

    it 'returns proper assistant content in choices for successful response' do
      allow(PWN::AI::Anthropic).to receive(:anthropic_rest_call).and_return(
        '{"id":"msg_test123","type":"message","role":"assistant","content":[{"type":"text","text":"This is a test response from Anthropic."}],"model":"claude-3-haiku-20240307","stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":10}}'
      )
      response = PWN::AI::Anthropic.chat(request: 'Test request')
      expect(response).to be_a(Hash)
      expect(response[:choices]).to be_an(Array)
      expect(response[:choices].last[:role]).to eq('assistant')
      expect(response[:choices].last[:content]).to eq('This is a test response from Anthropic.')
      expect(response[:choices].last[:content]).not_to be_empty
    end

    it 'raises error on API error response instead of returning empty content' do
      allow(PWN::AI::Anthropic).to receive(:anthropic_rest_call).and_return(
        '{"type":"error","error":{"type":"invalid_request_error","message":"test error - no content"}}'
      )
      expect { PWN::AI::Anthropic.chat(request: 'Test') }.to raise_error(/Anthropic Error|invalid_request_error/)
    end
  end

  it 'does not expose get_plan_usage' do
    expect(described_class).not_to respond_to(:get_plan_usage)
  end

  describe 'Hermes prompt-cache breakpoint' do
    it 'chat_with_tools source emits PromptCache.anthropic_system_blocks' do
      src = File.read(described_class.method(:chat_with_tools).source_location.first)
      expect(src).to include('PromptCache.anthropic_system_blocks')
      expect(src).to include('PromptCache.enabled?')
    end
  end

  it 'drops root combinators from Anthropic input_schema without mutating registry schemas' do
    allow(PWN::Env).to receive(:[]).with(:ai).and_return(
      anthropic: { key: 'test-key', model: 'claude-test', temp: 1, max_tokens: 100 }
    )
    allow(PWN::AI::Agent::PromptCache).to receive(:enabled?).and_return(false) if defined?(PWN::AI::Agent::PromptCache)
    tools = PWN::AI::Agent::Registry.definitions(core_only: true)
    artifact = tools.find { |tool| tool.dig(:function, :name) == 'artifact_read' }
    original = artifact[:function][:parameters]
    nested = {
      type: 'object',
      properties: {
        item: { anyOf: [{ type: 'string' }, { type: 'object', properties: { handle: { type: 'string' } } }] }
      }
    }
    union = {
      'anyOf' => [
        { 'type' => 'object', 'properties' => { 'handle' => { 'type' => 'string' } }, 'required' => ['handle'] },
        { 'type' => 'object', 'properties' => { 'path' => { 'type' => 'string' } }, 'required' => ['path'] }
      ]
    }
    sent = tools + [
      { type: 'function', function: { name: 'nested_union', description: 'keep nested', parameters: nested } },
      { type: 'function', function: { name: 'root_union', description: 'flatten', parameters: union } }
    ]
    captured = nil
    allow(described_class).to receive(:anthropic_rest_call) do |opts|
      captured = opts[:http_body]
      '{"id":"msg_schema","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}'
    end

    described_class.chat_with_tools(messages: [{ role: 'user', content: 'hello' }], tools: sent, model: 'claude-test')

    expect(original).to have_key(:anyOf)
    wire = captured[:tools]
    expect(wire.map { |tool| tool[:name] }[10]).to eq('artifact_read')
    wire.each do |tool|
      schema = tool[:input_schema]
      expect(schema.keys.map(&:to_s)).not_to include('anyOf', 'oneOf', 'allOf')
    end
    read_schema = wire[10][:input_schema]
    expect(read_schema[:properties].keys.map(&:to_s)).to include('handle', 'path', 'ref')
    expect(read_schema[:description]).to include('handle', 'path', 'ref')
    expect(wire.find { |tool| tool[:name] == 'nested_union' }[:input_schema][:properties][:item]).to have_key(:anyOf)
    flat = wire.find { |tool| tool[:name] == 'root_union' }[:input_schema]
    expect(flat[:properties].keys.map(&:to_s)).to include('handle', 'path')
    expect(flat[:description]).to include('handle', 'path')
  end

  it 'does not force tool use on Anthropic models that reject tool_choice any and tool' do
    allow(PWN::Env).to receive(:[]).with(:ai).and_return(
      anthropic: { key: 'test-key', model: 'claude-mythos-5', temp: 1, max_tokens: 100 }
    )
    allow(PWN::AI::Agent::PromptCache).to receive(:enabled?).and_return(false) if defined?(PWN::AI::Agent::PromptCache)
    captured = nil
    allow(described_class).to receive(:anthropic_rest_call) do |opts|
      captured = opts[:http_body]
      '{"id":"msg_choice","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}'
    end
    tools = [{ type: 'function', function: { name: 'memory_recall', description: 'recall', parameters: { type: 'object', properties: {} } } }]
    messages = [{ role: 'user', content: 'hello' }]

    described_class.chat_with_tools(messages: messages, tools: tools, model: 'claude-mythos-5', tool_choice: 'required')
    expect(captured[:tool_choice]).to eq(type: 'any')

    %w[claude-mythos-5-1 claude-fable-5-1 claude-opus-5-5 claude-sonnet-5-5].each do |model|
      described_class.chat_with_tools(messages: messages, tools: tools, model: model, tool_choice: 'required')
      expect(captured[:tool_choice]).to eq(type: 'auto'), model
      described_class.chat_with_tools(messages: messages, tools: tools, model: model, tool_choice: { type: 'function', function: { name: 'memory_recall' } })
      expect(captured[:tool_choice]).to eq(type: 'auto'), model
    end

    described_class.chat_with_tools(messages: messages, tools: tools, model: 'claude-mythos-5-1', tool_choice: 'none')
    expect(captured[:tool_choice]).to eq(type: 'none')
  end
end
