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
end
