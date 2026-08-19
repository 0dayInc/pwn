# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Gemini do
  it 'should display information for authors' do
    authors_response = PWN::AI::Gemini
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Gemini
    expect(help_response).to respond_to :help
  end

  it 'does not expose get_plan_usage' do
    expect(described_class).not_to respond_to(:get_plan_usage)
  end

  it 'chat_with_tools honors PromptCache when prompt_cache is on' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to include('PromptCache.gemini_system_instruction')
    expect(src).to include('enabled?(engine: :gemini)')
  end
end
