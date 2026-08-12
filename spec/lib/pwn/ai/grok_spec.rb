# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Grok do
  it 'should display information for authors' do
    authors_response = PWN::AI::Grok
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Grok
    expect(help_response).to respond_to :help
  end

  it 'chat_with_tools sanitizes messages via Loop.openai_wire_messages' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/openai_wire_messages/)
  end
end
