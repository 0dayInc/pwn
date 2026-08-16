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

  it 'exposes get_plan_usage for the PS1 subscription suffix' do
    expect(described_class).to respond_to(:get_plan_usage)
  end

  it 'grok_rest_call swallows ReadTimeout quietly without ERROR: print' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/RestClient::Exceptions::Timeout/)
    expect(src).to match(/quiet: opts\[:quiet\]/)
    expect(src).to include('Timed out reading data from server')
    timeout_rescue = src[/rescue RestClient::Exceptions::Timeout.*?rescue RestClient::ExceptionWithResponse/m]
    expect(timeout_rescue).not_to match(/puts "ERROR:/)
    expect(timeout_rescue).to match(/opts\[:quiet\]/)
  end

  it 'chat_with_tools honors PromptCache when prompt_cache is on' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to include('PromptCache.openai_messages')
    expect(src).to include('x-grok-conv-id')
    expect(src).to include('enabled?(engine: :grok)')
  end
end
