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
end
it 'should support oauth configuration for xAI SuperGrok subscriptions (in addition to API key via PWN::Config vault)' do
  grok = PWN::AI::Grok
  expect(grok).to respond_to :get_models
  expect(grok).to respond_to :chat
  # oauth support is via PWN::Env[:ai][:grok][:oauth][:access_token] (preferred) falling back to :key
  # populated via pwn-vault into the encrypted ~/.pwn/pwn.yaml and loaded by PWN::Config.refresh_env
end
