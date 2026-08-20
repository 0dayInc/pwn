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

  it 'does not expose get_plan_usage' do
    expect(described_class).not_to respond_to(:get_plan_usage)
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

  it 'grok_rest_call stops the spinner via TTYSpinner (joins worker after response)' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to include('PWN::Plugins::TTYSpinner.start')
    expect(src).to include('PWN::Plugins::TTYSpinner.stop(spin: spin)')
    expect(src).not_to match(/spin\.stop if spinner/)
  end

  it 'does not nil+ on 429 without Retry-After and does not retry 429 forever' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).not_to match(/headers\[:retry_after\]&.to_i\s*\|\|=/)
    expect(src).to match(/HttpRetry\.retry_after_s|headers\[:retry_after\]\.to_i/)
    expect(src).to match(/HttpRetry\.max_attempts|max_attempts/)
  end

  it 'defaults chat REST timeout to 180s and retries ReadTimeout up to 5 times' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/HttpRetry|timeout \|\|= 180/)
    expect(src).not_to match(/timeout \|\|= 900/)
    expect(src).to match(/HttpRetry\.max_attempts|max_attempts/)
    inner = src[/retry_count = 0.*?rescue RestClient::Exceptions::Timeout/m]
    expect(inner).to include('TooManyRequests')
    expect(inner).to include('Exceptions::Timeout')
  end

  it 'tees grok timeout/429 warnings into the debug request log' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/HttpRetry\.report_event|Log\.progress/)
  end
end
