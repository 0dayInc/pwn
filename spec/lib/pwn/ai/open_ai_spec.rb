# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::OpenAI do
  it 'should display information for authors' do
    authors_response = PWN::AI::OpenAI
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::OpenAI
    expect(help_response).to respond_to :help
  end

  it 'chat_with_tools sanitizes messages via Loop.openai_wire_messages' do
    src = File.read(described_class.method(:chat_with_tools).source_location.first)
    expect(src).to match(/openai_wire_messages/)
  end

  it 'exposes get_plan_usage for the PS1 subscription suffix' do
    expect(described_class).to respond_to(:get_plan_usage)
  end
  it 'computes a percentage from dashboard billing used vs hard limit' do
    allow(described_class).to receive(:plan_usage_credentials?).and_return(true)
    allow(described_class).to receive(:open_ai_rest_call) do |**kwargs|
      case kwargs[:rest_call]
      when 'dashboard/billing/subscription'
        '{"hard_limit_usd":100.0}'
      when 'dashboard/billing/usage'
        '{"total_usage":1900}'
      else
        '{"error":"no"}'
      end
    end
    usage = described_class.get_plan_usage
    expect(usage[:available]).to be true
    expect(usage[:percent]).to eq(19)
  end

  it 'returns unavailable when credentials are missing' do
    allow(described_class).to receive(:plan_usage_credentials?).and_return(false)
    expect(described_class.get_plan_usage[:available]).to be false
  end

  it 'open_ai_rest_call swallows ReadTimeout quietly without ERROR: print' do
    src = File.read(described_class.method(:chat).source_location.first)
    expect(src).to match(/RestClient::Exceptions::Timeout/)
    expect(src).to match(/quiet: opts\[:quiet\]/)
    timeout_rescue = src[/rescue RestClient::Exceptions::Timeout.*?rescue RestClient::ExceptionWithResponse/m]
    expect(timeout_rescue).not_to match(/puts "ERROR:/)
  end
end
