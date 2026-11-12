# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Config recursive redaction' do
  it 'rejects cyclic configuration safely without exposing secret contents' do
    config = { password: 'synthetic fixture only' }
    config[:cycle] = config
    expect do
      PWN::Config.redact_sensitive_artifacts(config: config)
    end.to raise_error(JSON::NestingError, /configuration nesting limit/)
    expect(config[:cycle]).to equal(config)
    expect(config[:password]).to eq('synthetic fixture only')
  end

  it 'redacts both occurrences of shared acyclic branches without changing the caller' do
    shared = { password: 'synthetic fixture only' }.freeze
    config = { first: shared, second: [shared].freeze }.freeze
    result = PWN::Config.redact_sensitive_artifacts(config: config)
    expect(result[:first][:password]).to include('REDACTED')
    expect(result[:second].first).to eq(result[:first])
    expect(shared[:password]).to eq('synthetic fixture only')
  end
end
