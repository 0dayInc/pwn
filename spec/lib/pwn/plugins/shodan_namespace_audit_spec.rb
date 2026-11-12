# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Shodan, 'optional search parameters regression' do
  it 'allows saved queries without optional sorting parameters' do
    expect(described_class).to receive(:shodan_rest_call).with(hash_including(rest_call: 'shodan/query', params: { key: 'fixture-token' })).and_return(matches: [])
    expect(described_class.saved_search_queries(api_key: 'fixture-token')).to eq(matches: [])
  end
end
