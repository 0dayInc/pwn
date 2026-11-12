# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::Plugins::NessusCloud, 'credential defaults regression' do
  it 'selects the documented Host SSH defaults when no filters are passed' do
    allow(described_class).to receive(:sleep)
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    response = double('response', body: { credentials: [{ category: 'Host', types: [{ name: 'SSH', id: 'ssh' }] }] }.to_json)
    allow(RestClient::Request).to receive(:execute).and_return(response)
    expect(described_class.get_credential_types(nessus_obj: {})).to eq(name: 'SSH', id: 'ssh')
  end
end
