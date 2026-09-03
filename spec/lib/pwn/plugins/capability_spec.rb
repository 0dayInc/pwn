# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Capability do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'does not apply setcap without operator_ack' do
    row = described_class.request(cap: 'cap_net_raw', reason: 'packet')
    expect(row[:needs_ack]).to eq(true)
    expect(row[:ok]).to eq(false)
  end
end
