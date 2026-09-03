# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Packet do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Packet
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Packet
    expect(help_response).to respond_to :help
  end

  it 'flags connect-scan results as degraded' do
    row = described_class.tcp_connect_scan(hosts: ['127.0.0.1'], ports: [1], timeout: 0.05)
    expect(row[:degraded]).to eq(true)
    expect(row[:results]).to be_an(Array)
  end
end
