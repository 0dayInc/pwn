# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Sock do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Sock
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Sock
    expect(help_response).to respond_to :help
  end

  it 'protocol :raw demands CAP_NET_RAW' do
    allow(PWN::Plugins::PreflightChecker).to receive(:cap_net_raw?).and_return(false)
    expect do
      described_class.connect(target: '127.0.0.1', port: 9, protocol: :raw)
    end.to raise_error(PWN::Plugins::PreflightChecker::MissingCapability)
  end
end
