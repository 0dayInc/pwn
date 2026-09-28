# frozen_string_literal: true

require 'spec_helper'

describe PWN::Blockchain do
  it 'should return data for help method' do
    help_response = PWN::Blockchain.help
    expect(help_response).not_to be_nil
  end

  it 'lists the read-only intelligence modules and their detailed help entry points' do
    result = nil
    expect { result = described_class.help }.to output(/BTC.help.*ETH.help/m).to_stdout
    expect(result).to include(:BTC, :ETH)
  end
end
