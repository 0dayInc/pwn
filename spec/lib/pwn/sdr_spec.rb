# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR do
  it 'formats an all-zero padded frequency as zero rather than an empty string' do
    expect(described_class.hz_to_s(freq: '000000')).to eq('0')
    expect(described_class.hz_to_s(freq: '0002450000000')).to eq('2.450.000.000')
  end

  it 'should return data for help method' do
    help_response = PWN::SDR.help
    expect(help_response).not_to be_nil
  end
end
