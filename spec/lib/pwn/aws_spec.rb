# frozen_string_literal: true

require 'spec_helper'

describe PWN::AWS do
  it 'does not advertise the removed legacy service wrappers' do
    %i[ElasticTranscoder LambdaPreview OpsWorks OpsWorksCM SMS].each do |name|
      expect(described_class.const_defined?(name, false)).to be(false)
    end
  end

  it 'should return data for help method' do
    help_response = PWN::AWS.help
    expect(help_response).not_to be_nil
  end
end
