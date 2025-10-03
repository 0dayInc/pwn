# frozen_string_literal: true

require 'spec_helper'

describe PWN::Config do
  it 'should return data for refresh method' do
    config_response = PWN::Config.refresh
    expect(config_response).not_to be_nil
  end
end
