# frozen_string_literal: true

require 'spec_helper'

describe PWN::AWS do
  it 'should return data for help method' do
    help_response = PWN::AWS.help
    expect(help_response).not_to be_nil
  end
end
