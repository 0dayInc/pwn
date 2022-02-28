# frozen_string_literal: true

require 'spec_helper'

describe PWN::Reports do
  it 'should return data for help method' do
    help_response = PWN::Reports.help
    expect(help_response).not_to be_nil
  end
end
