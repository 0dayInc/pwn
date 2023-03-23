# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::PWNLogger do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::PWNLogger
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::PWNLogger
    expect(help_response).to respond_to :help
  end
end
