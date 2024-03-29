# frozen_string_literal: true

require 'spec_helper'

describe PWN::Banner::ForkBomb do
  it 'should cointain a method for banner retrieval' do
    get_response = PWN::Banner::ForkBomb
    expect(get_response).to respond_to :get
  end

  it 'should display information for authors' do
    authors_response = PWN::Banner::ForkBomb
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Banner::ForkBomb
    expect(help_response).to respond_to :help
  end
end
