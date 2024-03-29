# frozen_string_literal: true

require 'spec_helper'

describe PWN::Banner::Radare2 do
  it 'should cointain a method for banner retrieval' do
    get_response = PWN::Banner::Radare2
    expect(get_response).to respond_to :get
  end

  it 'should display information for authors' do
    authors_response = PWN::Banner::Radare2
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Banner::Radare2
    expect(help_response).to respond_to :help
  end
end
