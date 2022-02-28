# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::BasicAuth do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::BasicAuth
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::BasicAuth
    expect(help_response).to respond_to :help
  end
end
