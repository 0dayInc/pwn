# frozen_string_literal: true

require 'spec_helper'

describe PWN::WWW::HackerOne do
  it 'should display information for authors' do
    authors_response = PWN::WWW::HackerOne
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::WWW::HackerOne
    expect(help_response).to respond_to :help
  end
end
