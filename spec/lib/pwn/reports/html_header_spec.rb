# frozen_string_literal: true

require 'spec_helper'

describe PWN::Reports::HTMLHeader do
  it 'should display information for authors' do
    authors_response = PWN::Reports::HTMLHeader
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Reports::HTMLHeader
    expect(help_response).to respond_to :help
  end
end
