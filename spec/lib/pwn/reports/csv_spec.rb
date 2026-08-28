# frozen_string_literal: true

require 'spec_helper'

describe PWN::Reports::CSV do
  it 'should display information for authors' do
    authors_response = PWN::Reports::CSV
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Reports::CSV
    expect(help_response).to respond_to :help
  end

  it 'should respond to generate' do
    expect(PWN::Reports::CSV).to respond_to :generate
  end
end
