# frozen_string_literal: true

require 'spec_helper'

describe PWN::Reports::XML do
  it 'should display information for authors' do
    authors_response = PWN::Reports::XML
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Reports::XML
    expect(help_response).to respond_to :help
  end

  it 'should respond to generate' do
    expect(PWN::Reports::XML).to respond_to :generate
  end
end
