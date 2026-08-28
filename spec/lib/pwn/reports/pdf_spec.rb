# frozen_string_literal: true

require 'spec_helper'

describe PWN::Reports::PDF do
  it 'should display information for authors' do
    authors_response = PWN::Reports::PDF
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Reports::PDF
    expect(help_response).to respond_to :help
  end

  it 'should respond to generate' do
    expect(PWN::Reports::PDF).to respond_to :generate
  end
end
