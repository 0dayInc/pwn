# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Android do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Android
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Android
    expect(help_response).to respond_to :help
  end
end
