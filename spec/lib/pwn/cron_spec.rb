# frozen_string_literal: true

require 'spec_helper'

describe PWN::Cron do
  it 'should display information for authors' do
    authors_response = PWN::Cron
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Cron
    expect(help_response).to respond_to :help
  end
end
