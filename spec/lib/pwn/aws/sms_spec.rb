# frozen_string_literal: true

require 'spec_helper'

describe PWN::AWS::SMS do
  it 'should display information for authors' do
    authors_response = PWN::AWS::SMS
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AWS::SMS
    expect(help_response).to respond_to :help
  end
end
