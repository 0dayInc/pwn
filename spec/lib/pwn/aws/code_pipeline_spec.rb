# frozen_string_literal: true

require 'spec_helper'

describe PWN::AWS::CodePipeline do
  it 'should display information for authors' do
    authors_response = PWN::AWS::CodePipeline
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AWS::CodePipeline
    expect(help_response).to respond_to :help
  end
end
