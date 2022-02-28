# frozen_string_literal: true

require 'spec_helper'

describe PWN::AWS::MarketplaceMetering do
  it 'should display information for authors' do
    authors_response = PWN::AWS::MarketplaceMetering
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AWS::MarketplaceMetering
    expect(help_response).to respond_to :help
  end
end
