# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::RedTeam::Overreliance do
  it 'scan method should exist' do
    scan_response = PWN::AI::RedTeam::Overreliance
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for security_references' do
    security_references_response = PWN::AI::RedTeam::Overreliance
    expect(security_references_response).to respond_to :security_references
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::RedTeam::Overreliance
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::RedTeam::Overreliance
    expect(help_response).to respond_to :help
  end
end
