# frozen_string_literal: true

require 'spec_helper'

describe PWN::SAST::Version do
  it 'scan method should exist' do
    scan_response = PWN::SAST::Version
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for security_requirements' do
    security_requirements_response = PWN::SAST::Version
    expect(security_requirements_response).to respond_to :security_requirements
  end

  it 'should display information for authors' do
    authors_response = PWN::SAST::Version
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SAST::Version
    expect(help_response).to respond_to :help
  end
end
