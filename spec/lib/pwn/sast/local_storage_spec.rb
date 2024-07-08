# frozen_string_literal: true

require 'spec_helper'

describe PWN::SAST::LocalStorage do
  it 'scan method should exist' do
    scan_response = PWN::SAST::LocalStorage
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for security_references' do
    security_references_response = PWN::SAST::LocalStorage
    expect(security_references_response).to respond_to :security_references
  end

  it 'should display information for authors' do
    authors_response = PWN::SAST::LocalStorage
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SAST::LocalStorage
    expect(help_response).to respond_to :help
  end
end
