# frozen_string_literal: true

require 'spec_helper'

describe PWN::SAST::CmdExecutionPython do
  it 'scan method should exist' do
    scan_response = PWN::SAST::CmdExecutionPython
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for security_references' do
    security_references_response = PWN::SAST::CmdExecutionPython
    expect(security_references_response).to respond_to :security_references
  end

  it 'should display information for authors' do
    authors_response = PWN::SAST::CmdExecutionPython
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SAST::CmdExecutionPython
    expect(help_response).to respond_to :help
  end
end
