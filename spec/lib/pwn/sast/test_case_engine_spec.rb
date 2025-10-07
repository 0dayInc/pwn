# frozen_string_literal: true

require 'spec_helper'

describe PWN::SAST::TestCaseEngine do
  it 'execute method should exist' do
    execute_response = PWN::SAST::TestCaseEngine
    expect(execute_response).to respond_to :execute
  end

  it 'should display information for authors' do
    authors_response = PWN::SAST::TestCaseEngine
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SAST::TestCaseEngine
    expect(help_response).to respond_to :help
  end
end
