# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::RedTeam::TestCaseEngine do
  it 'execute method should exist' do
    execute_response = PWN::AI::RedTeam::TestCaseEngine
    expect(execute_response).to respond_to :execute
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::RedTeam::TestCaseEngine
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::RedTeam::TestCaseEngine
    expect(help_response).to respond_to :help
  end
end
