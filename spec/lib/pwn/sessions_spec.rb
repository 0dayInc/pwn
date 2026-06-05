# frozen_string_literal: true

require 'spec_helper'

describe PWN::Sessions do
  it 'should display information for authors' do
    authors_response = PWN::Sessions
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Sessions
    expect(help_response).to respond_to :help
  end

  it 'should support create/list/append/load/delete' do
    s = PWN::Sessions.create(title: 'spec test session')
    expect(s[:id]).not_to be_nil
    PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'test input')
    t = PWN::Sessions.load(session_id: s[:id])
    expect(t.size).to be >= 2
    PWN::Sessions.delete(session_id: s[:id])
    expect(PWN::Sessions.list.any? { |x| x[:id] == s[:id] }).to be false
  end
end
