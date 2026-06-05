# frozen_string_literal: true

require 'spec_helper'

describe PWN::Memory do
  it 'should display information for authors' do
    authors_response = PWN::Memory
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Memory
    expect(help_response).to respond_to :help
  end

  it 'should support remember/recall/forget/clear' do
    PWN::Memory.clear
    PWN::Memory.remember(key: :test_fact, value: 'pwn-ai test memory', category: :fact)
    res = PWN::Memory.recall(query: 'test')
    expect(res.keys).to include(:test_fact)
    PWN::Memory.forget(:test_fact)
    expect(PWN::Memory.recall(query: 'test').keys).to be_empty
  end
end
