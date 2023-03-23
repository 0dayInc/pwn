# frozen_string_literal: true

require 'spec_helper'

describe PWN::VERSION do
  it 'is defined' do
    expect(PWN::VERSION).not_to be_nil
  end

  it 'is a string' do
    expect(PWN::VERSION).to be_a(String)
  end

  it 'matches the expected pattern' do
    expect(PWN::VERSION).to match(/\d+\.\d+\.\d+/)
  end
end
