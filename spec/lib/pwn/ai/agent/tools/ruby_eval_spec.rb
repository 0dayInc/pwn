# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools ruby_eval' do
  it 'registers the pwn_eval tool' do
    PWN::AI::Agent::Registry.discover
    expect(PWN::AI::Agent::Registry.lookup(name: 'pwn_eval')).not_to be_nil
  end
end
