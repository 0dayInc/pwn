# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools mistakes' do
  it 'registers mistakes_list / mistakes_resolve / mistakes_reset' do
    PWN::AI::Agent::Registry.discover(force: true)
    %w[mistakes_list mistakes_resolve mistakes_reset].each do |n|
      expect(PWN::AI::Agent::Registry.lookup(name: n)).not_to be_nil
    end
  end
end
