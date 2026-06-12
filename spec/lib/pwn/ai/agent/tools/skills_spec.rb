# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools skills' do
  it 'registers the skill_list tool' do
    PWN::AI::Agent::Registry.discover
    expect(PWN::AI::Agent::Registry.lookup(name: 'skill_list')).not_to be_nil
  end
end
