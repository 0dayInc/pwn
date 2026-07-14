# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools reward + curriculum' do
  it 'registers reward and curriculum tools' do
    PWN::AI::Agent::Registry.discover(force: true)
    names = PWN::AI::Agent::Registry.all.map(&:name)
    %w[reward_judge reward_prm reward_sentinel reward_preferences reward_export_dpo
       curriculum_practice curriculum_train curriculum_hindsight learning_purge_noise].each do |n|
      expect(names).to include(n)
    end
  end
end
