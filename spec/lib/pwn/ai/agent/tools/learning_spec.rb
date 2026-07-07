# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools learning' do
  it 'registers the learning_note_outcome tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_note_outcome')).not_to be_nil
  end

  it 'registers the learning_reflect tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_reflect')).not_to be_nil
  end

  it 'registers the learning_distill_skill tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_distill_skill')).not_to be_nil
  end

  it 'registers the learning_stats tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'learning_stats')).not_to be_nil
  end

  it 'exposes the learning toolset in the registry' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.toolsets).to include('learning')
  end
end
