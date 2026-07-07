# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Swarm do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Swarm
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Swarm
    expect(help_response).to respond_to :help
  end

  it 'exposes the core orchestration API' do
    %i[personas spawn retire create list ask debate broadcast bus_append bus_tail].each do |m|
      expect(PWN::AI::Agent::Swarm).to respond_to m
    end
  end

  it 'normalizes personas loaded from AGENTS_FILE without raising' do
    expect { PWN::AI::Agent::Swarm.personas }.not_to raise_error
  end

  it 'enforces the recursion depth guard' do
    Thread.current[:pwn_swarm_depth] = 999
    expect do
      PWN::AI::Agent::Swarm.ask(name: PWN::AI::Agent::Swarm.personas.keys.first || :__none, request: 'x')
    end.to raise_error(StandardError)
  ensure
    Thread.current[:pwn_swarm_depth] = nil
  end
end
