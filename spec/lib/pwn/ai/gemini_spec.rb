# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Gemini do
  it 'should display information for authors' do
    authors_response = PWN::AI::Gemini
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Gemini
    expect(help_response).to respond_to :help
  end

  it 'exposes get_plan_usage for the PS1 subscription suffix' do
    expect(described_class).to respond_to(:get_plan_usage)
  end
end
