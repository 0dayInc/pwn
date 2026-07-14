# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools curriculum' do
  before(:all) { PWN::AI::Agent::Registry.discover(force: true) }

  %w[curriculum_practice curriculum_train curriculum_hindsight learning_purge_noise].each do |tool|
    it "registers the #{tool} tool" do
      expect(PWN::AI::Agent::Registry.lookup(name: tool)).not_to be_nil
    end
  end

  it 'exposes curriculum tools under the learning toolset' do
    tool = PWN::AI::Agent::Registry.lookup(name: 'curriculum_practice')
    expect(tool.toolset).to eq('learning')
  end
end
