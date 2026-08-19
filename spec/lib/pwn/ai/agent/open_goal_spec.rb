# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tmpdir'

describe PWN::AI::Agent::OpenGoal do
  let(:tmp) { Dir.mktmpdir }

  before do
    stub_const('PWN::AI::Agent::OpenGoal::GOAL_FILE', File.join(tmp, 'open_goal.json'))
    described_class.clear!
  end

  after do
    FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
  end

  it 'saves, loads, and clears an unfinished host-work request' do
    expect(described_class.current).to be_nil
    described_class.begin!(request: 'Update all markdown files', session_id: 's1')
    row = described_class.current
    expect(row[:request]).to eq 'Update all markdown files'
    expect(row[:session_id]).to eq 's1'
    described_class.clear!
    expect(described_class.current).to be_nil
  end

  it 'resumes only a bare continue/resume ask, not a new goal' do
    described_class.begin!(request: 'Update all markdown files', session_id: 's1')
    expect(described_class.resume?(request: 'continue')).to eq true
    expect(described_class.resume?(request: 'resume')).to eq true
    expect(described_class.resume?(request: 'keep going')).to eq true
    expect(described_class.resume?(request: 'Update all markdown files again')).to eq false
    expect(described_class.resume?(request: 'what color is a cherry')).to eq false
  end
end
