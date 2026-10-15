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

  it 'keeps runtime-bound goals separate and exposes their checkpoint identity for resume' do
    runtimes = %w[one two].map do |sid|
      PWN::AI::Agent::RequestRuntime.new(request: "Write #{sid}.txt", session_id: sid, request_id: sid, artifact_root: tmp, trace: false)
    end
    runtimes.each do |runtime|
      Thread.current[:pwn_request_runtime] = runtime
      described_class.begin!(request: runtime.request, session_id: runtime.session_id)
    end
    runtimes.each do |runtime| # rubocop:disable Style/CombinableLoops -- assert after both writes to catch cross-session clobbering
      Thread.current[:pwn_request_runtime] = runtime
      expect(described_class.current).to include(request_id: runtime.request_id, checkpoint_path: runtime.checkpoint_path)
      expect(File.stat(described_class.goal_file).mode & 0o777).to eq(0o600)
    end
  ensure
    Thread.current[:pwn_request_runtime] = nil
  end

  it 'resumes only a bare continue/resume ask, not a new goal' do
    described_class.begin!(request: 'Update all markdown files', session_id: 's1')
    expect(described_class.resume?(request: 'continue')).to eq true
    expect(described_class.resume?(request: 'resume')).to eq true
    expect(described_class.resume?(request: 'keep going')).to eq true
    expect(described_class.resume?(request: 'Update all markdown files again')).to eq false
    expect(described_class.resume?(request: 'what color is a cherry')).to eq false
  end

  it 'holds the saved goal while a bound mission is not done' do
    described_class.begin!(request: 'fuzz for 6 hours', session_id: 's1', mission_id: 'long')
    allow(PWN::AI::Agent::Mission).to receive(:done?).with(id: 'long').and_return(false)
    expect(described_class.clear!).to eq(:held)
    expect(described_class.current[:request]).to eq('fuzz for 6 hours')
  end
end
