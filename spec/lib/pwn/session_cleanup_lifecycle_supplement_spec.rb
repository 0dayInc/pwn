# frozen_string_literal: true

require 'spec_helper'
require File.expand_path('../../../etc/default_cron/session_cleanup', __dir__)

RSpec.describe PWN::SessionCleanup, 'lifecycle audit regressions' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @root = File.join(@tmp, '.pwn')
    FileUtils.mkdir_p(@root, mode: 0o700)
    stub_const('PWN::Sessions::SESSIONS_DIR', File.join(@root, 'sessions'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(@root, 'learning.jsonl'))
    @proc_root = File.join(@tmp, 'fixture-processes')
    Dir.mkdir(@proc_root)
  end

  it 'stops coordinator retention after an admitted disposable deletion is interrupted' do
    described_class.install
    path = File.join(@root, 'cache', 'fixture.txt')
    described_class.cache(path: path, bytes: 'fixture disposable bytes')
    described_class.register_disposable(path: path, category: 'cache', expires_at: 0)
    allow(File).to receive(:unlink).and_call_original
    allow(File).to receive(:unlink).with(path).and_raise(Errno::EACCES)
    expect(PWN::AI::Agent::Learning).not_to receive(:consolidate)
    expect(PWN::AI::Agent::Learning).not_to receive(:prune_outcomes!)
    expect(PWN::AI::Agent::Mistakes).not_to receive(:lean!)
    expect(PWN::AI::Agent::Policy).not_to receive(:lean!)
    result = described_class.coordinate(proc_root: @proc_root)
    expect(result[:state]).to eq('interrupted')
    maintenance = result[:phases].fetch(:maintenance)
    expect(maintenance[:storage][:state]).to eq('interrupted')
    expect(maintenance[:storage][:records]).to include(hash_including('state' => 'prepared'))
    expect(File.binread(path)).to eq('fixture disposable bytes')
  ensure
    allow(File).to receive(:unlink).with(path).and_call_original if path
  end
end
