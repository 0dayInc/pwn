# frozen_string_literal: true

require 'spec_helper'
require 'pwn/session_trace'

RSpec.describe PWN::SessionTrace, 'lifecycle audit regressions' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
  end

  it 'does not create a session store when reading a missing trace' do
    directory = File.join(@tmp, 'absent-sessions')
    stub_const('PWN::Sessions::SESSIONS_DIR', directory)
    expect { described_class.read(session_id: 'missing') }.to raise_error(Errno::ENOENT)
    expect(File).not_to exist(directory)
  end

  it 'refuses trace writes through a symlinked session-store ancestor' do
    outside = File.join(@tmp, 'outside')
    Dir.mkdir(outside)
    linked = File.join(@tmp, 'linked-sessions')
    File.symlink(outside, linked)
    stub_const('PWN::Sessions::SESSIONS_DIR', linked)
    expect { described_class.append(session_id: 'fixture', event: 'request', data: 'fixture') }.to raise_error(ArgumentError, /Symlink/)
    expect(Dir.children(outside)).to eq([])
  end

  it 'does not publish a new trace reference while cleanup owns the session lease' do
    session = PWN::Sessions.create
    path = PWN::Sessions.support_path(kind: :lease, session_id: session[:id])
    File.open(path, File::RDWR) do |lock|
      expect(lock.flock(File::LOCK_EX | File::LOCK_NB)).to be_truthy
      expect { described_class.append(session_id: session[:id], event: 'request', data: 'fixture') }.to raise_error(IOError, /removed/)
    end
    expect(File).not_to exist(PWN::Sessions.support_path(kind: :trace, session_id: session[:id], read_only: true))
  end
end
