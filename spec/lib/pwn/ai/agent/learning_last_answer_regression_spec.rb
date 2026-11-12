# frozen_string_literal: true

require 'spec_helper'

describe 'last-assistant learning paths' do
  include_context 'pwn tmp sandbox'

  let(:transcript) do
    [
      { role: 'user', content: 'first task' },
      { role: 'assistant', content: 'older answer' },
      { role: 'user', content: 'second task' },
      { role: 'assistant', content: 'latest answer' },
      { role: 'user', content: 'no, that is wrong' }
    ]
  end

  before do
    allow(PWN::Sessions).to receive(:load).with(session_id: 'fixture-session').and_return(transcript)
  end

  it 'extracts the latest answer for provider-free reflection without mutating the transcript' do
    result = PWN::AI::Agent::Learning.reflect(session_id: 'fixture-session', dry_run: true)
    expect(result[:lessons].map { |row| row[:lesson] }).to eq(['Approach that worked: latest answer'])
    expect(transcript.last[:role]).to eq('user')
  end

  it 'retains the actual rejected answer for correction preference capture' do
    PWN::AI::Agent::Mistakes.check_user_correction(request: 'no, that is wrong', session_id: 'fixture-session')
    expect(Thread.current[:pwn_pending_pref]).to include(prompt: 'second task', rejected: 'latest answer')
  end
end
