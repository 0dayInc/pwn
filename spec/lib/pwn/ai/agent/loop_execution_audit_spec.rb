# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::Loop, 'previous-session recall persistence' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
  end

  it 'reads the previous transcript without appending the current conversation to it' do
    previous = PWN::Sessions.create(id: 'previous-recall', title: 'Previous recall fixture')
    PWN::Sessions.append(session_id: previous[:id], role: 'user', content: 'Keep the release notes concise.')
    PWN::Sessions.append(session_id: previous[:id], role: 'assistant', content: 'I recorded that preference.')
    current = PWN::Sessions.create(id: 'current-recall', title: 'Current recall fixture')
    previous_path = File.join(PWN::Sessions.sessions_dir, "#{previous[:id]}.jsonl")
    old_bytes = File.binread(previous_path)
    request = 'what did I just say in the last session?'
    expect(PWN::AI::Ollama).not_to receive(:chat_with_tools)

    answer = described_class.run(request: request, session_id: current[:id], system_role_content: 'Recall fixture')

    expect(answer).to include('Keep the release notes concise.')
    expect(File.binread(previous_path)).to eq(old_bytes)
    turns = PWN::Sessions.load(session_id: current[:id]).last(2)
    expect(turns.map { |row| row[:role].to_s }).to eq(%w[user assistant])
    expect(turns.map { |row| row[:content] }).to eq([request, answer])
  end
end
