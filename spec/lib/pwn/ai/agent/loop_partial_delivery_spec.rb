# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Loop, 'unfinished deliverables' do
  include_context 'pwn tmp sandbox'

  let(:sid) { PWN::Sessions.create(title: 'packing fixture')[:id] }
  let(:file) { File.join(@tmp, 'packing.txt') }
  let(:request) { "List two packing items in chat, then save the list to #{file}." }
  let(:draft) { 'Pack a coat and gloves. I did not save the file.' }

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @agent_cfg[:plan_first] = false
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    expect(PWN::AI::Agent::Reward).not_to receive(:judge)
  end

  def submit(ask, **options)
    described_class.run(request: ask, session_id: sid, engine: :openai, system_role_content: 'fixture',
                        on_outcome: ->(row) { @outcome = row }, **options)
  end

  it 'delivers a separately labelled chat draft when the requested file cannot be produced' do
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', content: draft } }])
    result = submit(request, enabled_toolsets: [])
    expect(result).to include(draft, file, 'not verified')
    expect(result).to be_a(described_class::TurnNotice)
    expect(@outcome).to include(status: 'blocked', unmet: include("artifact_missing:#{file}", 'no_available_tools'))
    rows = PWN::Sessions.load(session_id: sid)
    expect(rows.count { |r| r[:role] == 'notice' && r[:content] == result }).to eq(1)
    expect(rows).not_to include(hash_including(role: 'assistant'))
    expect(PWN::AI::Agent::OpenGoal.for_session(session_id: sid)).not_to be_nil
    expect(File.exist?(file)).to be(false)
  end

  it 'does not request a third final answer after telling the model exactly which file is missing' do
    calls = 0
    allow(PWN::AI::OpenAI).to receive(:chat_with_tools) do |opts|
      calls += 1
      raise 'third identical attempt with no new evidence' if calls > 2

      expect(opts[:messages].last[:content]).to include(file) if calls == 2
      { choices: [{ message: { role: 'assistant', content: draft } }] }
    end
    result = submit(request)
    expect(calls).to eq(2)
    expect(@outcome).to include(status: 'blocked', unmet: include('unchanged_evidence'))
    expect(result).to include(file, draft, 'not verified')
    expect(PWN::Sessions.load(session_id: sid)).to include(hash_including(role: 'notice', content: result))
  end

  it 'does not publish an unsupported write claim for a file-only request' do
    reply = 'The file was saved successfully.'
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', content: reply } }])
    result = submit("Save a list to #{file}.", enabled_toolsets: [])
    expect(result).to include(file, 'not verified')
    expect(result).not_to include(reply)
    expect(@outcome[:status]).to eq('blocked')
  end
end
