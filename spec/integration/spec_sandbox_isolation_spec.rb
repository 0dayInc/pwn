# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'offline spec mission isolation' do
  before do
    @outside = Dir.mktmpdir('pwn-outside-mission-')
    stub_const('PWN::AI::Agent::Mission::ROOT', File.join(@outside, 'missions'))
    stub_const('PWN::AI::Agent::OpenGoal::GOAL_FILE', File.join(@outside, 'open_goal.json'))
    PWN::AI::Agent::Mission.begin!(id: 'outside', request: 'Unrelated active mission fixture', unattended: true)
    PWN::AI::Agent::Mission.note_job!(id: 'outside', job_id: 'outside-job', command: 'fixture')
    PWN::AI::Agent::OpenGoal.begin!(request: 'Unrelated active mission fixture', mission_id: 'outside')
    @outside_files = Dir.glob(File.join(@outside, '**', '*')).select { |path| File.file?(path) }.to_h { |path| [path, File.binread(path)] }
    allow(PWN::Plugins::Jobs).to receive(:status).and_call_original
    allow(PWN::Plugins::Jobs).to receive(:status).with(id: 'outside-job').and_return(id: 'outside-job', status: 'RUNNING')
  end

  after { FileUtils.remove_entry(@outside) if @outside && Dir.exist?(@outside) }

  context 'with the shared persistence sandbox' do
    include_context 'pwn tmp sandbox'

    it 'answers through the provider without consulting or modifying an outside live mission' do
      allow(Dir).to receive(:home).and_return(@tmp)
      allow(PWN::AI::Agent::PromptBuilder).to receive(:build).and_return('Offline fixture')
      allow(PWN::AI::Agent::TaskSummarizer).to receive(:enabled?).and_return(false)
      allow(PWN::AI::Agent::Loop).to receive(:maybe_refresh_extro_snapshot!)
      allow(PWN::AI::Agent::Loop).to receive(:may_finalize?).and_return(true)
      allow(PWN::AI::Agent::Loop).to receive(:should_auto_introspect?).and_return(false)
      PWN::Env[:ai][:active] = :openai
      PWN::Env[:ai][:openai] = { model: 'offline-fixture' }
      allow(PWN::AI::OpenAI).to receive(:chat_with_tools).and_return(choices: [{ message: { role: 'assistant', content: 'Fixture answer.', tool_calls: [] } }])
      sid = PWN::Sessions.create(title: 'Isolation fixture')[:id]
      answer = PWN::AI::Agent::Loop.run(request: 'what color is a lemon?', session_id: sid, enabled_toolsets: [])
      expect(answer).to eq('Fixture answer.')
      expect(PWN::AI::OpenAI).to have_received(:chat_with_tools).once
      expect(PWN::AI::Agent::Mission::ROOT).to eq(File.join(@tmp, 'missions'))
      expect(PWN::AI::Agent::OpenGoal::GOAL_FILE).to eq(File.join(@tmp, 'open_goal.json'))
      expect(PWN::Plugins::Jobs).not_to have_received(:status).with(id: 'outside-job')
      @outside_files.each { |path, bytes| expect(File.binread(path)).to eq(bytes) }
    end
  end
end
