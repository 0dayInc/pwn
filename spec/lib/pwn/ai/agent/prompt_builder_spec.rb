# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::AI::Agent::PromptBuilder do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::PromptBuilder
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::PromptBuilder
    expect(help_response).to respond_to :help
  end

  describe 'last-turn injection' do
    it 'build includes recent_turns_block in source contract' do
      src = File.read(described_class.method(:build).source_location.first)
      expect(src).to match(/recent_turns_block/)
      expect(src).to match(/RECENT TURNS/)
      expect(src).to match(/recent_turns:/)
    end

    it 'injects prior user/assistant pair for the active session' do
      sess_tmp = Dir.mktmpdir('pwn-pb-sess')
      mem_tmp = Dir.mktmpdir('pwn-pb-mem')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      stub_const('PWN::Memory::MEMORY_FILE', File.join(mem_tmp, 'memory.json'))
      PWN::Memory.clear(force: true)
      sid = 'pb_recent'
      PWN::Sessions.create(id: sid, title: 'pb-recent')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'PRIOR USER MARKER 42')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'prior assistant ack')
      prompt = described_class.build(session_id: sid, request: 'what did I just say?')
      expect(prompt).to include('RECENT TURNS')
      expect(prompt).to include('PRIOR USER MARKER 42')
      expect(prompt).to include('prior assistant ack')
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
      FileUtils.rm_rf(mem_tmp) if mem_tmp
    end

    it 'injects last assistant turn for how-did-you-respond cues' do
      sess_tmp = Dir.mktmpdir('pwn-pb-asst')
      mem_tmp = Dir.mktmpdir('pwn-pb-mem2')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      stub_const('PWN::Memory::MEMORY_FILE', File.join(mem_tmp, 'memory.json'))
      PWN::Memory.clear(force: true)
      sid = 'pb_asst'
      PWN::Sessions.create(id: sid, title: 'pb-asst')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'ping')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'ASSISTANT MARKER 99')
      prompt = described_class.build(
        session_id: sid,
        request: 'how did you respond to what I just said?'
      )
      expect(prompt).to include('RECENT TURNS')
      expect(prompt).to include('ASSISTANT MARKER 99')
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
      FileUtils.rm_rf(mem_tmp) if mem_tmp
    end
  end

  describe 'Hermes skill-index prefix' do
    it 'emits SKILLS before MEMORY so prompt-cache can pin the index' do
      src = File.read(described_class.method(:build).source_location.first)
      skills_needle = ['#', '{skills_block}'].join
      memory_needle = ['#', '{memory_block'].join
      skills_at = src.index(skills_needle)
      memory_at = src.index(memory_needle)
      expect(skills_at).not_to be_nil
      expect(memory_at).not_to be_nil
      expect(skills_at).to be < memory_at
    end
  end
end
