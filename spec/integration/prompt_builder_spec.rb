# frozen_string_literal: true

require 'spec_helper'

# ─────────────────────────────────────────────────────────────────────────────
#  #3 — the system prompt is rebuilt every turn; a nil-interpolation or
#  dropped block breaks the WHOLE harness invisibly (the model just gets
#  quieter). NON-BLOCKING: Extrospection.to_context is stubbed and every
#  *_FILE lands in the sandbox.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::AI::Agent::PromptBuilder', :aggregate_failures do
  include_context 'pwn tmp sandbox'

  let(:builder)  { PWN::AI::Agent::PromptBuilder }
  let(:learning) { PWN::AI::Agent::Learning }
  let(:mistakes) { PWN::AI::Agent::Mistakes }

  before do
    # ensure every optional block has content so the assembler is exercised
    PWN::Memory.remember(key: 'pb_spec', value: 'prompt builder marker', category: :fact)
    learning.note_outcome(task: 'pb spec ok', success: true)
    learning.note_outcome(task: 'pb spec fail', success: false, details: 'boom')
    mistakes.record(tool: 'shell', error: 'pb spec error')
    PWN::AI::Agent::Metrics.record(name: 'shell', success: true, duration: 0.01)
    allow(PWN::AI::Agent::Extrospection).to receive(:to_context)
      .and_return("EXTROSPECTION\n  host_fp : deadbeef\n\n")
    stub_const('PWN::Skills', { pb_skill: { content: "# pb skill\nbody", references: [] } }.freeze)
    PWN::Env[:ai] = { active: :anthropic, module_reflection: false, agent: @agent_cfg }
  end

  it 'contains every section header, session_id and PWN::VERSION' do
    prompt = builder.build(session_id: 'sess_abc')
    ['ENVIRONMENT', 'MEMORY', 'SKILLS', 'LEARNING', 'KNOWN MISTAKES', 'TOOL EFFECTIVENESS', 'EXTROSPECTION', 'TOOL USE'].each do |hdr|
      expect(prompt).to include(hdr), "missing section: #{hdr}"
    end
    expect(prompt).to include('session_id : sess_abc')
    expect(prompt).to include(PWN::VERSION)
    expect(prompt).to include('prompt builder marker')
  end

  it 'never leaks a raw nil or an unrendered #{...} interpolation' do
    prompt = builder.build(session_id: 'sess_abc')
    expect(prompt).not_to include('#{')
    # allow "nil" inside code fences / values but not as a bare interpolated hole
    expect(prompt).not_to match(/:\s*nil\b/)
  end

  it '.budget for :ollama is strictly smaller per-block than :anthropic and gates :extro off' do
    PWN::Env[:ai] = { active: :ollama, module_reflection: false, agent: {} }
    small = builder.budget
    PWN::Env[:ai] = { active: :anthropic, module_reflection: false, agent: {} }
    big = builder.budget
    %i[memory metrics mistakes learning].each do |k|
      expect(small[k]).to be < big[k], "budget[:#{k}] not smaller for :ollama (#{small[k]} vs #{big[k]})"
    end
    expect(small[:extro]).to be(false)
    expect(big[:extro]).to be(true)
  end

  it 'falls back cleanly when MemoryIndex is unavailable and blocks are empty' do
    allow(PWN::Memory).to receive(:to_context).and_return('')
    allow(PWN::AI::Agent::Extrospection).to receive(:to_context).and_return('')
    prompt = builder.build(session_id: nil, request: 'anything')
    expect(prompt).to include('ENVIRONMENT').and include('TOOL USE')
    expect(prompt).to include('(none)') # session_id : (none)
  end
end
