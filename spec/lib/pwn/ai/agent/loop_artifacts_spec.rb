# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::AI::Agent::Loop do
  around do |example|
    keys = %i[pwn_loop_active pwn_loop_nested pwn_loop_deliverables pwn_loop_no_tools pwn_artifact_contract]
    saved = keys.to_h { |key| [key, Thread.current[key]] }
    Thread.current[:pwn_loop_active] = true
    Thread.current[:pwn_loop_nested] = nil
    Thread.current[:pwn_loop_deliverables] = nil
    Thread.current[:pwn_loop_no_tools] = nil
    Thread.current[:pwn_artifact_contract] = nil
    example.run
  ensure
    saved.each { |key, value| Thread.current[key] = value }
  end

  before do
    allow(described_class).to receive(:call_engine).and_return('not valid JSON')
    allow(PWN::AI::Agent::Mistakes).to receive(:record)
  end

  it 'never adopts cached model destinations absent from the original request' do
    Thread.current[:pwn_loop_deliverables] = { paths: ['/tmp/invented.pdf'] }
    expect(described_class.send(:declared_deliverables, request: 'Generate a report')).to eq([])
  end

  it 'does not let source read evidence bypass the destination contract' do
    Dir.mktmpdir do |dir|
      source = File.join(dir, 'source.md')
      output = File.join(dir, 'output.md')
      File.write(source, 'source content')
      request = "Read #{source} and write #{output}"
      messages = [{ role: 'tool', content: { success: true, effect: 'read', result: { path: source } }.to_json }]
      expect(described_class.evidence_satisfied?(request: request, messages: messages, text: 'Done.')).to be false
    end
  end

  it 'does not use a filename in tool output as evidence of its contents or of a delivered file' do
    Dir.mktmpdir do |dir|
      source = File.join(dir, 'notes.txt')
      File.write(source, 'casefold')
      request = 'Check casefold and answer in chat.'
      PWN::AI::Agent::TurnFinalizer.commit_artifacts!(request: request)
      Thread.current[:pwn_loop_deliverables] = { techniques: ['casefold'] }
      messages = [{ role: 'tool', name: 'artifact_read', content: { success: true, effect: 'read', result: { path: source, body: 'preview' } }.to_json }]
      allow(File).to receive(:binread).and_call_original
      unmet = described_class.send(:completion_unmet, request: request, messages: messages)
      expect(File).not_to have_received(:binread).with(source, any_args)
      expect(unmet).to include('techniques')
      expect(described_class.evidence_satisfied?(request: request, messages: messages, text: 'Done.')).to be(false)
    end
  end

  it 'can check the observed contents of a requested output without a matching claim in tool text' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'report.txt')
      request = "Write #{path} with the casefold result."
      finalizer = PWN::AI::Agent::TurnFinalizer
      paths = finalizer.commit_artifacts!(request: request).fetch(:required_artifacts)
      Thread.current[:pwn_loop_deliverables] = { techniques: ['casefold'] }
      before = finalizer.artifact_snapshot(paths: paths)
      File.write(path, 'casefold checked')
      observed = finalizer.observe_artifacts(paths: paths, before: before, effect: :write, success: true)
      messages = [{ role: 'tool', content: 'saved', artifact_observations: observed }]
      expect(described_class.send(:completion_unmet, request: request, messages: messages)).to be_empty
      expect(described_class.evidence_satisfied?(request: request, messages: messages)).to be(true)
    end
  end

  it 'keeps an explicit output pending when inference fails and a generic tool claims passed' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'answer.md')
      request = "Read /tmp/input.md and write #{path}"
      messages = [{ role: 'tool', content: '{"success":true,"effect":"read","result":{"passed":true}}' }]
      expect(described_class.send(:declared_deliverables, request: request)).to eq([path])
      expect(described_class.send(:completion_unmet, request: request, messages: messages)).to include("deliverable_missing:#{path}")
      expect(described_class.send(:may_finalize?, request: request, messages: messages, text: "Written #{path}")).to be false
      expect(PWN::AI::Agent::Mistakes).to have_received(:record).with(hash_including(tool: 'artifact_contract'))
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to include('artifact not written; write it now')
    end
  end
end

RSpec.describe PWN::AI::Agent::Loop, 'local document inputs' do
  include_context 'pwn tmp sandbox'

  it 'does not mark an unread document complete just because the destination is chat' do
    allow(Dir).to receive(:home).and_return(@tmp)
    @agent_cfg.merge!(plan_first: false, task_summary_llm: false, auto_introspect: false)
    sid = PWN::Sessions.create[:id]
    claim = 'I read the document.'
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', content: claim } }])
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    outcome = nil
    answer = described_class.run(request: 'Read "notes.txt" and reply in chat.', session_id: sid, engine: :openai, enabled_toolsets: [],
                                 system_role_content: 'Read the supplied document.', on_outcome: ->(row) { outcome = row })
    expect(outcome).to include(status: 'blocked', unmet: include('no_available_tools'))
    expect(answer).to include('notes.txt', 'not fully read')
    expect(PWN::Sessions.load(session_id: sid)).not_to include(hash_including(role: 'assistant', content: claim))
  end

  it 'can finish from successive real reads without having to change either input', :requires_landlock do
    allow(Dir).to receive(:home).and_return(@tmp)
    @agent_cfg.merge!(plan_first: false, task_summary_llm: false, auto_introspect: false)
    PWN::Env[:ai][:active] = :grok
    PWN::Env[:ai][:grok] = { model: 'fixture-model' }
    paths = %w[first.txt second.txt].map { |name| File.join(@tmp, name) }
    values = paths.map { |path| SecureRandom.hex(5).tap { |text| File.write(path, text) } }
    sid = PWN::Sessions.create[:id]
    seen = []
    watched = []
    allow(File).to receive(:binread).and_call_original
    allow(PWN::AI::Agent::TurnFinalizer).to receive(:artifact_snapshot).and_wrap_original do |original, opts|
      watched.concat(opts.fetch(:paths))
      original.call(opts)
    end
    allow(PWN::AI::Grok).to receive(:grok_rest_call) do |call|
      wire = call.fetch(:http_body)
      names = Array(wire[:tools]).map { |tool| tool.dig(:function, :name) }
      expect(names).to include('artifact_read')
      expect(names).not_to include('shell', 'pwn_eval')
      pages = wire.fetch(:messages).select { |row| row[:role] == 'tool' }.map do |row|
        page = JSON.parse(described_class.send(:unwrap_untrusted, text: row.fetch(:content)))
        expect(page).to include('success' => true, 'effect' => 'read')
        page.fetch('result').fetch('body')
      end
      seen << pages
      raise 'retried after both files were read' if seen.size > 3

      msg = if pages.size < paths.size
              fn = { name: 'artifact_read', arguments: { path: paths.fetch(pages.size) }.to_json }
              { tool_calls: [{ id: "read_#{pages.size}", type: 'function', function: fn }] }
            else
              { content: pages.join(' vs ') }
            end
      JSON.generate(choices: [{ message: msg.merge(role: 'assistant') }])
    end

    outcome = nil
    answer = described_class.run(request: "Compare #{paths.join(' to ')}.", session_id: sid, enabled_toolsets: ['sessions'],
                                 system_role_content: 'Compare the supplied documents.', on_outcome: ->(row) { outcome = row })
    expect(seen).to eq([[], values.first(1), values])
    expect(watched).to be_empty # Reading the inputs does not make them output artifacts.
    paths.each { |path| expect(File).not_to have_received(:binread).with(path) }
    expect(answer).to eq(values.join(' vs '))
    expect(outcome).to include(status: 'complete')
    expect(paths.map { |path| File.read(path) }).to eq(values)
    expect(PWN::Sessions.load(session_id: sid).last).to include(role: 'assistant', content: answer)
  end
end
