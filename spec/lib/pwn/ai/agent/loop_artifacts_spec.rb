# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::AI::Agent::Loop do
  around do |example|
    keys = %i[pwn_loop_active pwn_loop_nested pwn_loop_deliverables pwn_loop_no_tools]
    saved = keys.to_h { |key| [key, Thread.current[key]] }
    Thread.current[:pwn_loop_active] = true
    Thread.current[:pwn_loop_nested] = nil
    Thread.current[:pwn_loop_deliverables] = nil
    Thread.current[:pwn_loop_no_tools] = nil
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
