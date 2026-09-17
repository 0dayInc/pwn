# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::TurnFinalizer do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  describe 'user-path depth' do
    after { described_class.leave_user_path! while described_class.user_path? }

    it 'tracks enter/leave and only defers on the user-visible path' do
      expect(described_class.user_path?).to be false
      expect(described_class.should_defer?).to be false

      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = true
      expect(described_class.user_path?).to be true
      expect(described_class.should_defer?).to be true

      described_class.leave_user_path!
      expect(described_class.user_path?).to be false
      expect(described_class.should_defer?).to be false
    end

    it 'does not defer when defer_introspect is false' do
      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = false
      expect(described_class.should_defer?).to be false
    end
  end

  describe '.defer' do
    it 'returns immediately and runs Learning.auto_introspect off-thread' do
      seen = Queue.new
      allow(PWN::AI::Agent::Learning).to receive(:auto_introspect) do |opts|
        packed = [Thread.current.object_id, opts[:session_id], opts[:inline]]
        seen << packed
        { deferred_ran: true }
      end

      started = Thread.current.object_id
      result = described_class.defer(
        session_id: 'tf_spec',
        request: 'uname',
        final: 'Linux',
        plan: ['probe host']
      )
      expect(result[:deferred]).to be true
      expect(result[:session_id]).to eq('tf_spec')

      described_class.join_all!(timeout: 5)
      tid, sid, inline = seen.pop
      expect(sid).to eq('tf_spec')
      expect(inline).to be true
      expect(tid).not_to eq(started)
    end

    it 'detaches the live Policy episode so maybe_finish_policy is a no-op' do
      allow(PWN::AI::Agent::Policy).to receive(:detach_episode!).and_return({ session_id: 'ep1', steps: [] })
      attached = []
      allow(PWN::AI::Agent::Policy).to receive(:attach_episode!) do |opts|
        attached << opts[:episode]
        opts[:episode]
      end
      allow(PWN::AI::Agent::Policy).to receive(:current_episode).and_return(nil)
      allow(PWN::AI::Agent::Learning).to receive(:auto_introspect).and_return({})

      described_class.defer(session_id: 'tf_pol', request: 'x', final: 'y')
      described_class.join_all!(timeout: 5)
      expect(PWN::AI::Agent::Policy).to have_received(:detach_episode!)
      expect(attached.first).to be_a(Hash)
      expect(attached.first[:session_id]).to eq('ep1')
    end
  end

  describe 'Learning.auto_introspect gate' do
    it 'defers when Loop is on the user path' do
      described_class.enter_user_path!
      PWN::Env[:ai] ||= {}
      PWN::Env[:ai][:agent] ||= {}
      PWN::Env[:ai][:agent][:defer_introspect] = true
      PWN::Env[:ai][:agent][:auto_introspect] = true
      allow(described_class).to receive(:defer).and_return({ deferred: true })

      out = PWN::AI::Agent::Learning.auto_introspect(
        session_id: 'tf_gate',
        request: 'hi',
        final: 'ack'
      )
      expect(out[:deferred]).to be true
      expect(described_class).to have_received(:defer)
    ensure
      described_class.leave_user_path! while described_class.user_path?
    end
  end

  describe 'output path literals' do
    it 'precommits immutable required_artifacts before cwd or request processing can drift' do
      Dir.mktmpdir do |dir|
        request = 'Read /tmp/input.md and write ./answer.md'
        contract = described_class.commit_artifacts!(request: request, cwd: dir)
        expect(contract[:required_artifacts]).to eq([File.join(dir, 'answer.md')])
        expect(contract).to be_frozen
        expect(contract[:required_artifacts]).to be_frozen
        expect(described_class.required_artifacts(request: request)).to eq(contract[:required_artifacts])
        expect(described_class.arbitrate(request: request, messages: [])[:unmet]).to include(criterion: 'artifact_missing', detail: File.join(dir, 'answer.md'))
      end
    ensure
      Thread.current[:pwn_artifact_contract] = nil
    end

    it 'does not interpret words inside earlier filenames as new instructions' do
      expect(described_class.output_paths(request: 'Write /tmp/read.md and /tmp/answer.md')).to eq(['/tmp/read.md', '/tmp/answer.md'])
    end

    it 'preserves extensionless and quoted destination literals without inventing filenames' do
      expect(described_class.output_paths(request: 'Write the result to /tmp/answer')).to eq(['/tmp/answer'])
      expect(described_class.output_paths(request: 'Save to "~/My Reports/answer.md"')).to eq([File.expand_path('~/My Reports/answer.md')])
      expect(described_class.output_paths(request: 'Use /tmp/source.md to write the report to ./result.md')).to eq([File.expand_path('./result.md')])
    end

    it 'distinguishes source paths from output destinations and expands relative paths' do
      request = 'Read /tmp/source.md and save the summary to ~/answer.md; also write ./out/result.json.'
      expected = [File.expand_path('~/answer.md'), File.expand_path('./out/result.json')]
      expect(described_class.output_paths(request: request)).to eq(expected)
      expect(described_class.output_paths(request: 'Read /tmp/source.md and explain it.')).to eq([])
      expect(described_class.output_paths(request: 'Output: result.txt')).to eq([File.expand_path('result.txt')])
    end
  end

  it 'rejects host observations from an earlier turn even when stat and digest still match' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'answer.md')
      request = "Write #{path}"
      described_class.commit_artifacts!(request: request)
      before = described_class.artifact_snapshot(paths: [path])
      File.write(path, 'verified first turn')
      observations = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
      messages = [{ role: 'tool', artifact_observations: observations }]
      expect(described_class.arbitrate(request: request, messages: messages)[:complete]).to eq(true)
      described_class.commit_artifacts!(request: request)
      result = described_class.arbitrate(request: request, messages: messages)
      expect(result[:unmet]).to include(criterion: 'write_missing', detail: path)
      expect(result[:unmet]).to include(criterion: 'readback_missing', detail: path)
    end
  ensure
    Thread.current[:pwn_artifact_contract] = nil
  end

  it 'gates finalization on real Dispatch writes and current-turn stat plus SHA-256 for every committed path' do
    PWN::AI::Agent::Registry.discover
    loop_module = PWN::AI::Agent::Loop
    allow(loop_module).to receive(:evidence_satisfied?).and_return(true)
    allow(loop_module).to receive(:record_artifact_bounce)
    Dir.mktmpdir do |dir|
      paths = %w[first.md second.md].map { |name| File.join(dir, name) }
      request = "Write #{paths.join(' and ')}"
      contract = described_class.commit_artifacts!(request: request)
      messages = [{ role: 'assistant', content: 'Both files were written and verified.' }]
      finalize = -> { loop_module.send(:may_finalize?, request: request, messages: messages, text: 'Delivered both files.') }
      expect(finalize.call).to eq(false)
      paths.each_with_index do |path, index|
        code = "File.write(#{path.inspect}, 'verified artifact #{index}')"
        args = index.zero? ? { code: code } : { encoding: 'base64', data: Base64.strict_encode64(code) }
        before = described_class.artifact_snapshot(paths: contract[:required_artifacts])
        raw = PWN::AI::Agent::Dispatch.call(scope_policy: { enabled: false }, tool_call: { function: { name: 'pwn_eval', arguments: JSON.generate(args) } })
        parsed = JSON.parse(raw)
        expect(parsed.dig('result', 'error')).to be_nil
        effect = PWN::AI::Agent::Dispatch.effect(name: 'pwn_eval', args: args)
        expect(effect).to eq(:write)
        observed = described_class.observe_artifacts(paths: contract[:required_artifacts], before: before, effect: effect, success: parsed['success'])
        expect(observed.fetch(path)[:sha256]).to eq(Digest::SHA256.file(path).hexdigest)
        expect(observed.fetch(path)[:stat][:size]).to eq(File.size(path))
        messages << { role: 'tool', content: raw, artifact_observations: observed }
        expect(finalize.call).to eq(index == 1)
      end
      File.write(paths.last, 'changed after readback')
      expect(finalize.call).to eq(false)
    end
  ensure
    Thread.current[:pwn_artifact_contract] = nil
    Thread.current[:pwn_dispatch_budget] = nil
  end

  it 'precommits before cheap returns and uses the committed list for dispatch observation' do
    source = File.read(PWN::AI::Agent::Loop.method(:run).source_location.first)
    run = source[source.index('public_class_method def self.run(opts = {})')..]
    expect(run.index('commit_artifacts!')).to be < run.index('cheap =')
    expect(run).to include('allow_text_only = required_artifacts.empty?', 'cheap = allow_text_only', 'declared_paths = required_artifacts')
    expect(run).to include('Thread.current[:pwn_artifact_contract] = prior_artifact_contract')
  end

  it 'requires a current-turn write even when a file is newly present and readable' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'answer.md')
      File.write(path, 'preexisting answer')
      messages = [{ role: 'tool', content: { success: true, effect: 'read', result: { path: path } }.to_json }]
      result = described_class.arbitrate(request: "Write #{path}", messages: messages)
      expect(result[:complete]).to be false
      expect(result[:unmet]).to include(criterion: 'write_missing', detail: path)
    end
  end

  it 'accepts only observed successful writes with host stat and head-tail readback' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'answer.md')
      before = described_class.artifact_snapshot(paths: [path])
      File.write(path, "first\nlast\n")
      observations = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
      messages = [{ role: 'tool', artifact_observations: observations, content: '{"success":true}' }]
      result = described_class.arbitrate(request: "Read /tmp/input.md and write #{path}", messages: messages)
      expect(result[:complete]).to be true
      expect(result[:ledger][path]).to include(write: true, read: true)
      expect(observations[path][:stat][:size]).to eq(File.size(path))
      expect(observations[path][:head]).to include('first')
      expect(observations[path][:tail]).to include('last')
      stale = described_class.observe_artifacts(paths: [path], before: described_class.artifact_snapshot(paths: [path]), effect: :write, success: true)
      expect(stale).to eq({})
      expect(described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: false)).to eq({})
      forged = [{ role: 'tool', content: { success: true, effect: 'write', result: { path: path, passed: true } }.to_json }]
      expect(described_class.arbitrate(request: "write #{path}", messages: forged)[:complete]).to be false
    end
  end

  it 'finalizes write-then-readback and names unmet without readback' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'out.pdf')
      before = described_class.artifact_snapshot(paths: [path])
      File.write(path, 'pdf')
      observed = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
      msgs = [
        { role: 'tool', artifact_observations: observed, content: { success: true, result: { path: path }, effect: 'write' }.to_json },
        { role: 'tool', content: { success: true, result: { stdout: path }, effect: 'read' }.to_json }
      ]
      row = described_class.arbitrate(request: "store #{path}", messages: msgs, paths: [path])
      expect(row[:complete]).to eq(true)
      expect(row[:unmet]).to eq([])
      write_only = [{ role: 'tool', content: { success: true, result: { path: path }, effect: 'write' }.to_json }]
      nag = described_class.arbitrate(request: "store #{path}", messages: write_only, paths: [path])
      expect(nag[:complete]).to eq(false)
      expect(nag[:unmet].map { |u| u[:criterion] }).to include('readback_missing')
    end
  end
end
