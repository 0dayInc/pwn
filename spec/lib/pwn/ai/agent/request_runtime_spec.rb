# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/request_runtime'

describe PWN::AI::Agent::RequestRuntime do
  include_context 'pwn tmp sandbox'

  it 'accepts a binary-tagged request without raising JSON::GeneratorError' do
    request = "status \u2022 ok".b
    expect(request.encoding).to eq(Encoding::ASCII_8BIT)
    runtime = described_class.new(request: request, session_id: 'encoding-fixture', artifact_root: @tmp, trace: false)
    expect(runtime.request.encoding).to eq(Encoding::UTF_8)
    expect(runtime.request).to eq("status \u2022 ok")
    expect(JSON.parse(File.read(runtime.checkpoint_path)).fetch('request')).to eq("status \u2022 ok")
  end

  it 'rejects simultaneous execution of the same session before creating a runtime' do
    sid = 'exclusive-fixture'
    allow(PWN::AI::Agent::Loop).to receive(:run_turn).and_return('fixture')
    root = PWN::Sessions.sessions_dir
    FileUtils.mkdir_p(root)
    File.open(File.join(root, ".#{Digest::SHA256.hexdigest(sid)}.execution.lock"), File::RDWR | File::CREAT, 0o600) do |lock|
      lock.flock(File::LOCK_EX | File::LOCK_NB)
      expect { PWN::AI::Agent::Loop.run(request: 'fixture', session_id: sid) }.to raise_error(IOError, /already executing/)
    end
  end

  it 'imports only current completed child host receipts with retained provenance' do
    path = File.join(@tmp, 'child.txt')
    options = { request: "Write #{path}", artifact_root: @tmp, trace: false }
    parent = described_class.new(options.merge(session_id: 'parent'))
    child = described_class.new(options.merge(session_id: 'child'))
    before = PWN::AI::Agent::TurnFinalizer.artifact_snapshot(paths: [path])
    Thread.current[:pwn_request_runtime] = child
    Thread.current[:pwn_artifact_contract] = child.contract
    File.write(path, "correct\n")
    PWN::AI::Agent::TurnFinalizer.observe_artifacts(paths: [path], before: before, success: true, effect: :write, action_id: 'child-write', tool: 'shell')
    parent.accept_child!(runtime: child)
    expect(parent.observations).to be_empty
    child.finish!(status: 'complete')
    parent.accept_child!(runtime: child)
    expect(parent.observations.fetch(path)).to include(artifact_turn_id: parent.contract[:id], action_id: 'child-write', child_request_id: child.request_id, child_turn_id: child.contract[:id])
    Thread.current[:pwn_request_runtime] = parent
    Thread.current[:pwn_artifact_contract] = parent.contract
    expect(PWN::AI::Agent::TurnFinalizer.arbitrate(request: parent.request)[:complete]).to be true
    File.write(path, 'tampered')
    expect(PWN::AI::Agent::TurnFinalizer.arbitrate(request: parent.request)[:complete]).to be false
    other = described_class.new(options.merge(session_id: 'other'))
    other.accept_child!(runtime: child)
    expect(other.observations).to be_empty
  ensure
    Thread.current[:pwn_request_runtime] = nil
    Thread.current[:pwn_artifact_contract] = nil
  end

  it 'shares a single attempt budget across profile fallback and preserves identical inputs' do
    runtime = described_class.new(request: 'fixture', session_id: 'fallback-budget', artifact_root: @tmp, trace: false, provider_attempts: 3,
                                  profile: 'primary', profiles: { primary: { provider: 'openai', fallback: ['backup'] }, backup: { provider: 'ollama' } })
    seen = []
    expect do
      runtime.call(messages: [{ role: 'user', content: 'fixture' }], tools: []) do |messages, route|
        expect(messages.last[:content]).to eq('fixture')
        expect(PWN::AI::HttpRetry.max_attempts(max_attempts: 99)).to eq(1)
        seen << route[:provider]
        messages.last[:content] = 'modified by adapter'
        raise Timeout::Error
      end
    end.to raise_error(Timeout::Error)
    expect(seen).to eq(%i[openai ollama ollama])
    expect(runtime.events.count { |row| row[:phase] == 'provider_start' }).to eq(3)
    expect(runtime.events.count { |row| row[:phase] == 'provider_end' }).to eq(3)
  end

  it 'does not retry invalid requests or quota failures and observes cancellation before fallback' do
    runtime = described_class.new(request: 'fixture', session_id: 'retry-classification', artifact_root: @tmp, trace: false)
    calls = 0
    expect do
      runtime.call(messages: [{ role: 'user', content: 'fixture' }], tools: []) do
        calls += 1
        raise ArgumentError, 'invalid schema'
      end
    end.to raise_error(ArgumentError)
    expect(calls).to eq(1)
    calls = 0
    expect do
      runtime.call(messages: [{ role: 'user', content: 'fixture' }], tools: []) do
        calls += 1
        raise 'insufficient_quota'
      end
    end.to raise_error(RuntimeError, /insufficient_quota/)
    expect(calls).to eq(1)
    cancelled = false
    runtime = described_class.new(request: 'fixture', session_id: 'cancel-before-retry', artifact_root: @tmp, trace: false, cancel: -> { cancelled })
    calls = 0
    expect do
      runtime.call(messages: [{ role: 'user', content: 'fixture' }], tools: []) do
        calls += 1
        cancelled = true
        raise Timeout::Error
      end
    end.to raise_error(Interrupt)
    expect(calls).to eq(1)
  end

  it 'serializes alias conflicts and never trusts shell or unknown read declarations' do
    runtime = described_class.new(request: 'fixture', session_id: 'conflicts', artifact_root: @tmp, trace: false)
    path = File.join(@tmp, 'source')
    link = File.join(@tmp, 'alias')
    File.write(path, 'fixture')
    File.symlink(path, link)
    calls = [path, link].map { |target| { function: { name: 'artifact_read', arguments: { path: target }.to_json } } }
    batches = []
    runtime.each_tool_batch(calls) { |batch| batches << batch }
    expect(batches.map(&:length)).to eq([1, 1])
    %w[shell pwn_eval arbitrary_read].each do |name|
      metadata = PWN::AI::Agent::Dispatch.scheduling(tool_call: { function: { name: name, arguments: { effect: 'read', command: 'cat file' } } })
      expect(metadata[:exclusive]).to be true
    end
  end

  it 'persists typed exact-target evidence and rejects stale, unrelated and spoofed host claims' do
    options = { request: 'Check example.test', session_id: 'remote', request_id: 'same', artifact_root: @tmp, trace: false }
    runtime = described_class.new(options)
    row = runtime.observe_evidence!(requirement: options[:request], kind: :http, locator: 'https://example.test.evil.invalid/', passed: true, sha256: Digest::SHA256.hexdigest('ok'))
    expect(runtime.host_evidenced?('example.test')).to be false
    expect(row).to include(source_id: 'original', provenance: 'host_verifier', request_id: 'same')
    expect { runtime.observe_evidence!(requirement: 'Invented task', kind: :http, locator: 'https://example.test/', passed: true, sha256: 'x') }.to raise_error(ArgumentError)
    runtime.observe_evidence!(requirement: options[:request], kind: :http, locator: 'https://example.test/', passed: true, sha256: Digest::SHA256.hexdigest('ok'))
    restored = described_class.new(options.merge(resume: true))
    expect(restored.host_evidenced?('example.test')).to be true
    expect(restored.fresh_evidence?(row.merge(observed_at: (Time.now - 60).utc.iso8601, max_age: 1))).to be false
    restored.observe_evidence!(requirement: options[:request], kind: :http, locator: 'https://example.test/', passed: false, sha256: Digest::SHA256.hexdigest('failed'))
    expect(restored.host_evidenced?('example.test')).to be false
    restored.amend!(instruction: 'Also check another.test')
    expect(restored.host_evidenced?('example.test')).to be false
    expect(restored.scope_evidenced?).to be false
  end

  it 'requires operator-approved fresh exact-target reconciliation after an uncertain remote mutation' do
    runtime = described_class.new(request: 'Update remote record', session_id: 'remote-write', artifact_root: @tmp, trace: false)
    args = { url: 'https://example.test/records/one' }
    expect { runtime.execute_tool(name: 'remote_update', args: args, effect: :exclusive) { raise Timeout::Error } }.to raise_error(Timeout::Error)
    key = runtime.events.first[:payload_sha256]
    row = runtime.observe_evidence!(requirement: runtime.request, kind: :http, locator: args[:url], passed: true, sha256: Digest::SHA256.hexdigest('updated'))
    expect(runtime.unmet).to include('uncertain_side_effect')
    expect { runtime.reconcile_effect!(payload_sha256: key, evidence_id: row[:id]) }.to raise_error(ArgumentError, /approval/)
    expect(runtime.reconcile_effect!(payload_sha256: key, evidence_id: row[:id], operator_approved: true)).to eq(:reconciled)
    expect(runtime.unmet).to be_empty
  end

  it 'persists uncertain effects before refusing duplicate execution after restart' do
    options = { request: 'Perform fixture mutation', session_id: 'uncertain', request_id: 'one', artifact_root: @tmp }
    runtime = described_class.new(options)
    counter = File.join(@tmp, 'counter')
    call = { name: 'fixture_write', args: { target: counter }, effect: :write, action_id: 'first' }
    expect do
      runtime.execute_tool(call) do
        File.open(counter, 'a') { |io| io.puts('effect') }
        raise Timeout::Error
      end
    end.to raise_error(Timeout::Error)
    restored = described_class.new(options.merge(resume: true))
    denied = restored.execute_tool(call.merge(action_id: 'second')) do
      File.open(counter, 'a') { |io| io.puts('duplicate') }
    end
    expect(denied).to include(error: 'uncertain_side_effect')
    expect(File.readlines(counter)).to eq(["effect\n"])
    expect(restored.unmet).to include('uncertain_side_effect')
    expect(restored.events.map { |event| event[:phase] }).to eq(%w[start end])
    expect(restored.events.last[:state]).to eq('uncertain')
  end

  it 'keeps original obligations through ordered amendments, with explicit replacement and cancellation' do
    runtime = described_class.new(request: 'Write /tmp/one.txt', session_id: 'scope', artifact_root: @tmp)
    runtime.amend!(instruction: 'Also write /tmp/two.txt')
    expect(runtime.original_request).to eq('Write /tmp/one.txt')
    expect(runtime.original_request).to be_frozen
    expect(runtime.contract[:required_artifacts]).to contain_exactly('/tmp/one.txt', '/tmp/two.txt')
    runtime.amend!(instruction: 'replace: Write /tmp/three.txt')
    expect(runtime.contract[:required_artifacts]).to eq(['/tmp/three.txt'])
    expect(runtime.amendments.map { |row| row[:mode] }).to eq(%w[add replace])
    runtime.amend!(instruction: 'cancel')
    expect(runtime.outcome[:status]).to eq('cancelled')
    expect(runtime.original_request).to eq('Write /tmp/one.txt')
  end

  it 'reloads revision-bound host evidence without needing any chat messages' do
    path = File.join(@tmp, 'proof.bin')
    options = { request: "Write #{path}", session_id: 'ledger', request_id: 'request-one', artifact_root: @tmp }
    runtime = described_class.new(options)
    Thread.current[:pwn_artifact_contract] = runtime.contract
    Thread.current[:pwn_request_runtime] = runtime
    before = PWN::AI::Agent::TurnFinalizer.artifact_snapshot(paths: [path])
    File.binwrite(path, "\xffverified".b)
    PWN::AI::Agent::TurnFinalizer.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
    restored = described_class.new(options.merge(resume: true))
    Thread.current[:pwn_request_runtime] = restored
    Thread.current[:pwn_artifact_contract] = restored.contract
    verdict = PWN::AI::Agent::TurnFinalizer.arbitrate(request: restored.request, messages: [])
    expect(verdict[:status]).to eq('complete')
    expect(verdict[:ledger][path][:evidence][:sha256]).to eq(Digest::SHA256.file(path).hexdigest)
    File.binwrite(path, 'different revision')
    expect(PWN::AI::Agent::TurnFinalizer.arbitrate(request: restored.request, messages: [])[:status]).to eq('incomplete')
  ensure
    Thread.current[:pwn_request_runtime] = nil
    Thread.current[:pwn_artifact_contract] = nil
  end

  it 'keeps atomic checkpoints disjoint for concurrent sessions using the same request id' do
    workers = %w[one two].map do |sid|
      Thread.new do
        runtime = described_class.new(request: "Write /tmp/#{sid}.txt", session_id: sid, request_id: 'same', artifact_root: @tmp, trace: false)
        runtime.finish!(status: 'incomplete', unmet: [sid])
        runtime
      end
    end
    runtimes = workers.map(&:value)
    expect(runtimes.map(&:checkpoint_path).uniq.length).to eq(2)
    runtimes.each do |runtime|
      row = JSON.parse(File.read(runtime.checkpoint_path))
      expect(row['session_id']).to eq(runtime.session_id)
      expect(row.dig('outcome', 'unmet')).to eq([runtime.session_id])
      expect(File.stat(runtime.checkpoint_path).mode & 0o777).to eq(0o600)
    end
  ensure
    workers&.each(&:join)
  end

  it 'rejects stale checkpoint writers rather than losing newer evidence' do
    options = { request: 'fixture', session_id: 'generation', request_id: 'same', artifact_root: @tmp, trace: false }
    first = described_class.new(options)
    second = described_class.new(options.merge(resume: true))
    second.finish!(status: 'incomplete', unmet: ['newer evidence'])
    expect { first.finish!(status: 'complete') }.to raise_error(IOError, /stale request checkpoint/)
    expect(JSON.parse(File.read(first.checkpoint_path)).dig('outcome', 'unmet')).to eq(['newer evidence'])
  end

  it 'persists caller tool permissions and verification contract across restart' do
    contract = { root: @tmp, requirements: ['fixture'], checks: [{ requirement: 'fixture', kind: 'answer', expected: 'seven' }] }
    options = { request: 'fixture', session_id: 'permissions', request_id: 'same', artifact_root: @tmp, trace: false,
                enabled_toolsets: ['memory'], verification_contract: contract }
    described_class.new(options)
    restored = described_class.new(options.except(:enabled_toolsets, :verification_contract).merge(resume: true))
    expect(restored.verification_contract).to eq(contract)
    expect(restored.tool_allowed?(toolset: 'shell')).to be false
    expect(restored.tool_allowed?(toolset: 'memory')).to be true
  end

  it 'connects the loop provider call to the selected profile' do
    runtime = described_class.new(request: 'Check fixture', session_id: 'runtime', profile: 'local',
                                  profiles: { local: { provider: 'ollama', model: 'fixture-local', temperature: 0.2 } }, artifact_root: @tmp)
    previous = Thread.current[:pwn_request_runtime]
    Thread.current[:pwn_request_runtime] = runtime
    allow(PWN::AI::Agent::Loop).to receive(:publish_usage)
    allow(PWN::AI::Agent::Loop).to receive(:active_engine).and_return(:openai)
    allow(PWN::AI::OpenAI).to receive(:chat_with_tools).and_raise('profile routing was not applied')
    expect(PWN::AI::Ollama).to receive(:chat_with_tools).with(hash_including(model: 'fixture-local', temp: 0.2)).and_return(
      choices: [{ message: { role: 'assistant', content: 'verified' } }]
    )
    result = PWN::AI::Agent::Loop.send(:call_engine, messages: [{ role: 'user', content: 'Check fixture' }], tools: [])
    expect(result[:content]).to eq('verified')
  ensure
    Thread.current[:pwn_request_runtime] = previous
  end

  it 'routes a profile fallback without changing global configuration and records the response' do
    profiles = { first: { provider: 'openai', model: 'first-model', fallback: ['backup'] }, backup: { provider: 'ollama', model: 'backup-model', temperature: 0.2 } }
    runtime = described_class.new(request: 'Check fixture', session_id: 'runtime', profile: 'first', profiles: profiles, artifact_root: @tmp)
    seen = []
    response = runtime.call(messages: [{ role: 'user', content: 'Check fixture' }], tools: []) do |messages, route|
      seen << route
      expect(messages.last[:content]).to eq('Check fixture')
      raise Errno::ECONNREFUSED if route[:provider] == :openai

      { role: 'assistant', content: 'verified' }
    end
    expect(seen.map { |row| row[:model] }).to eq(%w[first-model backup-model])
    expect(response[:content]).to eq('verified')
    rows = PWN::SessionTrace.read(session_id: 'runtime')
    expect(rows.map { |row| row['event'] }).to eq(%w[request response])
    expect(rows.last['model']).to eq('backup-model')
  end

  it 'records original tool arguments and spills large output with an artifact reference' do
    runtime = described_class.new(request: 'Check fixture', session_id: 'runtime', artifact_root: @tmp, tool_cap: 1024)
    call = { id: 'call1', function: { name: 'shell', arguments: '{"command":"printf fixture"}' } }
    runtime.tool_call(call)
    compact = runtime.tool_result(call, 'x' * 9000)
    expect(compact.bytesize).to be <= 1024
    expect(compact).to include('Raw artifact:')
    rows = PWN::SessionTrace.read(session_id: 'runtime')
    expect(rows.find { |row| row['event'] == 'tool_call' }.dig('data', 'arguments', 'command')).to eq('printf fixture')
    expect(rows.last.dig('data', 'content').length).to eq(9000)
  end
end
