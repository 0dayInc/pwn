# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::TurnFinalizer do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'does not promote prose abbreviations into output filenames' do
    request = 'Generate a report, i.e. a PDF; save /tmp/container_pentest-PWN.pdf'
    expect(described_class.output_paths(request: request)).to eq(['/tmp/container_pentest-PWN.pdf'])
    expect(described_class.output_paths(request: 'Write `i.e`')).to eq([File.expand_path('i.e')])
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
    it 'rejects observed wrong bytes for an explicit exact literal requirement' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'result.txt')
        request = "Create #{path} containing exactly alpha followed by newline and verify it."
        described_class.commit_artifacts!(request: request)
        before = described_class.artifact_snapshot(paths: [path])
        File.write(path, "wrong\n")
        observed = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
        row = described_class.arbitrate(request: request, messages: [{ role: 'tool', artifact_observations: observed }])
        expect(row[:complete]).to be false
        expect(row[:unmet]).to include(criterion: 'artifact_content_mismatch', detail: path)
        before = described_class.artifact_snapshot(paths: [path])
        File.write(path, "alpha\n")
        observed = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
        expect(described_class.arbitrate(request: request, messages: [{ role: 'tool', artifact_observations: observed }])[:complete]).to be true
      end
    ensure
      Thread.current[:pwn_artifact_contract] = nil
    end

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
      expect(described_class.output_paths(request: 'Are you able to mv foo to /tmp/test?')).to eq(['/tmp/test'])
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

    it 'does not grant write access to a comparison operand before an explicit destination' do
      request = 'Compare ./left.txt to ./right.txt and save the differences to ./result.txt.'
      expect(described_class.output_paths(request: request)).to eq([File.expand_path('./result.txt')])
      expect(described_class.output_paths(request: 'Generate a summary from ./left.txt into ./result.txt.')).to eq([File.expand_path('./result.txt')])
    end

    it 'retains an explicit destination for a document transformation' do
      expect(described_class.output_paths(request: 'Summarize ./input.txt into ./output.txt.')).to eq([File.expand_path('./output.txt')])
      expect(described_class.output_paths(request: 'Append the answer to ./output.txt.')).to eq([File.expand_path('./output.txt')])
    end

    it 'treats an extraction source as input and only its named destination as output' do
      expect(described_class.output_paths(request: 'Extract names from ./records.json.')).to be_empty
      expect(described_class.output_paths(request: 'Extract names from ./records.json into ./names.txt.')).to eq([File.expand_path('./names.txt')])
    end
  end

  it 'accepts an observed one-byte output, but not an empty or unobserved output' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'flag.txt')
      request = "Write #{path}"
      before = described_class.artifact_snapshot(paths: [path])
      File.write(path, '')
      observe = lambda do
        observed = described_class.observe_artifacts(paths: [path], before: before, effect: :write, success: true)
        described_class.arbitrate(request: request, messages: [{ role: 'tool', artifact_observations: observed }])
      end
      expect(observe.call[:complete]).to be(false)
      File.write(path, 'Y')
      expect(described_class.arbitrate(request: request, messages: [])[:complete]).to be(false)
      expect(observe.call[:complete]).to be(true)
    end
  end

  describe 'local document reads' do
    let(:reader) { described_class::InputPages }

    it 'binds local file operands without treating URLs or additional actions as plain reads' do
      Dir.mktmpdir do |dir|
        expect(reader.for_request(request: 'Read the file notes.txt.', cwd: dir)&.unmet).to eq(["input_unread:#{dir}/notes.txt (next byte 0)"])
        expect(reader.for_request(request: 'Read "https://example.invalid/notes.txt".', cwd: dir)).to be_nil
        expect(reader.for_request(request: 'Read ./notes.txt and save a copy.', cwd: dir)).to be_nil
      end
    end

    it 'requires complete observed pages of the named inputs, not a preview, a missing page, or another file' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'input.txt')
        other = File.join(dir, 'other.txt')
        File.write(path, 'abcd')
        File.write(other, 'else')
        pages = reader.for_request(request: 'Read ./input.txt.', cwd: dir)
        observe = lambda do |**args|
          page = PWN::Plugins::ArtifactRegistry.read_page(**args)
          pages.observe('artifact_read', JSON.generate(success: true, effect: 'read', result: page))
        end
        observe.call(path: other)
        observe.call(path: path, grep: 'abcd')
        observe.call(path: path, offset: 2, length: 2)
        expect(pages.unmet).to eq(["input_unread:#{path} (next byte 0)"])
        observe.call(path: path, offset: 0, length: 1)
        expect(pages.unmet).to eq(["input_unread:#{path} (next byte 1)"])
        observe.call(path: path, offset: 1, length: 1)
        expect(pages.unmet).to be_empty
      end
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
    expect(source).to include('run_turn(options)')
    run = source[source.index('private_class_method def self.run_turn(opts = {})')..]
    expect(run.index('commit_artifacts!')).to be < run.index('cheap =')
    expect(run).to include('allow_text_only = steering.nil? && required_artifacts.empty?', 'cheap = allow_text_only')
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

describe PWN::AI::Agent::TurnFinalizer, 'host artifact readback' do
  around do |example|
    previous = Thread.current[:pwn_artifact_contract]
    Thread.current[:pwn_artifact_contract] = nil
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  ensure
    Thread.current[:pwn_artifact_contract] = previous
  end

  it 'never opens a FIFO or symlink for content, even alongside a declared regular file' do
    fifo, link, file = %w[stream alias actual.txt].map { |name| File.join(@dir, name) }
    File.mkfifo(fifo)
    File.write(file, 'verified')
    File.symlink(file, link)
    described_class.commit_artifacts!(request: "Write #{fifo} and #{link} and #{file}")
    allow(File).to receive(:open).and_call_original
    expect(File).not_to receive(:open).with(fifo, any_args)
    expect(File).not_to receive(:open).with(link, any_args)
    snapshot = described_class.artifact_snapshot(paths: [fifo, link, file])
    expect(snapshot.keys).to eq([file])
    expect(snapshot.fetch(file)).to include(sha256: Digest::SHA256.hexdigest('verified'))
  end

  it 'keeps a denied baseline distinct from a missing file without losing evidence for other outputs' do
    denied, output = %w[denied.txt output.txt].map { |name| File.join(@dir, name) }
    File.write(denied, 'unchanged')
    request = "Write #{denied} and #{output}"
    paths = described_class.commit_artifacts!(request: request).fetch(:required_artifacts)
    allow(File).to receive(:open).and_call_original
    allow(File).to receive(:open).with(denied, any_args).and_raise(Errno::EACCES)
    before = described_class.artifact_snapshot(paths: paths)
    expect(before).to eq(output => nil)

    allow(File).to receive(:open).with(denied, any_args).and_call_original
    File.write(output, 'delivered')
    observed = described_class.observe_artifacts(paths: paths, before: before, success: true, effect: :write)
    expect(observed.keys).to eq([output])
    verdict = described_class.arbitrate(request: request, messages: [{ role: 'tool', artifact_observations: observed }])
    expect(verdict[:unmet]).to include(criterion: 'readback_missing', detail: denied)
  end

  it 'does not sample or recheck paths outside the active output contract' do
    unrelated = File.join(@dir, 'notes.txt')
    File.write(unrelated, 'not a deliverable')
    contract = described_class.commit_artifacts!(request: 'List the document names.')
    expect(contract[:required_artifacts]).to be_empty
    expect(File).not_to receive(:open).with(unrelated, any_args)
    expect(described_class.artifact_snapshot(paths: [unrelated])).to be_empty
    prior = { unrelated => { artifact_turn_id: contract[:id] } }
    expect(described_class.evidence_ledger(messages: [{ role: 'tool', artifact_observations: prior }])).to be_empty
  end

  it 'does not reopen a receipt for a different file when checking an output outside an active turn' do
    prior, expected = %w[old.txt new.txt].map { |name| File.join(@dir, name) }
    File.write(prior, 'earlier output')
    receipt = described_class.artifact_snapshot(paths: [prior])
    allow(File).to receive(:open).and_call_original
    verdict = described_class.arbitrate(request: "Write #{expected}", messages: [{ role: 'tool', artifact_observations: receipt }])
    expect(File).not_to have_received(:open).with(prior, any_args)
    expect(verdict[:ledger]).to be_empty
    expect(verdict[:unmet]).to include(criterion: 'artifact_missing', detail: expected)
  end
end

describe PWN::AI::Agent::TurnFinalizer, 'default skill directory evidence' do
  include_context 'pwn tmp sandbox'

  around do |example|
    previous_home = Dir.home if ENV.key?('HOME')
    previous_runtime = Thread.current[:pwn_request_runtime]
    previous_contract = Thread.current[:pwn_artifact_contract]
    example.run
  ensure
    ENV['HOME'] = previous_home
    Thread.current[:pwn_request_runtime] = previous_runtime
    Thread.current[:pwn_artifact_contract] = previous_contract
  end

  before { ENV['HOME'] = @tmp }

  let(:library) { File.join(@tmp, '.pwn', 'skills') }
  let(:skill) { File.join(library, 'meeting-notes') }
  let(:entry) { File.join(skill, 'SKILL.md') }
  let(:request) { 'Save the meeting notes skill under ~/.pwn/skills' }

  def bind_turn(text = request)
    runtime = PWN::AI::Agent::RequestRuntime.new(request: text, session_id: 'local-skill', artifact_root: @tmp, trace: false, retrieve: false)
    Thread.current[:pwn_request_runtime] = runtime
    Thread.current[:pwn_artifact_contract] = runtime.contract
    runtime
  end

  # Exercise the real controller's successful/failed action boundaries. The
  # external shell is not invoked; its harmless file operation is native Ruby.
  def action(runtime, id = 'save-notes', status: 0)
    runtime.execute_tool(name: 'shell', args: { fixture: id }, effect: :write, action_id: id) do
      yield
      { exit: status }
    end
  end

  it 'verifies a new nonempty document inside the named library without publishing its contents' do
    runtime = bind_turn
    action(runtime) do
      FileUtils.mkdir_p(skill)
      File.write(entry, 'private meeting procedure')
    end
    result = described_class.arbitrate(request: request)
    expect(result[:unmet]).to be_empty
    expect(result[:complete]).to be(true)
    expect(runtime.observations.fetch(library)[:action_id]).to eq('save-notes')
    expect(result[:ledger].to_json).not_to include('private meeting procedure')
  end

  it 'does not sample unrequested paths from tool arguments on a directory delivery' do
    bind_turn
    FileUtils.mkdir_p(skill)
    unrelated = File.join(@tmp, 'private.txt')
    File.write(unrelated, 'unrequested contents')
    File.symlink(unrelated, entry)
    snapshot = described_class.artifact_snapshot(paths: [library, entry, unrelated])
    expect(snapshot.values_at(entry, unrelated)).to eq([nil, nil])
  end

  it 'does not certify a directory, empty entry, scripts, unchanged document or timestamp-only change' do
    runtime = bind_turn
    action(runtime, 'mkdir') { FileUtils.mkdir_p(File.join(skill, 'scripts')) }
    action(runtime, 'empty') { File.write(entry, '') }
    action(runtime, 'script') { File.write(File.join(skill, 'scripts', 'SKILL.md'), 'not an entry') }
    File.write(entry, 'already present outside the action')
    action(runtime, 'unchanged') { File.stat(entry) }
    action(runtime, 'touch') { File.utime(Time.at(100), Time.at(100), entry) }
    expect(runtime.observations).to be_empty
    expect(described_class.arbitrate(request: request)[:complete]).to be(false)
  end

  it 'checks every changed document of one skill without opening other catalog bodies' do
    runtime = bind_turn
    refs = File.join(skill, 'references')
    FileUtils.mkdir_p(refs)
    File.write(File.join(refs, 'untouched.md'), 'unrelated meeting records')
    allow(File).to receive(:open).and_call_original
    expect(File).not_to receive(:open).with(a_string_ending_with('/untouched.md'), any_args)
    reference = File.join(refs, 'format.md')
    action(runtime) do
      File.write(entry, '# Meeting notes')
      File.write(reference, 'List decisions and owners.')
    end
    result = described_class.arbitrate(request: request)
    expect(result[:complete]).to be(true)
    documents = result[:ledger].fetch(library).fetch(:evidence).fetch(:skill_documents)
    expect(documents.map { |doc| doc[:path] }).to contain_exactly('meeting-notes/SKILL.md', 'meeting-notes/references/format.md')
    expect(documents.last[:sha256]).to eq(Digest::SHA256.file(reference).hexdigest)
    File.write(reference, 'different')
    expect(described_class.arbitrate(request: request)[:complete]).to be(false)
  end

  it 'verifies a size-changing edit in an operator-named references directory' do
    refs = File.join(skill, 'references')
    FileUtils.mkdir_p(refs)
    reference = File.join(refs, 'format.txt')
    File.write(reference, 'rough')
    runtime = bind_turn('Save the reference under ~/.pwn/skills/meeting-notes/references')
    action(runtime) { File.write(reference, 'Write down decisions and owners.') }
    expect(described_class.arbitrate(request: runtime.request)).to include(complete: true, unmet: [])
    expect(runtime.observations.fetch(refs)[:skill_documents].first[:path]).to eq('format.txt')
  end

  it 'does not credit a failed write to a later successful no-op' do
    runtime = bind_turn
    stale = nil
    action(runtime, 'failed', status: 1) do
      stale = described_class.artifact_snapshot(paths: [library])
      FileUtils.mkdir_p(skill)
      File.write(entry, 'partial output')
    end
    action(runtime, 'later') do
      replay = described_class.observe_artifacts(paths: [library], before: stale, effect: :write, success: true, action_id: 'later', tool: 'shell')
      expect(replay).to be_empty
    end
    claim = { role: 'tool', content: { success: true, effect: 'write', path: entry }.to_json }
    expect(described_class.arbitrate(request: request, messages: [claim])[:complete]).to be(false)
    expect(runtime.observations).to be_empty
  end

  it 'rejects a prior receipt and tool-supplied receipt fields even if restamped for this turn' do
    old = bind_turn
    action(old) do
      FileUtils.mkdir_p(skill)
      File.write(entry, '# Notes')
    end
    receipt = old.observations.fetch(library)
    current = bind_turn
    action(current) { File.stat(entry) }
    [receipt, receipt.merge(artifact_turn_id: current.contract[:id])].each do |row|
      message = { role: 'tool', artifact_observations: { library => row }, content: row.to_json }
      expect(described_class.arbitrate(request: request, messages: [message])[:complete]).to be(false)
    end
  end

  it 'does not transfer a directory receipt to a nested caller or a different request' do
    previous = Thread.current[:pwn_loop_nested]
    runtime = bind_turn
    action(runtime) do
      FileUtils.mkdir_p(skill)
      File.write(entry, '# Notes')
    end
    expect(described_class.arbitrate(request: request)[:complete]).to be(true)
    expect(described_class.arbitrate(request: 'Save the other skill under ~/.pwn/skills')[:complete]).to be(false)
    Thread.current[:pwn_loop_nested] = true
    expect(described_class.arbitrate(request: request)[:complete]).to be(false)
  ensure
    Thread.current[:pwn_loop_nested] = previous
  end

  it 'refuses linked entries, linked ancestors and stale path replacements' do
    outside = File.join(@tmp, 'elsewhere')
    FileUtils.mkdir_p(outside)
    other = File.join(outside, 'SKILL.md')
    File.write(other, 'unrequested private data')
    runtime = bind_turn
    FileUtils.mkdir_p(skill)
    action(runtime, 'hardlink') { File.link(other, entry) }
    expect(runtime.observations).to be_empty
    File.unlink(entry)
    action(runtime, 'symlink') { File.symlink(other, entry) }
    expect(runtime.observations).to be_empty
    File.unlink(entry)
    action(runtime, 'real') { File.write(entry, '# Notes') }
    expect(described_class.arbitrate(request: request)[:complete]).to be(true)
    File.rename(skill, "#{skill}-saved")
    File.symlink(outside, skill)
    expect(described_class.arbitrate(request: request)[:complete]).to be(false)
  end

  it 'does not choose between different changed skills or accept an oversized or binary document' do
    runtime = bind_turn
    action(runtime, 'ambiguous') do
      [skill, File.join(library, 'other')].each do |dir|
        FileUtils.mkdir_p(dir)
        File.write(File.join(dir, 'SKILL.md'), '# Notes')
      end
    end
    action(runtime, 'oversized') { File.truncate(entry, 2 << 20) }
    action(runtime, 'binary') { File.binwrite(entry, "a\x00b") }
    expect(runtime.observations).to be_empty
    expect(described_class.arbitrate(request: request)[:complete]).to be(false)
  end

  it 'does not treat renaming a folder of unchanged documents as a new document write' do
    previous = File.join(library, 'previous')
    FileUtils.mkdir_p(previous)
    File.write(File.join(previous, 'SKILL.md'), '# Old notes')
    runtime = bind_turn
    action(runtime) { File.rename(previous, skill) }
    expect(described_class.arbitrate(request: request)[:complete]).to be(false)

    runtime = bind_turn('Save the notes under ~/.pwn/skills/meeting-notes')
    replacement = File.join(@tmp, 'replacement')
    FileUtils.mkdir_p(replacement)
    File.write(File.join(replacement, 'SKILL.md'), '# Other notes')
    action(runtime) do
      File.rename(skill, previous)
      File.rename(replacement, skill)
    end
    expect(described_class.arbitrate(request: runtime.request)[:complete]).to be(false)
  end

  it 'does not mistake an over-budget pre-write inventory for an empty directory' do
    stub_const('PWN::AI::Agent::TurnFinalizer::SkillDirectory::MAX_ENTRIES', 2)
    runtime = bind_turn
    FileUtils.mkdir_p(skill)
    extra = %w[a b].map { |n| File.join(skill, n) }
    extra.each { |path| File.write(path, 'existing') }
    action(runtime) do
      File.unlink(*extra)
      File.write(entry, '# Notes')
    end
    expect(runtime.observations).to be_empty
    expect(described_class.arbitrate(request: request)[:complete]).to be(false)
  end

  it 'preserves exact-file evidence and does not extend the rule to an ordinary directory' do
    FileUtils.mkdir_p(skill)
    runtime = bind_turn('Write the document to ~/.pwn/skills/meeting-notes/SKILL.md')
    File.write(entry, 'rough')
    action(runtime) { File.write(entry, 'final') }
    expect(described_class.arbitrate(request: runtime.request)[:complete]).to be(true)
    expect(runtime.observations.fetch(entry)).to include(head: 'final', tail: 'final')

    other = File.join(@tmp, 'skills')
    runtime = bind_turn("Save the meeting notes skill under #{other}")
    action(runtime) do
      FileUtils.mkdir_p(other)
      File.write(File.join(other, 'SKILL.md'), '# Notes')
    end
    expect(described_class.arbitrate(request: runtime.request)[:unmet]).to include(criterion: 'artifact_missing', detail: other)
  end

  it 'keeps an independently named file outstanding after the directory delivery succeeds' do
    other = File.join(@tmp, 'summary.md')
    runtime = bind_turn("#{request} and write #{other}")
    action(runtime) do
      FileUtils.mkdir_p(skill)
      File.write(entry, '# Notes')
    end
    result = described_class.arbitrate(request: runtime.request)
    expect(result[:ledger].keys).to contain_exactly(library)
    expect(result[:complete]).to be(false)
    expect(result[:unmet]).to eq([{ criterion: 'artifact_missing', detail: other }])
  end
end
