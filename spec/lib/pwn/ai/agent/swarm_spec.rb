# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe 'Swarm serialization nesting' do
  it 'rejects deep and cyclic values with a bounded JSON error and preserves symbols and shared branches' do
    cycle = {}
    cycle[:self] = cycle
    deep = :leaf
    10_000.times { deep = [deep] }
    [cycle, deep].each do |value|
      expect { PWN::AI::Agent::Swarm.send(:deep_stringify, hash: value) }.to raise_error(JSON::NestingError, /nesting limit/)
    end
    shared = { role: :reviewer }
    expect(PWN::AI::Agent::Swarm.send(:deep_stringify, hash: [shared, shared])).to eq([{ 'role' => 'reviewer' }] * 2)
    expect(shared).to eq(role: :reviewer)
    boundary = :leaf
    100.times { boundary = [boundary] }
    expect(JSON.generate(PWN::AI::Agent::Swarm.send(:deep_stringify, hash: boundary))).to eq(JSON.generate(boundary))
    expect { PWN::AI::Agent::Swarm.send(:deep_stringify, hash: [boundary]) }.to raise_error(JSON::NestingError)
  end
end

describe PWN::AI::Agent::Swarm do
  before do
    @swarm_home = Dir.mktmpdir('pwn-swarm-spec')
    allow(Dir).to receive(:home).and_return(@swarm_home)
    stub_const('PWN::AI::Agent::Swarm::AGENTS_FILE', File.join(@swarm_home, 'agents.yml'))
    stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(@swarm_home, 'swarm'))
    # Sessions may have been loaded before Dir.home was stubbed by this spec.
    stub_const('PWN::Sessions::SESSIONS_DIR', File.join(@swarm_home, 'sessions'))
    stub_const('PWN::Env', { ai: { active: 'openai', agent: { max_iters: 90 } } })
    @swarm_overrides = %i[pwn_swarm_engine pwn_swarm_model pwn_swarm_depth pwn_swarm_id pwn_swarm_honesty].to_h do |key|
      [key, Thread.current[key]]
    end
  end

  after do
    @swarm_overrides.each { |key, value| Thread.current[key] = value }
    FileUtils.remove_entry(@swarm_home)
  end

  it 'persists the exact model identifier in the global persona registry' do
    model = ' Vendor/Model-V2:Q4_K_M '
    out = described_class.spawn(name: 'reviewer', role: 'review', model: model)
    expect(out[:persona][:model]).to eq(model)
    expect(YAML.safe_load_file(out[:file])['reviewer']['model']).to eq(model)
    expect(described_class.personas[:reviewer][:model]).to eq(model)
  end

  it 'treats missing, blank, and non-string models as provider defaults' do
    [nil, '', " \t\n", 123, false, :Model, ['Model'], { id: 'Model' }].each do |model|
      row = described_class.send(:normalize_persona, persona: { model: model })
      expect(row[:model]).to be_nil
    end
    expect(described_class.send(:normalize_persona, persona: {})[:model]).to be_nil
  end

  it 'scopes persona model and engine without mutating global configuration' do
    original = Marshal.load(Marshal.dump(PWN::Env))
    Thread.current[:pwn_swarm_engine] = 'grok'
    Thread.current[:pwn_swarm_model] = 'Parent-Model'
    result = described_class.send(:with_persona_env, persona: { engine: :ollama, model: 'Child:Q4', max_iters: 3 }) do
      expect(Thread.current[:pwn_swarm_model]).to eq('Child:Q4')
      expect(Thread.current[:pwn_swarm_engine]).to eq('ollama')
      expect(PWN::Env).to eq(original)
      :reply
    end
    expect(result).to eq(:reply)
    expect(Thread.current[:pwn_swarm_engine]).to eq('grok')
    expect(Thread.current[:pwn_swarm_model]).to eq('Parent-Model')
    expect(PWN::Env).to eq(original)
  end

  it 'restores nested overrides on exceptions while omitted models use provider defaults' do
    Thread.current[:pwn_swarm_engine] = 'openai'
    Thread.current[:pwn_swarm_model] = 'Root-Model'
    described_class.send(:with_persona_env, persona: { engine: :anthropic, model: 'Outer-Model' }) do
      expect do
        described_class.send(:with_persona_env, persona: {}) do
          expect(Thread.current[:pwn_swarm_engine]).to eq('anthropic')
          expect(Thread.current[:pwn_swarm_model]).to be_nil
          raise 'child failed'
        end
      end.to raise_error(RuntimeError, 'child failed')
      expect(Thread.current[:pwn_swarm_engine]).to eq('anthropic')
      expect(Thread.current[:pwn_swarm_model]).to eq('Outer-Model')
    end
    expect(Thread.current[:pwn_swarm_engine]).to eq('openai')
    expect(Thread.current[:pwn_swarm_model]).to eq('Root-Model')
  end

  it 'restores unset overrides when a persona raises' do
    Thread.current[:pwn_swarm_engine] = nil
    Thread.current[:pwn_swarm_model] = nil
    expect do
      described_class.send(:with_persona_env, persona: { engine: :grok, model: 'Child' }) { raise 'failed' }
    end.to raise_error(RuntimeError, 'failed')
    expect(Thread.current[:pwn_swarm_engine]).to be_nil
    expect(Thread.current[:pwn_swarm_model]).to be_nil
  end

  it 'keeps concurrent persona selections isolated with no transient global writes' do
    ready = Queue.new
    release = Queue.new
    original = Marshal.load(Marshal.dump(PWN::Env))
    selections = [{ engine: :ollama, model: 'Local:Q4' }, { engine: :anthropic, model: 'Remote-V2' }]
    workers = selections.map do |persona|
      Thread.new do
        selected = described_class.send(:with_persona_env, persona: persona.merge(max_iters: 3)) do
          ready << true
          release.pop
          [Thread.current[:pwn_swarm_engine], Thread.current[:pwn_swarm_model]]
        end
        [selected, Thread.current[:pwn_swarm_engine], Thread.current[:pwn_swarm_model]]
      end
    end
    begin
      selections.each { ready.pop }
      expect(PWN::Env).to eq(original)
    ensure
      selections.each { release << true }
      results = workers.map(&:value)
    end
    expect(results).to eq([[['ollama', 'Local:Q4'], nil, nil], [%w[anthropic Remote-V2], nil, nil]])
    expect(PWN::Env).to eq(original)
  end

  it 'selects models without needing mutable global AI configuration' do
    [nil, {}, { ai: { active: 'openai' }.freeze }.freeze].each do |env|
      stub_const('PWN::Env', env)
      described_class.send(:with_persona_env, persona: { engine: :ollama, model: 'Local:Q4' }) do
        expect(Thread.current[:pwn_swarm_engine]).to eq('ollama')
        expect(Thread.current[:pwn_swarm_model]).to eq('Local:Q4')
      end
      expect(PWN::Env).to equal(env)
    end
  end

  it 'loads ephemeral model overrides without changing the global persona model' do
    described_class.spawn(name: 'reviewer', role: 'global review', model: 'Global-V1')
    out = described_class.spawn(name: 'reviewer', role: 'local review', model: ' Local/V2:Q4 ', swarm_id: 'lab', ephemeral: true)
    expect(out[:ephemeral]).to eq(true)
    expect(YAML.safe_load_file(out[:file])['reviewer']['model']).to eq(' Local/V2:Q4 ')
    expect(described_class.personas(swarm_id: 'lab')[:reviewer][:model]).to eq(' Local/V2:Q4 ')
    expect(described_class.personas[:reviewer][:model]).to eq('Global-V1')
  end

  it 'loads legacy and invalid YAML models as provider defaults' do
    File.write(described_class::AGENTS_FILE, YAML.dump(
                                               'legacy' => { 'role' => 'review' },
                                               'blank' => { 'role' => 'review', 'model' => " \t" },
                                               'numeric' => { 'role' => 'review', 'model' => 123 }
                                             ))
    expect(described_class.personas.values.map { |persona| persona[:model] }).to eq([nil, nil, nil])
  end

  it 'dispatches loaded persona selection to the nested loop and restores the caller' do
    described_class.spawn(name: 'reviewer', role: 'review', engine: :ollama, model: 'Local-V2:Q4', swarm_id: 'lab')
    allow(described_class).to receive(:persona_session).and_return('isolated-session')
    allow(described_class).to receive(:build_persona_prompt).and_return('Review carefully')
    allow(described_class).to receive(:child_inbox).and_return(finding_ids: [], artifact_shas: [])
    Thread.current[:pwn_swarm_engine] = 'grok'
    Thread.current[:pwn_swarm_model] = 'Caller'
    allow(PWN::AI::Agent::Loop).to receive(:debug_progress)
    allow(PWN::AI::Agent::Loop).to receive(:publish_usage)
    expect(PWN::AI::Ollama).to receive(:chat_with_tools)
      .with(hash_including(model: 'Local-V2:Q4'))
      .and_return(assistant_message: { role: 'assistant', content: 'reviewed' })
    expect(PWN::AI::Agent::Loop).to receive(:run).with(hash_including(nested: true, request: 'inspect')) do
      expect(Thread.current[:pwn_swarm_engine]).to eq('ollama')
      expect(Thread.current[:pwn_swarm_model]).to eq('Local-V2:Q4')
      expect(PWN::Env[:ai][:active]).to eq('openai')
      PWN::AI::Agent::Loop.send(:call_engine, messages: [{ role: 'user', content: 'inspect' }], tools: [])[:content]
    end
    expect(described_class.ask(name: 'reviewer', request: 'inspect', swarm_id: 'lab')[:reply]).to eq('reviewed')
    expect(Thread.current[:pwn_swarm_engine]).to eq('grok')
    expect(Thread.current[:pwn_swarm_model]).to eq('Caller')
  end

  it 'documents the optional spawn model and provider-default fallback' do
    expect { described_class.help }.to output(/model: 'optional - exact model identifier \(defaults to selected provider model\)'/).to_stdout
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Swarm
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Swarm
    expect(help_response).to respond_to :help
  end

  it 'exposes the core orchestration API' do
    %i[personas spawn retire create list ask debate broadcast bus_append bus_tail
       pack_specialist child_inbox child_honesty view_graph claim honesty_unmet].each do |m|
      expect(PWN::AI::Agent::Swarm).to respond_to m
    end
  end

  it 'normalizes personas loaded from AGENTS_FILE without raising' do
    expect { PWN::AI::Agent::Swarm.personas }.not_to raise_error
  end

  it 'enforces the recursion depth guard' do
    Thread.current[:pwn_swarm_depth] = 999
    expect do
      PWN::AI::Agent::Swarm.ask(name: PWN::AI::Agent::Swarm.personas.keys.first || :__none, request: 'x')
    end.to raise_error(StandardError)
  ensure
    Thread.current[:pwn_swarm_depth] = nil
  end

  it 'text_only / empty toolsets strip tools so a reviewer cannot open browsers' do
    src = File.read(described_class.method(:ask).source_location.first)
    expect(src).to match(/text_only/)
    expect(src).to match(/core_only:\s*empty_tools/)
  end

  it 'does not leak child_filed_nothing honesty from a text_only reviewer into the parent' do
    described_class.spawn(name: 'pwn_red_team', role: 'review', toolsets: %w[pwn terminal extrospection])
    Thread.current[:pwn_swarm_honesty] = nil
    Thread.current[:pwn_swarm_id] = nil
    allow(PWN::AI::Agent::Loop).to receive(:run) do |options|
      expect(PWN::Sessions.active?(session_id: options[:session_id])).to be(true)
      'Step 1 is most likely to fail.'
    end
    described_class.ask(
      name: 'pwn_red_team',
      request: 'GOAL: summarize the conversation of this session.',
      text_only: true
    )
    expect(PWN::Sessions.sessions_dir).to eq(File.join(@swarm_home, 'sessions'))
    expect(PWN::Sessions.list(include_hidden: true).length).to eq(1)
    expect(PWN::Sessions.active?(session_id: PWN::Sessions.list(include_hidden: true).first[:id])).to be(false)
    expect(PWN::Sessions.list(include_hidden: true).map { |session| session[:path] }).to all(start_with(File.join(@swarm_home, 'sessions', '')))
    expect(described_class.honesty_unmet).to eq([])
    expect(Array(Thread.current[:pwn_swarm_honesty])).to eq([])
    expect(Thread.current[:pwn_swarm_id]).to be_nil
  end

  it 'maps several ports and returns a merged result set' do
    rows = described_class.map_targets(targets: '127.0.0.1', ports: '1,9,22,80')
    expect(rows.length).to eq(4)
    expect(rows.map { |r| r[:port] }.uniq.length).to eq(4)
  end

  it 'allows only one live claim per unit' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      a = described_class.claim(unit: '10.0.0.5:recon', agent_id: 'a', ttl: 60, engagement_id: 'lab')
      b = described_class.claim(unit: '10.0.0.5:recon', agent_id: 'b', ttl: 60, engagement_id: 'lab')
      expect(a[:ok]).to eq(true)
      expect(b[:ok]).to eq(false)
    end
  end

  it 'packs specialists to at most three skills and strips swarm unless orchestrator' do
    packed = described_class.pack_specialist(name: 'xss', skills: %w[xss sqli ssrf auth], toolsets: %w[pwn swarm terminal])
    expect(packed[:skills].length).to eq(3)
    expect(packed[:toolsets]).not_to include('swarm')
    orch = described_class.pack_specialist(name: 'lead', skills: %w[recon], toolsets: %w[swarm pwn], orchestrator: true)
    expect(orch[:toolsets]).to include('swarm')
  end

  it 'spills long bus rows to the artifact store and keeps a short content plus ref' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'art'))
      s = described_class.create(topic: 'bus')
      body = 'P' * 800
      row = described_class.bus_append(swarm_id: s[:swarm_id], from: :red, content: body)
      expect(row[:content].bytesize).to be <= 400
      expect(row[:sha256]).to match(/\A[0-9a-f]{64}\z/)
      expect(row[:ref].to_s).not_to be_empty
    end
  end

  it 'refuses ask when the work unit is already claimed' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      stub_const('PWN::AI::Agent::Swarm::AGENTS_FILE', File.join(dir, 'agents.yml'))
      described_class.spawn(name: 'red', role: 'recon')
      described_class.claim(unit: '10.0.0.5:recon', agent_id: 'other', ttl: 600, engagement_id: 'lab')
      out = described_class.ask(name: 'red', request: 'recon 10.0.0.5', unit: '10.0.0.5:recon', engagement_id: 'lab')
      expect(out[:ok]).to eq(false)
      expect(out[:error]).to eq('claim_held')
    end
  end

  it 'child inbox lists finding ids from Findings, not reply prose' do
    allow(PWN::Plugins::Findings).to receive(:report).and_return(
      [{ id: 'deadbeef', session_id: 'sess-1', title: 'xss' }]
    )
    allow(PWN::Plugins::ArtifactRegistry).to receive(:list).and_return([])
    box = described_class.child_inbox(session_id: 'sess-1', name: 'red')
    expect(box[:finding_ids]).to eq(['deadbeef'])
  end

  it 'flags child honesty gap when pwn toolset filed nothing' do
    allow(described_class).to receive(:child_inbox).and_return(finding_ids: [], artifact_shas: [], coverage: [])
    h = described_class.child_honesty(name: 'xss', toolsets: %w[pwn], session_id: 's')
    expect(h[:gap]).to eq('child_filed_nothing')
  end

  it 'view_graph lists personas and live claims' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      s = described_class.create(topic: 'g')
      File.write(File.join(dir, 'swarm', s[:swarm_id], 'personas.json'), JSON.generate('red' => 'sess'))
      described_class.claim(unit: 'h1:recon', agent_id: 'red', ttl: 60, engagement_id: s[:swarm_id])
      g = described_class.view_graph(swarm_id: s[:swarm_id])
      expect(g[:agents].map { |a| a[:name] }).to include('red')
      expect(g[:claims].any? { |c| c[:unit] == 'h1:recon' }).to eq(true)
    end
  end

  it 'stores ephemeral personas under the swarm dir, not the host agents.yml' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(dir, 'swarm'))
      stub_const('PWN::AI::Agent::Swarm::AGENTS_FILE', File.join(dir, 'agents.yml'))
      s = described_class.create(topic: 'eph')
      described_class.spawn(name: 'xss', role: 'xss only', swarm_id: s[:swarm_id], ephemeral: true)
      expect(File).not_to exist(File.join(dir, 'agents.yml'))
      expect(described_class.personas(swarm_id: s[:swarm_id]).keys.map(&:to_s)).to include('xss')
    end
  end

  it 'broadcast fans out with threads' do
    src = File.read(described_class.method(:broadcast).source_location.first)
    expect(src).to match(/Thread\.new/)
  end

  it 'ask passes nested: true so nested Loop.run does not write the RN footer' do
    src = File.read(described_class.method(:ask).source_location.first)
    expect(src).to match(/nested:\s*true/)
  end

  it 'migrate_personas empties stock escalator tools and adds pwn to scribe' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'agents.yml')
      File.write(path, <<~YML)
        ---
        red:
          role: keep
          engine: grok
          toolsets: [terminal, pwn]
          max_iters: 25
        scribe:
          role: report
          engine: grok
          toolsets: [memory, skills, learning, sessions]
          max_iters: 10
        escalator:
          role: hint
          engine: grok
          toolsets: [terminal, pwn, memory]
          max_iters: 8
      YML
      out = described_class.migrate_personas(path: path)
      expect(out[:changed]).to eq(true)
      expect(out[:patched]).to include('escalator', 'scribe')
      again = described_class.migrate_personas(path: path)
      expect(again[:changed]).to eq(false)
      loaded = described_class.send(:load_personas_file, path: path)
      expect(loaded[:escalator][:toolsets]).to eq([])
      expect(loaded[:scribe][:toolsets]).to include('pwn')
      expect(loaded[:red][:engine]).to eq(:grok)
      expect(loaded[:red][:toolsets]).to eq(%w[terminal pwn])
    end
  end
end
