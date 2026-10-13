# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::Sessions do
  include_context 'pwn tmp sandbox'

  it 'rejects provider echoed placeholder titles without advancing summary provenance' do
    session = described_class.create
    sid = session[:id]
    described_class.append(session_id: sid, role: 'user', content: 'Explain session locking')
    allow(PWN::AI::Router).to receive(:summarize).and_return(JSON.generate(title: "pwn-ai session #{sid}", summary: 'Session locking explained'))
    original = described_class.metadata(session_id: sid)
    expect(described_class.refresh_title(session_id: sid)).to eq(original)
    expect(described_class.metadata(session_id: sid)).to eq(original)
  end

  it 'does not let repeated session listings create their own dependency pins' do
    allow(Dir).to receive(:home).and_return(@tmp)
    id = '20260708_225330_27490e1f'
    described_class.create(id: id)
    observer = described_class.create(id: '20260709_172057_49594079')
    25.times do
      listing = JSON.generate(described_class.list)
      File.open(observer[:path], 'a') { |file| file.puts(JSON.generate(role: 'tool', content: listing)) }
    end
    result = described_class.list.find { |row| row[:id] == id }
    expect(result[:dependencies]).to eq([])
    expect(result[:dependency_errors]).to eq([])
  end

  describe 'schema-aware dependency references' do
    let(:sid) { '20260708_225330_27490e1f' }
    let(:other) { '20260709_172057_49594079' }

    before do
      allow(Dir).to receive(:home).and_return(@tmp)
      FileUtils.mkdir_p(File.join(@tmp, '.pwn'))
    end

    def dependency_fixture(relative, value)
      path = File.join(Dir.home, '.pwn', relative)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, JSON.generate(value))
      path
    end

    {
      'learning.jsonl' => ->(id) { { session_id: id, details: 'evidence' } },
      'mistakes.json' => ->(id) { { signature: { sessions: [id], verified_sessions: [id] } } },
      'memory.json' => ->(id) { { "reflect_#{id}_1234abcd" => { value: 'lesson', category: 'lesson' } } },
      'memory.archive.json' => ->(id) { { "reflect_#{id}_1234abcd" => { value: 'lesson' } } },
      'open_goal.json' => ->(id) { { session_id: id } },
      'policy_traj.jsonl' => ->(id) { { session_id: id } },
      'findings.jsonl' => ->(id) { { session_id: id } },
      'jobs/123456abcdef.json' => ->(id) { { id: '123456abcdef', session_id: id } },
      'swarm/fixture/personas.json' => ->(id) { { critic: id } },
      'curriculum/log.jsonl' => ->(id) { { event: 'practice', data: [{ runs: [{ session_id: id }] }] } },
      'engagements/fixture/facts.jsonl' => ->(id) { { source_session: id } },
      'extrospection.json' => ->(id) { { observations: [{ source: 'auto_extrospect', tags: ['drift', id] }] } },
      'artifacts/manifest.jsonl' => ->(id) { { session: id } }
    }.each do |relative, build|
      it "retains the defined session reference in #{relative}, not incidental prose" do
        path = dependency_fixture(relative, build.call(sid))
        result = described_class.dependency_index
        expect(result[:dependencies].fetch(sid)).to eq([path])
        expect(result[:errors]).to eq([])
      end
    end

    it 'ignores prose, quoted JSON, arbitrary map keys and unrelated identifiers' do
      text = "See #{sid} and #{JSON.generate(session_id: sid)}"
      fixtures = {
        'learning.jsonl' => { session_id: "prefix#{sid}", task: text, details: { session_id: sid } },
        'mistakes.json' => { sid => { error: text, sample_args: { session_id: sid } } },
        'memory.json' => { sid => { value: { session_id: sid }, source: sid }, "not_reflect_#{sid}_1234abcd" => { value: text } },
        'policy.json' => { sid => { session_id: sid } },
        'preferences.jsonl' => { prompt: text, chosen: text, rejected: text, meta: { session_id: sid } },
        'reward_sentinel.json' => { window: [{ source: text }] },
        'skill_review.jsonl' => { request: text, path: sid },
        'curriculum_kpi.jsonl' => { summary: text },
        'extrospection.json' => { observations: [{ source: 'manual', tags: [sid], data: { session_id: sid } }] },
        'runs/fixture/checkpoints.jsonl' => { id: sid, result: { session_id: sid } },
        'missions/fixture.json' => { id: sid, request: text, run_id: sid, jobs: [sid] },
        'jobs/123456abcdef.json' => { id: sid, session_id: nil, command: text, env: { session_id: sid } },
        'swarm/fixture/bus.jsonl' => { from: sid, to: sid, content: { session_id: sid } },
        'swarm/fixture/solve.json' => { swarm_id: sid, records: [{ data: { session_id: sid } }] },
        'swarm/fixture/personas.json' => { sid => 'critic' },
        'curriculum/log.jsonl' => { event: 'critic', data: { flaw: text } },
        'curriculum/models.json' => { sid => text },
        'curriculum/cooldown.json' => { sid => { reason: text } },
        'engagements/fixture.json' => { name: sid, roe: text },
        'engagements/fixture/hosts.json' => { sid => { notes: text } },
        'engagements/fixture/scans/nmap-fixture.json' => { command: text },
        'engagements/fixture/binaries/abc/facts.json' => { strings_top: [text] },
        'engagements/fixture/recon/observations.jsonl' => { lead: text },
        'engagements/fixture/evidence.jsonl' => { finding_id: sid, path: "/tmp/#{sid}.jsonl" },
        'artifacts/manifest.jsonl' => { session: "#{sid}.extra", tags: [sid], source_path: "/tmp/#{sid}.jsonl" }
      }
      fixtures.each { |relative, value| dependency_fixture(relative, value) }
      expect(described_class.dependency_index).to eq(dependencies: {}, errors: [])
    end

    it 'recognizes only exact session-owned paths and exact structured evidence paths' do
      described_class.create(id: sid)
      transcript = File.join(described_class.sessions_dir, "#{sid}.jsonl")
      paths = []
      paths << dependency_fixture("artifacts/#{sid}/index.jsonl", { src: 'unrelated' })
      paths << dependency_fixture("artifacts/#{sid}/engagement-memory.json", { notes: other })
      paths << dependency_fixture('artifacts/manifest.jsonl', { source_path: transcript })
      paths << dependency_fixture('findings.jsonl', { evidence_paths: [transcript], poc_artifacts: [transcript] })
      paths << dependency_fixture('engagements/fixture/evidence.jsonl', { path: transcript })
      paths << dependency_fixture('engagements/evidence.jsonl', { path: transcript })
      paths << dependency_fixture('engagements/fixture/recon/observations.jsonl', { evidence_path: transcript })
      trace = File.join(described_class.sessions_dir, sid, 'trace.jsonl')
      FileUtils.mkdir_p(File.dirname(trace))
      File.write(trace, JSON.generate(event: 'tool_result', data: { session_id: other }))
      paths << trace
      paths << dependency_fixture("embeddings/#{sid}.db", {})
      dependency_fixture("embeddings/prefix-#{other}.db", {})
      result = described_class.dependency_index
      expect(result[:dependencies]).to eq(sid => paths.sort)
      expect(result[:errors]).to eq([])
    end

    it 'does not invent cross-session links in transcript metadata or tool payloads' do
      session = described_class.create(id: sid)
      File.write(session[:path], JSON.generate(role: 'tool', content: { session_id: other }, session_id: other))
      File.write(session[:path].sub('.jsonl', '.meta.json'), JSON.generate(id: sid, title: other, source: other, summary: JSON.generate(session_id: other)))
      expect(described_class.dependency_index).to eq(dependencies: {}, errors: [])
    end

    it 'reports unknown stores and malformed structural references without guessing' do
      paths = []
      paths << dependency_fixture('runs/fixture/future.json', { session_id: sid })
      paths << dependency_fixture('mistakes.json', { sig: { sessions: { session_id: sid } } })
      paths << dependency_fixture('learning.jsonl', { session_id: { id: sid } })
      paths << dependency_fixture('memory.json', [sid])
      paths << dependency_fixture('curriculum/log.jsonl', { event: 'practice', data: 'invalid' })
      result = described_class.dependency_index
      expect(result[:dependencies]).to eq({})
      expect(result[:errors]).to eq(paths.sort)
    end

    it 'does not treat an extensionless session-looking evidence path as a transcript' do
      dependency_fixture('findings.jsonl', { evidence_paths: [File.join(described_class.sessions_dir, sid)] })
      expect(described_class.dependency_index).to eq(dependencies: {}, errors: [])
    end

    it 'fails closed for null map entries, invalid JSON, unreadable stores and unsafe embeddings' do
      mistakes = dependency_fixture('mistakes.json', { signature: nil })
      learning = dependency_fixture('learning.jsonl', {})
      File.write(learning, '{')
      memory = dependency_fixture('memory.json', {})
      allow(File).to receive(:read).and_call_original
      allow(File).to receive(:read).with(memory).and_raise(Errno::EACCES)
      database = File.join(Dir.home, '.pwn', 'embeddings', "#{sid}.db")
      FileUtils.mkdir_p(database)
      result = described_class.dependency_index
      expect(result[:errors]).to eq([mistakes, learning, memory, database].sort)
    end

    it 'distinguishes swarm artifact IDs and unrelated observation tags from session provenance' do
      dependency_fixture('artifacts/manifest.jsonl', { session: sid, kind: 'swarm-bus' })
      dependency_fixture('extrospection.json', { observations: [{ source: 'auto_extrospect', tags: ['drift', 'unrelated', sid] }] })
      expect(described_class.dependency_index).to eq(dependencies: {}, errors: [])
    end

    it 'does not accept session ID substrings, whitespace or trailing newlines as references' do
      ["prefix#{sid}", "#{sid}suffix", " #{sid}", "#{sid}\n", sid.upcase, 'unrelated-session'].each do |value|
        dependency_fixture('learning.jsonl', { session_id: value })
        expect(described_class.dependency_index).to eq(dependencies: {}, errors: [])
      end
    end
  end
end

describe PWN::Sessions do
  include_context 'pwn tmp sandbox'

  it 'caps provisional titles at seven Unicode-whitespace words without shortening requests' do
    sid = described_class.create(id: 'seven_words')[:id]
    request = "Investigate\u00a0café\u2003login failures and repair expired certificates today"
    described_class.append(session_id: sid, content: request)
    title = 'Investigate café login failures and repair expired'
    expect(described_class.metadata(session_id: sid)[:title]).to eq(title)
    stored = JSON.parse(File.read(File.join(described_class.sessions_dir, "#{sid}.meta.json")))
    expect(stored['title']).to eq(title)
    expect(described_class.to_llm_messages(session_id: sid).last[:content]).to eq(request)
    expect(described_class.resolve(identifier: title)).to eq(sid)
  end

  it 'bounds summary titles but preserves the rolling summary and conversation' do
    sid = described_class.create(id: 'summary_cap')[:id]
    described_class.append(session_id: sid, content: 'Repair login')
    summary = 'Investigated login failures and repaired certificates while preserving rotation requirements. ' * 30
    allow(PWN::AI::Router).to receive(:summarize).and_return(JSON.generate(title: 'Investigate café login failures and repair expired certificates today', summary: summary))
    result = described_class.refresh_title(session_id: sid)
    expect(result[:title]).to eq('Investigate café login failures and repair expired')
    expect(result[:summary]).to eq(summary)
    expect(described_class.metadata(session_id: sid)).to eq(result)
    expect(described_class.resolve(identifier: result[:title])).to eq(sid)
  end

  it 'bounds explicit titles while preserving Unicode whitespace and internal quotes' do
    title = "Café\u00a0\"login\"  repair and test all seven"
    session = described_class.create(id: 'manual_cap', title: "#{title} extra words")
    expect(session[:meta][:title]).to eq(title)
    expect(described_class.resolve(identifier: "'#{title}'")).to eq(session[:id])
    expect(JSON.parse(File.read(File.join(described_class.sessions_dir, 'manual_cap.meta.json')))['title']).to eq(title)
  end

  it 'normalizes legacy metadata and transcript titles on read without rewriting history' do
    long = 'One two three four five six seven eight'
    session = described_class.create(id: 'legacy_cap')
    path = File.join(described_class.sessions_dir, 'legacy_cap.meta.json')
    stored = JSON.generate(title: long, title_source: 'summary', summary: 'Keep this complete summary.', summary_turns: 2)
    File.write(path, stored)
    transcript = File.binread(session[:path])
    expect(described_class.list.first[:title]).to eq('One two three four five six seven')
    expect(described_class.resolve(identifier: described_class.list.first[:title])).to eq(session[:id])
    expect(described_class.metadata(session_id: session[:id])[:summary]).to eq('Keep this complete summary.')
    expect(File.binread(path)).to eq(stored)
    expect(File.binread(session[:path])).to eq(transcript)
    File.delete(path)
    File.write(session[:path], JSON.generate(role: 'system', content: "Session started: #{long}"))
    expect(described_class.metadata(session_id: session[:id])[:title]).to eq('One two three four five six seven')
  end

  it 'exposes structured ambiguity candidates without changing persisted files' do
    sessions = %w[structured_a structured_b].map { |id| described_class.create(id: id, title: 'Same title') }
    originals = sessions.to_h { |session| [session[:path], File.binread(session[:path])] }
    expect { described_class.resolve(identifier: 'Same title') }.to raise_error(PWN::Sessions::AmbiguousTitle) { |error|
      expect(error).to be_a(ArgumentError)
      expect(error.identifier).to eq('Same title')
      expect(error.candidates.map { |row| row[:id] }).to contain_exactly('structured_a', 'structured_b')
      expect(error.candidates).to all(include(title: 'Same title', mtime: a_kind_of(String), lines: 1))
    }
    originals.each { |path, contents| expect(File.binread(path)).to eq(contents) }
  end

  it 'reports collisions after capping titles and always accepts stable ids' do
    %w[first second].each do |id|
      described_class.create(id: id, title: "One two three four five six seven #{id}")
    end
    expect { described_class.resolve(identifier: 'One two three four five six seven') }.to raise_error(ArgumentError, /Ambiguous.*first.*second|Ambiguous.*second.*first/)
    expect(described_class.resolve(identifier: 'first')).to eq('first')
    expect(described_class.resolve(identifier: 'second')).to eq('second')
  end

  it 'persists an early grounded title and resolves exact titles without changing ids' do
    session = described_class.create(id: 'title_test')
    described_class.append(session_id: session[:id], role: 'user', content: 'Investigate café "login" failures')
    row = described_class.list.find { |item| item[:id] == session[:id] }
    expect(row[:title]).to eq('Investigate café "login" failures')
    expect(described_class.resolve(identifier: row[:title])).to eq('title_test')
    expect(described_class.resolve(identifier: 'title_test')).to eq('title_test')
  end

  it 'evolves titles from a rolling overall summary, keeping recent-turn history untouched' do
    sid = described_class.create(id: 'evolving')[:id]
    described_class.append(session_id: sid, content: 'Investigate login failures')
    described_class.append(session_id: sid, role: 'assistant', content: 'The expired certificate explains login failures.')
    allow(PWN::AI::Router).to receive(:summarize).and_return(JSON.generate(title: 'Login certificate repair', summary: 'Investigated login failures and found an expired certificate.'))
    before = described_class.to_llm_messages(session_id: sid)
    expect(described_class.refresh_title(session_id: sid)[:title]).to eq('Login certificate repair')
    described_class.append(session_id: sid, content: 'Now automate certificate rotation')
    expect(PWN::AI::Router).to receive(:summarize).with(hash_including(text: a_string_including('Investigated login failures', 'automate certificate rotation'), session: true)).and_return(JSON.generate(title: 'Login repair and certificate rotation', summary: 'Repaired login and automated certificate rotation.'))
    expect(described_class.refresh_title(session_id: sid)[:title]).to eq('Login repair and certificate rotation')
    expect(described_class.to_llm_messages(session_id: sid).first(2)).to eq(before)
    expect(described_class.metadata(session_id: sid)[:summary]).to include('automated')
    expect(File.stat(File.join(described_class.sessions_dir, "#{sid}.meta.json")).mode & 0o777).to eq(0o600)
  end

  it 'resumes a listed title after an asynchronous refresh and refuses ambiguous historical names' do
    sid = described_class.create(id: 'listed_before_refresh', title: 'Displayed café title')[:id]
    displayed = described_class.list.first[:title]
    described_class.append(session_id: sid, content: 'Repair login')
    allow(PWN::AI::Router).to receive(:summarize).and_return(JSON.generate(title: 'Updated login repair', summary: 'Repaired login'))
    described_class.refresh_title(session_id: sid)
    expect(described_class.list.first[:title]).to eq('Updated login repair')
    expect(described_class.resolve(identifier: displayed)).to eq(sid)
    described_class.create(id: 'duplicate_old_title', title: displayed)
    expect { described_class.resolve(identifier: displayed) }.to raise_error(ArgumentError, /Ambiguous.*listed_before_refresh.*duplicate_old_title|Ambiguous.*duplicate_old_title.*listed_before_refresh/)
    expect(described_class.resolve(identifier: sid)).to eq(sid)
    described_class.create(id: 'id_shaped_title', title: sid)
    expect(described_class.resolve(identifier: "'#{sid}'")).to eq(sid)
  end

  it 'falls back for missing old metadata and never lets malformed metadata change the canonical id' do
    session = described_class.create(id: 'legacy', title: 'Legacy title')
    path = File.join(described_class.sessions_dir, 'legacy.meta.json')
    File.delete(path)
    expect(described_class.metadata(session_id: session[:id])[:title]).to eq('Legacy title')
    File.write(path, JSON.generate(id: 'wrong', title: nil))
    expect(described_class.metadata(session_id: session[:id])).to include(id: 'legacy', title: 'Legacy title')
    File.write(session[:path], JSON.generate(role: 'user', content: 'old turn'))
    File.delete(path)
    expect(described_class.list.first[:title]).to eq('pwn-ai session legacy')
  end

  it 'preserves the previous title and retries after invalid or unavailable summaries' do
    sid = described_class.create(id: 'retry_title')[:id]
    described_class.append(session_id: sid, content: 'Repair login')
    ['not json', '{}', '{"title":"","summary":"no"}', JSON.generate(title: "\u00a0\u2003", summary: 'no'), '[]', ''].each do |response|
      allow(PWN::AI::Router).to receive(:summarize).and_return(response)
      expect(described_class.refresh_title(session_id: sid)[:title]).to eq('Repair login')
      expect(described_class.metadata(session_id: sid)[:summary_turns]).to be_nil
    end
  end

  it 'rejects stale summary writes when a newer worker has already advanced the cursor' do
    sid = described_class.create(id: 'concurrent_title')[:id]
    described_class.append(session_id: sid, content: 'First request')
    entered = Queue.new
    release = Queue.new
    allow(PWN::AI::Router).to receive(:summarize) do
      if Thread.current[:slow_title]
        entered << true
        release.pop
        JSON.generate(title: 'Old title', summary: 'Old summary')
      else
        JSON.generate(title: 'New title', summary: 'Both requests summarized')
      end
    end
    old = Thread.new do
      Thread.current[:slow_title] = true
      described_class.refresh_title(session_id: sid)
    end
    entered.pop
    described_class.append(session_id: sid, content: 'Second request')
    expect(described_class.refresh_title(session_id: sid)[:title]).to eq('New title')
    release << true
    old.join
    expect(described_class.metadata(session_id: sid)).to include(title: 'New title', summary_turns: 2)
    expect(Dir.glob(File.join(described_class.sessions_dir, '*.tmp'))).to be_empty
  ensure
    old&.kill
    old&.join
  end

  it 'removes naming metadata when retention deletes the transcript' do
    session = described_class.create(id: 'obsolete_title')
    File.utime(Time.at(0), Time.at(0), session[:path])
    described_class.lean!(hot_days: 0, retain_days: 1)
    expect(File.exist?(session[:path])).to be(false)
    expect(File.exist?(File.join(described_class.sessions_dir, 'obsolete_title.meta.json'))).to be(false)
  end

  it 'should display information for authors' do
    authors_response = PWN::Sessions
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Sessions
    expect(help_response).to respond_to :help
  end

  it 'should support create/list/append/load/delete' do
    s = PWN::Sessions.create(title: 'spec test session')
    expect(s[:id]).not_to be_nil
    PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'test input')
    t = PWN::Sessions.load(session_id: s[:id])
    expect(t.size).to be >= 2
    # Hot sessions are pinned — force required for intentional delete.
    expect { PWN::Sessions.delete(session_id: s[:id]) }.to raise_error(/protected/)
    PWN::Sessions.delete(session_id: s[:id], force: true)
    expect(PWN::Sessions.list.any? { |x| x[:id] == s[:id] }).to be false
  end

  it 'caps tool/assistant content on append per TOOL_CONTENT_MAX/ASSISTANT_CONTENT_MAX' do
    s = PWN::Sessions.create(title: 'cap test')
    tool_big = 'T' * (PWN::Sessions::TOOL_CONTENT_MAX + 100)
    asst_big = 'A' * (PWN::Sessions::ASSISTANT_CONTENT_MAX + 100)
    PWN::Sessions.append(session_id: s[:id], role: 'tool', content: tool_big)
    PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: asst_big)
    rows = PWN::Sessions.load(session_id: s[:id])
    tool = rows.find { |e| e[:role] == 'tool' }
    asst = rows.find { |e| e[:role] == 'assistant' }
    expect(tool[:content].bytesize).to be <= (PWN::Sessions::TOOL_CONTENT_MAX + 20)
    expect(asst[:content].bytesize).to be <= (PWN::Sessions::ASSISTANT_CONTENT_MAX + 20)
    expect(tool[:content]).to include('[compacted]')
  ensure
    PWN::Sessions.delete(session_id: s[:id], force: true) if s
  end

  it 'lean! respects MIN_STUB_BYTES and HOT_DAYS pins' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    hot = PWN::Sessions.create(title: 'hot')
    PWN::Sessions.append(session_id: hot[:id], role: 'user', content: 'substantive user line here')
    # cold stub: tiny file outside hot window
    stub_id = '19990101_000000_deadbeef'
    stub_path = File.join(tmp, "#{stub_id}.jsonl")
    File.write(stub_path, %({"role":"system","content":"Session started","timestamp":"1999-01-01T00:00:00Z"}
))
    File.utime(Time.at(0), Time.at(0), stub_path)
    res = PWN::Sessions.lean!(current_session_id: hot[:id])
    expect(File.exist?(File.join(tmp, "#{hot[:id]}.jsonl"))).to be true
    expect(File.exist?(stub_path)).to be false
    expect(res[:deleted]).to be >= 1
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'recall searches prior session transcripts and skips the current session' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    old = PWN::Sessions.create(id: '20200101_000000_oldone', title: 'old')
    PWN::Sessions.append(session_id: old[:id], role: 'user', content: 'use hping3 for a ping sweep')
    PWN::Sessions.append(session_id: old[:id], role: 'assistant', content: 'Prefer pwn_eval then shell for that')
    cur = PWN::Sessions.create(id: '20260101_000000_curone', title: 'current')
    PWN::Sessions.append(session_id: cur[:id], role: 'user', content: 'unrelated current chatter')
    hits = PWN::Sessions.recall(query: 'hping3', exclude_session_id: cur[:id], limit: 8)
    expect(hits).to be_an(Array)
    expect(hits).not_to be_empty
    expect(hits.all? { |h| h[:session_id] != cur[:id] }).to eq true
    expect(hits.any? { |h| h[:content].to_s.include?('hping3') }).to eq true
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'previous_id returns the newest session that is not the current one' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    old = PWN::Sessions.create(id: '20200101_000000_oldses', title: 'old')
    PWN::Sessions.append(session_id: old[:id], role: 'user', content: 'SHIP MARKER LAST SESSION')
    cur = PWN::Sessions.create(id: '20260101_000000_curses', title: 'current')
    PWN::Sessions.append(session_id: cur[:id], role: 'user', content: 'what did I just say?')
    expect(PWN::Sessions.previous_id(exclude_session_id: cur[:id])).to eq(old[:id])
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'to_llm_messages returns this session user/assistant turns for the next LLM call' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    sid = 'llm_hist_sess'
    PWN::Sessions.create(id: sid, title: 'hist')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'where is OpenGoal?')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'in open_goal.rb')
    PWN::Sessions.append(session_id: sid, role: 'tool', content: 'ignore me')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'and Loop.run?')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'in loop.rb around resume?')
    msgs = PWN::Sessions.to_llm_messages(session_id: sid)
    expect(msgs.map { |m| m[:role] }).to eq(%w[user assistant user assistant])
    expect(msgs.map { |m| m[:content] }).to include('where is OpenGoal?', 'in open_goal.rb', 'and Loop.run?', 'in loop.rb around resume?')
    expect(msgs.none? { |m| m[:content].to_s.include?('ignore me') }).to eq true
    skip_last = PWN::Sessions.to_llm_messages(session_id: sid, skip_request: 'and Loop.run?')
    expect(skip_last.last[:content]).to eq('in loop.rb around resume?')
    expect(skip_last.none? { |m| m[:content] == 'and Loop.run?' && m[:role] == 'user' }).to eq true
    tiny = PWN::Sessions.to_llm_messages(session_id: sid, max_chars: 40)
    expect(tiny.last[:content]).to include('loop.rb')
    expect(tiny.map { |m| m[:content].to_s.length }.sum).to be <= 80
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'retrieves a throttle-evasion session from a rate-limit paraphrase' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:sessions_dir).and_return(dir)
      FileUtils.mkdir_p(dir)
      sid = described_class.create(id: 'throttle_fix', title: 'login')[:id]
      described_class.append(session_id: sid, role: 'assistant', content: 'throttle evasion on the login form')
      hits = described_class.recall(query: 'how did I bypass the login rate limit')
      expect(hits.map { |h| h[:session_id] }).to include(sid)
    end
  end

  it 'redacts AWS access-key shaped tokens' do
    out = described_class.redact(content: 'id AKIAIOSFODNN7EXAMPLE extra')
    expect(out).to include('[REDACTED:aws:')
    expect(out).not_to include('AKIAIOSFODNN7EXAMPLE')
  end

  it 'gzips old transcripts and leaves findings alone' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:sessions_dir).and_return(File.join(dir, 'sessions'))
      FileUtils.mkdir_p(described_class.sessions_dir)
      path = File.join(described_class.sessions_dir, 'old.jsonl')
      File.write(path, %({"role":"user","content":"hi"}\n))
      File.utime(Time.now - (10 * 86_400), Time.now - (10 * 86_400), path)
      findings = File.join(dir, 'findings.jsonl')
      File.write(findings, 'keep')
      stub_const('PWN::Plugins::Findings::FILE', findings)
      r = described_class.retain(days: 1)
      expect(r[:gzipped].to_i).to be >= 1
      expect(File.file?(path)).to be false
      expect(File.file?("#{path}.gz")).to be true
      expect(File.read(findings)).to eq('keep')
    end
  end

  it 'retain with a huge keep window reports zero deleted' do
    expect(described_class.retain(days: 10_000)[:deleted]).to eq(0)
  end

  it 'export writes a sha256 manifest next to the tarball' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:sessions_dir).and_return(File.join(dir, 'sessions'))
      FileUtils.mkdir_p(described_class.sessions_dir)
      allow(Dir).to receive(:home).and_return(dir)
      sid = 'exportme'
      File.write(File.join(described_class.sessions_dir, "#{sid}.jsonl"), %({"role":"user"}\n))
      out = described_class.export(session_id: sid)
      expect(File.file?(out[:path])).to be true
      expect(out[:manifest]).to be_a(Hash)
      expect(out[:manifest].values.first.to_s).to match(/\A[0-9a-f]{64}\z/)
    end
  end
end
