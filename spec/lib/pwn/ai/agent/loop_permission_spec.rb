# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Loop, 'permission boundaries' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @agent_cfg[:plan_first] = false
  end

  it 'answers a question when permission to open its optional request log is denied' do
    sid = PWN::Sessions.create(title: 'optional diagnostics')[:id]
    log = PWN::Plugins::Log
    dir = File.join(@tmp, 'private-log')
    FileUtils.mkdir_p(dir)
    path = File.join(dir, "pwn-ai-DEBUG-#{sid}-R1.log")
    allow(log).to receive(:debug_dir).and_return(dir)
    allow(File).to receive(:open).and_call_original
    expect(File).to receive(:open).with(path, 'a', 0o600).once.and_raise(Errno::EACCES, 'private-fixture-detail')
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', content: 'Yellow.' } }])
    notices = []
    stderr = $stderr
    answer = described_class.run(request: 'What color is a lemon?', session_id: sid, engine: :openai, enabled_toolsets: [],
                                 debug: true, trace: true, debug_tee: StringIO.new, on_notice: ->(msg) { notices << msg }, system_role_content: 'fixture')
    expect(answer).to eq('Yellow.')
    expect(notices).to eq(['Permission denied opening the debug log. Continuing without request tracing.'])
    expect(PWN::Sessions.load(session_id: sid)).to include(hash_including(role: 'assistant', content: answer))
    expect(log.debug_enabled? || log.trace_enabled?).to be(false)
    expect($stderr).to equal(stderr)
    File.open("#{path}.lease", File::RDWR) { |lease| expect(lease.flock(File::LOCK_EX | File::LOCK_NB)).to eq(0) }
  ensure
    log&.stop_debug
  end

  it 'does not promote a real denied result to success when its mistake record cannot be written' do
    raw = JSON.generate(success: false, error: 'Permission denied reading the fixture')
    expect(PWN::AI::Agent::Mistakes).to receive(:record).and_raise(Errno::EROFS)
    tele = described_class.send(:record_metrics, name: 'fixture', args: {}, raw: raw)
    expect(tele).to include(ok: false, err: 'Permission denied reading the fixture', mistake: nil)
  end

  it 'returns a saved blocked result to the caller when the provider denies the planning call' do
    require 'rest-client'
    @agent_cfg[:plan_first] = true
    sid = PWN::Sessions.create(title: 'artifact planning')[:id]
    request_id = "req_#{'ab' * 16}"
    http = Net::HTTPForbidden.new('1.1', '403', 'Forbidden')
    http['x-request-id'] = request_id
    http['x-fixture'] = 'private-header'
    body = JSON.generate(error: { code: 'insufficient_scope', message: 'private-provider-detail' })
    response = RestClient::Response.create(body, http, RestClient::Request.new(method: :post, url: 'https://example.invalid/private-route'))
    expect(PWN::AI::Grok).to receive(:chat_with_tools).with(hash_including(tools: nil)).once.and_raise(RestClient::Forbidden.new(response))
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    outcome = nil
    answer = described_class.run(request: 'Save the meeting agenda to ./agenda.txt.', session_id: sid, engine: :grok,
                                 system_role_content: 'fixture', on_outcome: ->(result) { outcome = result })
    expect(answer).to match(/planning request.*HTTP 403.*no answer/i)
    expect(answer).to include('Provider code: insufficient_scope', "Provider request ID: #{request_id}")
    expect(answer).not_to match(/private-(?:provider-detail|header|route)/)
    expect(outcome).to include(status: 'blocked', stage: 'planning', unmet: include('provider_denied_plan'))
    rows = PWN::Sessions.load(session_id: sid)
    expect(rows).to include(hash_including(role: 'notice', content: answer))
    expect(rows).not_to include(hash_including(role: 'assistant'))
  end

  it 'keeps an opaque planning denial opaque, even if its text resembles a known reason' do
    require 'rest-client'
    window = described_class::PlanWindow.new
    bodies = ['insufficient_quota', JSON.generate(error: { code: 'private-value', message: 'billing_not_active' }), JSON.generate(error: { code: 'model_not_found', message: 'x' * 32_768 })]
    bodies.each do |body|
      response = Struct.new(:code, :body, :headers).new(403, body, { x_request_id: 'private-header' })
      notice = window.read(nested: false, handoff: false) { raise RestClient::Forbidden, response }
      expect(notice).to be_a(described_class::DeniedPlan)
      expect(notice).to include('No recognized provider error code')
      expect(notice).not_to match(/insufficient_quota|billing_not_active|model_not_found|private-|Provider request ID/)
    end
  end

  it 'explains a Grok subscription restriction on the effort sent by the planner' do
    require 'rest-client'
    @agent_cfg[:plan_first] = true
    PWN::Env[:ai][:grok] = { model: 'grok-4.7', key: 'fixture-only', reasoning_effort: 'xhigh' }
    sid = PWN::Sessions.create(title: 'effort diagnostic')[:id]
    body = JSON.generate(code: 'permission-denied', error: "Reasoning effort 'xhigh' is not available on your current subscription. Private fixture detail.")
    response = Struct.new(:code, :body, :headers).new(403, body, {})
    expect(RestClient::Request).to receive(:execute).once do |call|
      expect(JSON.parse(call.fetch(:payload))).to include('reasoning_effort' => 'xhigh')
      raise RestClient::Forbidden, response
    end
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    outcome = nil
    notice = described_class.run(request: 'Save the meeting agenda to ./agenda.txt.', session_id: sid, engine: :grok,
                                 system_role_content: 'fixture', on_outcome: ->(result) { outcome = result })
    expect(notice).to be_a(described_class::DeniedPlan)
    expect(notice).to include('Your current Grok subscription does not include the "xhigh" reasoning effort.', 'Provider code: permission-denied.')
    expect(notice).not_to include('Private fixture detail')
    expect(outcome).to include(status: 'blocked', stage: 'planning')
    expect(PWN::Sessions.load(session_id: sid).select { |r| %w[assistant notice].include?(r[:role]) }).to contain_exactly(hash_including(role: 'notice', content: notice))
  end

  it 'uses the structured top-level denial code rather than its accompanying error text' do
    require 'rest-client'
    window = described_class::PlanWindow.new
    response = Struct.new(:code, :body, :headers).new(403, JSON.generate(code: 'permission-denied', error: 'insufficient_quota'), {})
    notice = window.read(nested: false, handoff: false) { raise RestClient::Forbidden, response }
    expect(notice).to include('Provider code: permission-denied.')
    expect(notice).not_to include('insufficient_quota')
  end

  it 'can finish the same question after an optional read is denied, without retrying the operation' do
    sid = PWN::Sessions.create(title: 'optional note')[:id]
    call = { id: 'optional-read', type: 'function', function: { name: 'artifact_read', arguments: '{}' } }
    denial = 'Permission denied reading the optional fixture note.'
    reply = 'Yellow. The optional note was not available.'
    expect(PWN::AI::Agent::Dispatch).to receive(:call).once.and_return(JSON.generate(success: false, error: denial))
    responses = [{ role: 'assistant', tool_calls: [call] }, { role: 'assistant', content: reply }].map { |message| { choices: [{ message: message }] } }
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).twice.and_return(*responses)
    answers = []
    answer = described_class.run(request: 'What color is a lemon? You may read the optional fixture file for reference.', session_id: sid, engine: :openai, system_role_content: 'fixture',
                                 on_tool: ->(name, _, value) { answers << value if name == 'artifact_read' })
    expect(answers).to contain_exactly(include(denial))
    expect(answer).to eq(reply)
    expect(PWN::Sessions.load(session_id: sid)).to include(hash_including(role: 'assistant', content: reply))
  end

  it 'reports the current failed operation instead of unwinding if its correction history is also denied' do
    sid = PWN::Sessions.create(title: 'permission fixture')[:id]
    call = { id: 'fixture-1', type: 'function', function: { name: 'artifact_read', arguments: '{}' } }
    denial = 'Permission denied reading the optional note.'
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', tool_calls: [call] } }])
    expect(PWN::AI::Agent::Dispatch).to receive(:call).once.and_return(JSON.generate(success: false, error: denial))
    path = PWN::AI::Agent::Mistakes::MISTAKES_FILE
    File.write(path, '{}')
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with(path).and_raise(Errno::EACCES, 'private-history-marker')
    results = []
    outcome = nil
    answer = described_class.run(request: 'Read the fixture note.', session_id: sid, engine: :openai, system_role_content: 'fixture', on_outcome: ->(row) { outcome = row },
                                 on_tool: ->(name, _, value) { results << value if name == 'artifact_read' })
    expect(answer).to include('blocked:', 'tool failed', 'correction history', 'No retry')
    expect(answer).not_to include('private-history-marker')
    expect(outcome[:status]).to eq('blocked')
    expect(results.length).to eq(1)
    expect(results.first).to include(denial)
    expect(results.first).not_to include('private-history-marker')
    expect(File.binread(path)).to eq('{}')
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', content: 'Yellow.' } }])
    expect(described_class.run(request: 'What color is a lemon?', session_id: sid, engine: :openai, enabled_toolsets: [], system_role_content: 'fixture')).to eq('Yellow.')
  end
end
