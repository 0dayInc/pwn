# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Loop, 'chat deliverables' do
  include_context 'pwn tmp sandbox'

  let(:sid) { PWN::Sessions.create[:id] }
  let(:note) { 'Thank you for making time for me.' }
  let(:missing) { 'Translate the following sentence into Italian.' }
  let(:question) { 'Which sentence would you like me to translate?' }

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    PWN::Env[:ai][:active] = :openai
    PWN::Env[:ai][:openai] = { model: 'gpt-5', server_tools: ['web_search'] }
    @agent_cfg[:plan_first] = true
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    expect(PWN::AI::Agent::Reward).not_to receive(:judge)
  end

  def submit(request, **opts)
    described_class.run(request: request, session_id: sid, on_outcome: ->(row) { @outcome = row }, **opts)
  end

  def reply(text)
    { choices: [{ message: { role: 'assistant', content: text } }] }
  end

  def checkpoints
    Dir.glob(File.join(PWN::Sessions.sessions_dir, 'requests', Digest::SHA256.hexdigest(sid), '*.json')).map { |path| JSON.parse(File.read(path), symbolize_names: true) }
  end

  def public_history
    PWN::Sessions.load(session_id: sid).drop(1).map { |row| row.values_at(:role, :content) }
  end

  {
    'Write a one-sentence thank-you note here in chat.' => 'Thank you for making time for me.',
    'Give me a one-sentence thank-you note here in chat.' => 'Thank you for making time for me.',
    'Write a one-sentence thank-you note.' => 'Thank you for making time for me.',
    'Write me an epitaph for an imaginary constellation.' => 'The dark remembers where you shone.',
    'Could you compose a short birthday greeting?' => 'Happy birthday!',
    'Draft a cheerful poem about spring.' => 'A bud unfolds in April rain.',
    'Compose an inscription for a cracked observatory lens.' => 'Even imperfect glass can hold a star.',
    'How many sides does a triangle have?' => 'Three.',
    'What is the number of edges of a cube?' => 'Twelve.',
    'Convert two hours to minutes.' => '120 minutes.',
    'How many centimeters are in 1.5 meters?' => '150 centimeters.',
    'Translate this sentence into Spanish: "I like apples."' => 'Me gustan las manzanas.'
  }.each do |request, answer|
    it "delivers #{request.inspect} on one untooled model turn and saves answer-only evidence" do
      expect(described_class).not_to receive(:plan_first)
      expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once do |wire|
        expect([*wire[:tools], *wire[:server_tools], wire[:tool_choice]].compact).to be_empty
        expect(wire[:messages].last).to include(role: 'user', content: request)
        reply(answer)
      end
      expect(submit(request)).to eq(answer)
      expect(public_history).to eq([['user', request], ['assistant', answer]])
      expect(@outcome).to include(status: 'complete', unmet: [])
      expect(checkpoints.fetch(0)[:evidence]).to contain_exactly(hash_including(kind: 'answer', requirement: request, sha256: Digest::SHA256.hexdigest(answer)))
    end
  end

  it 'preserves public text but does not execute or certify an unsolicited action on a reply turn' do
    answer = 'Velvet dusk.'
    call = { id: 'unused', type: 'function', function: { name: 'fixture_action', arguments: '{}' } }
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', content: answer, tool_calls: [call] } }])
    result = submit('Compose a two-word caption.')
    expect(result).to be_a(described_class::TurnNotice)
    expect(result).to include(answer, 'not processed')
    expect(@outcome).to include(status: 'incomplete', adjudication: 'unknown')
    expect(public_history.last).to eq(['notice', result])
    expect(checkpoints.first).to include(evidence: [], effects: {})
  end

  it 'records that a draft was saved, not that an independent verifier passed the original goal' do
    runtime = nil
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once do
      runtime = Thread.current[:pwn_request_runtime]
      reply(note)
    end
    expect(submit('Draft a thank-you note.')).to eq(note)
    expect(@outcome).to include(status: 'complete', adjudication: 'unknown')
    expect(checkpoints.first.fetch(:evidence)).to contain_exactly(hash_including(kind: 'answer', locator: 'chat:reply', provenance: 'session_transcript', passed: nil))
    expect(runtime.scope_evidenced?).to be(false)
  end

  it 'uses only the public disposition in a recovered non-ASCII clarification, without completing it or replaying actions' do
    prompt = 'Quel énoncé souhaitez-vous traduire ?'
    frame = JSON.generate(pwn_turn: 'needs_input', text: prompt, remaining: 'source sentence')
    wire = JSON.generate(message: { role: 'assistant', content: frame, thinking: 'private fixture' }, done: true).b
    expect(PWN::AI::Ollama).to receive(:chat_with_tools).once do |opts|
      expect(Array(opts[:tools])).to be_empty
      PWN::AI::Ollama.send(:assemble_ollama_stream, body: wire, rest_call: 'api/chat')
    end
    notices = []
    expect(submit(missing, engine: :ollama, on_notice: ->(msg) { notices << msg })).to eq(prompt)
    expect(@outcome).to include(status: 'incomplete', goal_status: 'awaiting_input', adjudication: 'unknown')
    expect(public_history).to eq([['user', missing], ['assistant', prompt]])
    expect(checkpoints.first).to include(evidence: [], effects: {})
    expect(PWN::AI::Agent::OpenGoal.for_session(session_id: sid)).to include(request: missing)
  end

  it 'shows only public text and a warning when a recovered reply also contains a pending action' do
    caption = 'Un été calme.'
    frame = JSON.generate(pwn_turn: 'answer', text: caption)
    message = { role: 'assistant', content: frame, tool_calls: [{ function: { name: 'fixture', arguments: { value: 'private marker' } } }] }
    wire = JSON.generate(message: message, done: true).b
    expect(PWN::AI::Ollama).to receive(:chat_with_tools).once do
      PWN::AI::Ollama.send(:assemble_ollama_stream, body: wire, rest_call: 'api/chat')
    end
    notices = []
    expect(submit('Draft a short caption.', engine: :ollama, on_notice: ->(msg) { notices << msg })).to eq(caption)
    expect(notices).to contain_exactly(a_string_matching(/Ollama: .*action was not processed/))
    expect(@outcome).to include(status: 'incomplete', unmet: ['unprocessed_action'], adjudication: 'unknown')
    expect(public_history.last).to eq(['notice', "#{caption}\n\n#{notices.first}"])
    expect(checkpoints.first).to include(evidence: [], effects: {})
  end

  it 'accepts a question as the supplied translation text without opening a different goal' do
    source = 'Where are my glasses?'
    translation = 'Dove sono i miei occhiali?'
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(reply(JSON.generate(pwn_turn: 'needs_input', text: question, remaining: 'source sentence')))
    expect(submit(missing)).to eq(question)
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once do |wire|
      expect([*wire[:tools], *wire[:server_tools], wire[:tool_choice]].compact).to be_empty
      expect(wire[:messages].last(3).map { |row| row[:content] }).to eq([missing, question, source])
      reply(JSON.generate(pwn_turn: 'answer', text: translation, continues: true))
    end
    expect(submit(source)).to eq(translation)
    expect(PWN::AI::Agent::OpenGoal.for_session(session_id: sid)).to be_nil
  end

  it 'keeps the original open goal through two different clarification questions' do
    request = 'Translate the following sentence.'
    language = 'Which language should I translate it into?'
    source = 'Our lantern is still lit.'
    answer = 'La nostra lanterna è ancora accesa.'
    frames = [[question, 'needs_input', 'source sentence', false], [language, 'needs_input', 'language', true], [answer, 'answer', nil, true]]
    expect(described_class).not_to receive(:plan_first)
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).exactly(3).times do |wire|
      text, state, remaining, continues = frames.shift
      expect([*wire[:tools], *wire[:server_tools]]).to be_empty
      reply(JSON.generate(pwn_turn: state, text: text, remaining: remaining, continues: continues))
    end
    expect(submit(request)).to eq(question)
    goal = PWN::AI::Agent::OpenGoal.for_session(session_id: sid)
    expect(submit(source)).to eq(language)
    expect(PWN::AI::Agent::OpenGoal.for_session(session_id: sid)).to include(request: request, request_id: goal[:request_id], reply_question: Digest::SHA256.hexdigest(language))
    expect(submit('Italian')).to eq(answer)
    expect(PWN::AI::Agent::OpenGoal.for_session(session_id: sid)).to be_nil
  end

  it 'does not publish private reasoning or invent an unprocessed action for a thinking-only response' do
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(choices: [{ message: { role: 'assistant', content: '', thinking: 'private synthetic reasoning' } }])
    result = submit('Draft a two-word caption.')
    expect(result).to be_a(described_class::TurnNotice)
    expect(result).to include('No public answer')
    expect(result).not_to include('private synthetic reasoning', 'An action')
    expect(@outcome).to include(status: 'incomplete', unmet: ['public_reply_missing'])
  end

  it 'keeps missing source input open, then delivers the translation of the actual follow-up on its original request' do
    expect(described_class).not_to receive(:plan_first)
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once.and_return(reply(JSON.generate(pwn_turn: 'needs_input', text: question, remaining: 'source sentence')))
    expect(submit(missing)).to eq(question)
    expect(@outcome).to include(status: 'incomplete', goal_status: 'awaiting_input', unmet: ['source sentence'])
    waiting = checkpoints.fetch(0)
    expect(waiting).to include(original_request: missing, evidence: [], effects: {})
    expect(PWN::AI::Agent::OpenGoal.for_session(session_id: sid)).to include(request_id: waiting[:request_id])
    expect(public_history).to eq([['user', missing], ['assistant', question]])
    source = 'Our lantern is still lit.'
    translation = 'La nostra lanterna è ancora accesa.'
    expect(PWN::AI::OpenAI).to receive(:chat_with_tools).once do |wire|
      expect([*wire[:tools], *wire[:server_tools], wire[:tool_choice]].compact).to be_empty
      expect(wire[:messages].last(3).map { |row| row.values_at(:role, :content) }).to eq([['user', missing], ['assistant', question], ['user', source]])
      reply(JSON.generate(pwn_turn: 'answer', text: translation, continues: true))
    end
    expect(submit(source)).to eq(translation)
    expect(@outcome).to include(status: 'complete', unmet: [])
    expect(public_history.last(2)).to eq([['user', source], ['assistant', translation]])
    expect(checkpoints).to contain_exactly(hash_including(request_id: waiting[:request_id], outcome: hash_including(goal_status: 'awaiting_input')),
                                           hash_including(original_request: source, evidence: [hash_including(kind: 'answer', sha256: Digest::SHA256.hexdigest(translation))]))
    expect(PWN::AI::Agent::OpenGoal.for_session(session_id: sid)).to be_nil
  end
end
