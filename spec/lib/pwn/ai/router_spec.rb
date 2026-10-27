# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Router do
  it 'summarizes sessions with the active provider and model rather than the local artifact route' do
    stub_const('PWN::Env', { ai: { active: 'openai', openai: { model: 'active-model', key: 'test-key' }, ollama: { model: 'local', base_uri: 'http://localhost:11434' } } })
    expect(PWN::AI::Ollama).not_to receive(:chat)
    expect(PWN::AI::OpenAI).to receive(:chat).with(hash_including(model: 'active-model', request: a_string_including('overall conversation', 'JSON', 'at most 7 words'), spinner: false)) do
      expect(Thread.current[:pwn_session_title]).to be(true)
      { choices: [{ role: 'system', content: 'wrong' }, { role: 'assistant', content: '{"title":"Repair","summary":"Fixed login"}' }] }
    end
    expect(described_class.summarize(text: 'Login repaired', llm: true, session: true)).to include('Fixed login')
    expect(Thread.current[:pwn_session_title]).to be_nil
    expect(PWN::Env[:ai][:active]).to eq('openai')
    PWN::Env[:ai][:active] = 'openwebui'
    PWN::Env[:ai][:openwebui] = { model: 'local', base_uri: 'http://localhost:3000', key: 'optional - API key' }
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    expect(PWN::AI::OpenWebUI).not_to receive(:chat)
    expect(described_class.summarize(text: 'Login repaired', llm: true, session: true)).to eq('')
  end

  %w[openai anthropic grok gemini ollama openwebui].each do |engine|
    it "routes session summaries only to the active #{engine} model" do
      stub_const('PWN::Env', { ai: { active: engine.to_sym, engine.to_sym => { model: 'selected-model', key: 'fixture-key', base_uri: 'http://localhost:1234' } } })
      mod = Object.const_get(described_class::ENGINE_MOD.fetch(engine))
      expect(mod).to receive(:chat).with(hash_including(model: 'selected-model', quiet: true, spinner: false)).and_return('{"title":"Topic","summary":"Overall conversation context."}')
      expect(described_class.summarize(text: 'Conversation', llm: true, session: true)).to include('Topic')
      expect(PWN::Env[:ai][:active]).to eq(engine.to_sym)
    end
  end

  it 'retains a safe title on active-provider failure without fallback or authentication prompts' do
    stub_const('PWN::Env', { ai: { active: :openai, openai: { model: 'active-model', key: 'fixture-key' }, ollama: { model: 'local', base_uri: 'http://localhost:11434' } } })
    expect(PWN::AI::Ollama).not_to receive(:chat)
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    expect(PWN::AI::OpenAI).not_to receive(:obtain_oauth_bearer_token)
    allow(PWN::AI::OpenAI).to receive(:chat).and_raise(IOError, 'offline provider')
    expect { described_class.summarize(text: 'Conversation', llm: true, session: true) }.to raise_error(IOError, 'offline provider')
    expect(Thread.current[:pwn_session_title]).to be_nil
    PWN::Env[:ai][:openai].delete(:key)
    expect(PWN::AI::OpenAI).not_to receive(:chat)
    expect(described_class.summarize(text: 'Conversation', llm: true, session: true)).to eq('')
  end

  %w[openai anthropic grok].each do |engine|
    it "does not enroll or prompt for #{engine} when session-title OAuth credentials have expired" do
      stub_const('PWN::Env', { ai: { active: engine.to_sym, engine.to_sym => { model: 'selected-model', oauth: { bearer_token: 'expired-fixture' } } } })
      mod = Object.const_get(described_class::ENGINE_MOD.fetch(engine))
      allow(mod).to receive(:oauth_token_expiring?).and_return(true)
      expect(mod).not_to receive(:obtain_oauth_bearer_token)
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      expect(PWN::Plugins::TransparentBrowser).not_to receive(:open)
      if engine == 'anthropic'
        # This adapter parses a nil transport result; preserve that failure
        # rather than disguising it as a downstream title JSON parse error.
        expect { described_class.summarize(text: 'Conversation', llm: true, session: true) }.to raise_error(TypeError)
      else
        expect(described_class.summarize(text: 'Conversation', llm: true, session: true)).to eq('')
      end
      expect(Thread.current[:pwn_session_title]).to be_nil
    end
  end

  it 'extracts supported symbol and string keyed wrapper content without reasoning or tool data' do
    stub_const('PWN::Env', { ai: { active: :openai, openai: { model: 'fixture', key: 'fixture-key' } } })
    body = JSON.generate(title: 'Certificate repair', summary: 'Repaired login certificates.')
    payloads = [
      { choices: [{ message: { role: 'assistant', content: body } }] },
      { 'choices' => [{ 'role' => 'assistant', 'content' => body }] },
      { 'content' => [{ 'type' => 'thinking', 'thinking' => 'not output' }, { 'type' => 'text', 'text' => body }] },
      { choices: [{ content: [{ type: 'output_text', text: body }] }] },
      { message: { role: 'assistant', content: body } },
      { title: 'Certificate repair', summary: 'Repaired login certificates.' }
    ]
    payloads.each do |payload|
      allow(PWN::AI::OpenAI).to receive(:chat).and_return(payload)
      expect(described_class.summarize(text: 'Fixture', llm: true, session: true)).to eq(body)
    end
    [{ content: [{ type: 'tool_use', input: { title: 'Wrong', summary: 'Wrong' } }] },
     { choices: [{ role: 'user', content: body }] }, { content: { title: 'Wrong' } }].each do |payload|
      allow(PWN::AI::OpenAI).to receive(:chat).and_return(payload)
      expect(described_class.summarize(text: 'Fixture', llm: true, session: true)).to eq('')
    end
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'maps task classes from ai_router with fallback chains' do
    stub_const('PWN::Env', {
                 ai_router: {
                   summarize: { engine: 'ollama', model: 'tinyllama', fallbacks: [{ engine: 'openwebui' }] },
                   plan: { engine: 'ollama', fallbacks: [] },
                   exploit_dev: { engine: 'ollama', model: 'qwen2.5-coder', fallbacks: [{ engine: 'openai', model: 'gpt-5' }] },
                   triage: { engine: 'ollama', fallbacks: [{ engine: 'openwebui' }] }
                 },
                 ai: { active: 'grok', ollama: { model: 'tinyllama' } }
               })
    sum = described_class.resolve(task: :summarize)
    expect(sum[:endpoints].first[:engine].to_s).to eq('ollama')
    expect(sum[:allow_frontier]).to eq(false)
    exp = described_class.resolve(task: :exploit_dev)
    expect(exp[:endpoints].map { |row| row[:engine].to_s }).to include('ollama', 'openai')
    expect(exp[:endpoints].first[:model].to_s).to include('coder')
  end

  it 'never spends frontier-model tokens on artifact summarization' do
    Dir.mktmpdir('pwn-router-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      stub_const('PWN::Env', {
                   ai_router: {
                     summarize: { engine: 'grok', model: 'grok-4', fallbacks: [{ engine: 'openai' }, { engine: 'ollama', model: 'tinyllama' }] }
                   },
                   ai: { active: 'grok', grok: { model: 'grok-4' }, openai: { model: 'gpt-5' }, ollama: { model: 'tinyllama' } }
                 })
      described_class.reset_usage
      %i[Grok OpenAI Anthropic Gemini].each do |name|
        allow(PWN::AI.const_get(name)).to receive(:chat).and_raise('frontier must not be called')
      end
      allow(PWN::AI::Ollama).to receive(:chat).and_return('local artifact summary')
      path = File.join(dir, 'big.txt')
      File.write(path, 'A' * (PWN::AI::Context::WINDOW + 50))
      row = PWN::AI::Context.attach_file(path: path, session_id: 'sum')
      expect(row[:summarized]).to eq(true)
      expect(described_class.usage.dig(:summarize, :frontier_tokens)).to eq(0)
      expect(PWN::AI::Grok).not_to have_received(:chat)
      expect(PWN::AI::OpenAI).not_to have_received(:chat)
    end
  end
end
