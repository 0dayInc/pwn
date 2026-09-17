# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Router do
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
