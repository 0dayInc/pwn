# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::TransparentBrowser, 'jev action loop' do
  let(:browser) { double('browser', goto: nil) }
  let(:browser_obj) { { type: :headless, browser: browser } }

  before do
    Thread.current[:pwn_jev_model] = nil
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :openwebui).and_return({ base_uri: 'https://ow.example', key: 'token', model: 'llama' })
    allow(PWN::Env).to receive(:dig).with(:ai, :active).and_return(:grok)
    allow(PWN::Env).to receive(:dig).with(:ai, :grok, :model).and_return('grok-4')
    allow(PWN::AI::OpenWebUI).to receive(:get_models).and_return([{ id: 'jev-27b' }])
  end

  after { Thread.current[:pwn_jev_model] = nil }

  it 'stays inactive when Open WebUI has no Jev model' do
    allow(PWN::AI::OpenWebUI).to receive(:get_models).and_return([{ id: 'llama' }])
    expect(described_class.act(browser_obj: browser_obj, goal: 'find the article')).to include(available: false, status: 'unavailable')
  end

  it 'asks Jev for the operation and the active engine only for typed text' do
    scripts = []
    allow(browser).to receive(:execute_script) do |script|
      if script.include?('querySelectorAll')
        { 'url' => 'https://example.test', 'title' => 'Example', 'rows' => [{ 'index' => 1, 'role' => 'textbox', 'name' => 'Where to?', 'value' => '' }] }
      else
        scripts << script
        { 'status' => scripts.length == 1 ? 'acted' : 'done' }
      end
    end
    decisions = ['{"operation":"TYPE_TEXT","target":1}', '{"operation":"DONE","target":0}']
    allow(PWN::AI::OpenWebUI).to receive(:chat) { { choices: [{ role: 'assistant', content: decisions.shift }] } }
    allow(PWN::AI::Grok).to receive(:chat).and_return({ choices: [{ role: 'assistant', content: '{"text":"London"}' }] })

    result = described_class.act(browser_obj: browser_obj, goal: 'Search for London', steps: 2)

    expect(result).to include(available: true, status: 'done', jev_model: 'jev-27b', text_engine: :grok, text_model: 'grok-4')
    expect(PWN::AI::Grok).to have_received(:chat)
    expect(scripts.first).to include('London')
    expect(scripts.first).not_to include('querySelectorAll')
  end
end
