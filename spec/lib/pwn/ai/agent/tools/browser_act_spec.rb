# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools browser_act' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/browser_act.rb'
  end

  it 'registers browser_act' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'browser_act')).not_to be_nil
  end

  it 'opens, acts, and closes when no browser is supplied' do
    browser_obj = { type: :headless, browser: :stub }
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).with(browser_type: :headless).and_return(browser_obj)
    allow(PWN::Plugins::TransparentBrowser).to receive(:act).and_return({ available: true, status: 'done' })
    allow(PWN::Plugins::TransparentBrowser).to receive(:close)

    result = PWN::AI::Agent::Registry.lookup(name: 'browser_act').handler.call(
      'goal' => 'find the article',
      'url' => 'https://example.test'
    )

    expect(result).to include(available: true, status: 'done')
    expect(PWN::Plugins::TransparentBrowser).to have_received(:act).with(
      hash_including(browser_obj: browser_obj, goal: 'find the article', url: 'https://example.test')
    )
    expect(PWN::Plugins::TransparentBrowser).to have_received(:close).with(browser_obj: browser_obj)
  end

  it 'does not close a browser the caller already owns' do
    supplied = { type: :rest, browser: :kept }
    allow(PWN::Plugins::TransparentBrowser).to receive(:open)
    allow(PWN::Plugins::TransparentBrowser).to receive(:act).and_return({ available: false, status: 'unavailable' })
    allow(PWN::Plugins::TransparentBrowser).to receive(:close)

    PWN::AI::Agent::Registry.lookup(name: 'browser_act').handler.call(browser_obj: supplied, goal: 'look')

    expect(PWN::Plugins::TransparentBrowser).not_to have_received(:open)
    expect(PWN::Plugins::TransparentBrowser).not_to have_received(:close)
  end
end
