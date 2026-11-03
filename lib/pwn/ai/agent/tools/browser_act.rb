# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'browser_act',
  toolset: 'pwn',
  schema: {
    name: 'browser_act',
    description: 'Drive a live browser toward a goal. When Open WebUI has a Jev model, Jev picks each CLICK, TYPE_TEXT, SELECT, scroll, WAIT, DONE, or BLOCKED target from visible controls. The active pwn-ai model writes field text only. If Jev is not configured, the call reports unavailable and does not invent clicks.',
    parameters: {
      type: 'object',
      properties: {
        goal: { type: 'string', description: 'Natural-language goal for the current page.' },
        url: { type: 'string', description: 'Optional HTTP(S) URL to open before the first observation.' },
        steps: { type: 'integer', description: 'Maximum decision cycles, 1 to 60. Defaults to 12.' },
        browser_type: { type: 'string', description: 'Browser type when no browser_obj is supplied. Defaults to headless.' }
      },
      required: ['goal']
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    owned = args[:browser_obj].nil?
    browser_obj = args[:browser_obj] || PWN::Plugins::TransparentBrowser.open(browser_type: (args[:browser_type] || :headless).to_sym)
    begin
      PWN::Plugins::TransparentBrowser.act(browser_obj: browser_obj, goal: args[:goal], url: args[:url], steps: args[:steps])
    ensure
      PWN::Plugins::TransparentBrowser.close(browser_obj: browser_obj) if owned && browser_obj
    end
  }
)
