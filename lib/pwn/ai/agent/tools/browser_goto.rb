# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'browser_goto',
  toolset: 'pwn',
  schema: {
    name: 'browser_goto',
    description: 'Navigate a URL and optionally record screenshot, DOM snapshot, and HAR into the artifact store. When title is set, records a finding with pixel and HAR proof in the same call.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'HTTP(S) URL to open.' },
        uri: { type: 'string' },
        capture: { type: 'boolean', description: 'Spill screenshot, DOM, and HAR (defaults true when title is set).' },
        title: { type: 'string', description: 'Finding title; records pixel and HAR proof without a second call.' },
        severity: { type: 'string' },
        session_id: { type: 'string' },
        engagement_id: { type: 'string' },
        html: { type: 'string', description: 'DOM HTML fixture when no live browser is open.' },
        har: { type: 'string', description: 'HAR JSON fixture when no live capture proxy is attached.' },
        screenshot: { type: 'string', description: 'PNG path used when no live screenshot is available.' },
        label: { type: 'string' }
      }
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    PWN::Plugins::TransparentBrowser.goto(args)
  }
)
