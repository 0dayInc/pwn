# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'finding_record',
  toolset: 'pwn',
  schema: {
    name: 'finding_record',
    description: 'Append a finding row (title, severity, host, evidence, poc path) to ~/.pwn/findings.jsonl.',
    parameters: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        severity: { type: 'string' },
        host: { type: 'string' },
        evidence: { type: 'string' },
        poc: { type: 'string' },
        poc_artifacts: { type: 'array', items: { type: 'string' } },
        session_id: { type: 'string' }
      },
      required: %w[title]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Findings.record(
      title: args[:title] || args['title'],
      severity: args[:severity] || args['severity'],
      host: args[:host] || args['host'],
      evidence: args[:evidence] || args['evidence'],
      poc: args[:poc] || args['poc'],
      poc_artifacts: args[:poc_artifacts] || args['poc_artifacts'],
      session_id: args[:session_id] || args['session_id']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'finding_report',
  toolset: 'pwn',
  schema: {
    name: 'finding_report',
    description: 'List recorded findings from ~/.pwn/findings.jsonl.',
    parameters: { type: 'object', properties: {} }
  },
  handler: lambda { |_args|
    PWN::Plugins::Findings.report
  }
)
