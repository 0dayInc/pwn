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
        session_id: { type: 'string' },
        op: { type: 'string' },
        parent_id: { type: 'string' },
        engagement_id: { type: 'string' }
      },
      required: %w[]
    }
  },
  handler: lambda { |args|
    op = (args[:op] || args['op'] || 'record').to_s
    case op
    when 'query'
      PWN::Plugins::Findings.query(host: args[:host] || args['host'])
    when 'chain'
      PWN::Plugins::Findings.chain(
        parent_id: args[:parent_id] || args['parent_id'],
        title: args[:title] || args['title'],
        severity: args[:severity] || args['severity'],
        poc_artifacts: args[:poc_artifacts] || args['poc_artifacts'],
        poc: args[:poc] || args['poc'],
        session_id: args[:session_id] || args['session_id']
      )
    when 'export'
      PWN::Plugins::Findings.render(report_name: 'findings')
    else
      PWN::Plugins::Findings.record(
        title: args[:title] || args['title'],
        severity: args[:severity] || args['severity'],
        host: args[:host] || args['host'],
        evidence: args[:evidence] || args['evidence'],
        poc: args[:poc] || args['poc'],
        poc_artifacts: args[:poc_artifacts] || args['poc_artifacts'],
        session_id: args[:session_id] || args['session_id'],
        engagement_id: args[:engagement_id] || args['engagement_id']
      )
    end
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
