# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'finding_record',
  toolset: 'pwn',
  schema: {
    name: 'finding_record',
    description: 'Record a validated finding with CVSS 3.x, evidence file paths and a required command/code PoC. File existence is not execution proof. Also supports query, chain and export.',
    parameters: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        cwe: { type: 'string', pattern: '^CWE-[1-9][0-9]*$' },
        cvss_vector: { type: 'string' },
        cvss_score: { type: 'number', minimum: 0, maximum: 10 },
        affected_asset: { type: 'string' },
        evidence_paths: { type: 'array', minItems: 1, items: { type: 'string' } },
        attack_chain_refs: { type: 'array', items: { type: 'string' } },
        remediation: { type: 'string' },
        confidence: { type: 'number', minimum: 0, maximum: 1 },
        dir_path: { type: 'string' },
        report_name: { type: 'string' },
        severity: { type: 'string' },
        host: { type: 'string' },
        evidence: { type: 'string' },
        poc: { type: 'string' },
        poc_artifacts: { type: 'array', items: { type: 'string' } },
        session_id: { type: 'string' },
        op: { type: 'string', enum: %w[query export chain record verify retest chain_impact gaps] },
        parent_id: { type: 'string' },
        engagement_id: { type: 'string' },
        kind: { type: 'string', enum: %w[http script] },
        impact: { type: 'string' },
        request_path: { type: 'string' },
        response_path: { type: 'string' },
        execution_log: { type: 'string' },
        ids: { type: 'array', items: { type: 'string' } },
        combined_impact_path: { type: 'string' },
        escalate: { type: 'boolean' },
        combined_severity: { type: 'string' }
      },
      required: %w[],
      anyOf: [
        { properties: { op: { enum: %w[query export] } }, required: %w[op] },
        { required: %w[title cwe cvss_vector cvss_score affected_asset evidence_paths poc attack_chain_refs remediation confidence] }
      ]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    op = (args[:op] || 'record').to_s
    case op
    when 'query'
      PWN::Plugins::Findings.query(args)
    when 'chain'
      parent = args[:parent_id].to_s
      raise ArgumentError, 'parent_id is required' if parent.empty?

      PWN::Plugins::Findings.record_structured(args.merge(attack_chain_refs: (Array(args[:attack_chain_refs]) + [parent]).uniq))
    when 'export'
      PWN::Plugins::Findings.render(args)
    when 'verify'
      PWN::Plugins::Findings.verify(args)
    when 'retest'
      PWN::Plugins::Findings.retest(args)
    when 'chain_impact'
      PWN::Plugins::Findings.chain_impact(args)
    when 'gaps'
      PWN::Plugins::Findings.issue_work_gaps(args)
    when 'record'
      PWN::Plugins::Findings.record_structured(args)
    else
      raise ArgumentError, "unknown finding operation: #{op}"
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
PWN::AI::Agent::Registry.register(
  name: 'chain_score',
  toolset: 'pwn',
  schema: {
    name: 'chain_score',
    description: 'Recompute combined severity when findings are chained (e.g. SSRF + metadata).',
    parameters: {
      type: 'object',
      properties: {
        ids: { type: 'array', items: { type: 'string' } },
        chain_refs: { type: 'array', items: { type: 'string' } }
      }
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Findings.chain_score(ids: args[:ids] || args['ids'], chain_refs: args[:chain_refs] || args['chain_refs'])
  }
)
