# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'finding_record',
  toolset: 'pwn',
  schema: {
    name: 'finding_record',
    description: 'Record a finding with CVSS 3.x, severity justification, ordered reproduction steps, and evidence paths or artifact handles (pcap, screenshot, crash, PoC). Export embeds hash-verified evidence. Hashes are not execution proof.',
    parameters: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        cwe: { type: 'string', pattern: '^CWE-[1-9][0-9]*$' },
        cvss_vector: { type: 'string' },
        cvss_score: { type: 'number', minimum: 0, maximum: 10 },
        affected_asset: { type: 'string' },
        evidence_paths: { type: 'array', minItems: 1, items: { type: 'string' } },
        artifact_handles: {
          type: 'array', minItems: 1,
          items: {
            anyOf: [
              { type: 'string', minLength: 1 },
              { type: 'object', required: %w[handle], additionalProperties: false,
                properties: { handle: { type: 'string', minLength: 1 }, kind: { type: 'string', enum: %w[pcap screenshot crash poc evidence] },
                              label: { type: 'string', minLength: 1 }, sha256: { type: 'string', pattern: '^[0-9a-f]{64}$' } } }
            ]
          }
        },
        severity_justification: { type: 'string', minLength: 1, description: 'Explain demonstrated impact and why it supports the chosen CVSS metrics; do not claim untested escalation.' },
        reproduction_steps: { type: 'array', minItems: 1, items: { type: 'string', minLength: 1 }, description: 'Ordered setup, PoC commands and expected observations for independent reproduction.' },
        attack_chain_refs: { type: 'array', items: { type: 'string' } },
        enables: { type: 'array', uniqueItems: true, items: { type: 'string', minLength: 1 }, description: 'Outgoing finding IDs this finding enables, within the same engagement. Use op=link to update an existing finding.' },
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
        op: { type: 'string', enum: %w[query export chain record link verify retest chain_impact gaps] },
        id: { type: 'string', minLength: 1 },
        parent_id: { type: 'string' },
        engagement_id: { type: 'string' },
        kind: { type: 'string', enum: %w[http script] },
        impact: { type: 'string' },
        request_path: { type: 'string' },
        response_path: { type: 'string' },
        execution_log: { type: 'string' },
        ids: { type: 'array', uniqueItems: true, items: { type: 'string' }, description: 'Ordered source-to-impact finding IDs for chain_impact.' },
        combined_impact_path: { type: 'string' },
        escalate: { type: 'boolean' },
        combined_severity: { type: 'string' }
      },
      required: %w[],
      anyOf: [
        { properties: { op: { enum: %w[query export gaps] } }, required: %w[op] },
        { properties: { op: { enum: %w[verify retest] } }, required: %w[op id kind impact],
          anyOf: [{ required: %w[request_path response_path] }, { required: %w[execution_log] }] },
        { properties: { op: { enum: %w[chain_impact] } }, required: %w[op ids combined_impact_path] },
        { properties: { op: { enum: %w[link] } }, required: %w[op id enables] },
        { properties: { op: { enum: %w[record chain] } }, required: %w[title cwe cvss_vector cvss_score affected_asset poc attack_chain_refs remediation confidence severity_justification reproduction_steps],
          anyOf: [{ required: %w[evidence_paths] }, { required: %w[artifact_handles] }] }
      ]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    op = (args[:op] || 'record').to_s
    if %w[record chain].include?(op)
      raise ArgumentError, 'severity_justification must be a nonempty string' unless args[:severity_justification].is_a?(String) && !args[:severity_justification].strip.empty?
      raise ArgumentError, 'reproduction_steps are required' unless args.key?(:reproduction_steps) && !args[:reproduction_steps].nil?
    end
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
    when 'link'
      PWN::Plugins::Findings.link(args)
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
