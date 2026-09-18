# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'nuclei_scan',
  toolset: 'pwn',
  schema: {
    name: 'nuclei_scan',
    description: 'Run or ingest nuclei JSONL (optionally after httpx tech-detect). Records web findings with matched-at URL, template id, and severity into the findings store.',
    parameters: {
      type: 'object',
      properties: {
        jsonl: { type: 'string', description: 'nuclei JSONL path or raw JSONL (skips the nuclei binary).' },
        target: { type: 'string' },
        url: { type: 'string' },
        httpx_jsonl: { type: 'string', description: 'httpx JSONL used to select nuclei tags by tech stack.' },
        techs: { type: 'array', items: { type: 'string' } },
        record: { type: 'boolean' },
        templates: { type: 'string' },
        severity: { type: 'string' }
      }
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    techs = Array(args[:techs])
    techs = PWN::Plugins::Httpx.probe(jsonl: args[:httpx_jsonl])[:techs] if techs.empty? && !args[:httpx_jsonl].to_s.empty?
    PWN::Plugins::Nuclei.scan(args.merge(techs: techs, record: args.fetch(:record, true)))
  }
)
