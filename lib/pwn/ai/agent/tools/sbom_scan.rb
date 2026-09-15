# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'sbom_scan',
  toolset: 'pwn',
  schema: {
    name: 'sbom_scan',
    description: 'Scan a lockfile, directory, or image for known CVEs via syft, grype, trivy, or osv-scanner.',
    parameters: {
      type: 'object',
      properties: {
        path_or_image: { type: 'string' },
        path: { type: 'string' },
        image: { type: 'string' },
        engine: { type: 'string' },
        record: { type: 'boolean' }
      }
    }
  },
  handler: lambda { |args|
    PWN::Plugins::SBOM.scan(args.transform_keys(&:to_sym))
  }
)
