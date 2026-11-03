# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'workspace_tool',
  toolset: 'pwn',
  schema: {
    name: 'workspace_tool',
    description: 'Run one provider-hosted tool. Open WebUI workspace tools, including Ask Jev, execute on that server and are not mixed into the client tools array. Other engines expose only their own hosted tools, such as web_search, google_search, or x_search. Ollama has none. Omit name to list the Open WebUI workspace.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Workspace tool name, such as Ask Jev, or a hosted tool name such as web_search.' },
        request: { type: 'string', description: 'Question or state to send with the tool. Required unless name is omitted to list Open WebUI tools.' },
        engine: { type: 'string', description: 'Optional provider. Ask Jev uses Open WebUI when that provider is configured, even if another model is active.' }
      },
      required: []
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    if args[:name].to_s.strip.empty?
      PWN::AI::ServerTools.list(engine: :openwebui)
    else
      PWN::AI::ServerTools.call(name: args[:name], request: args[:request], engine: args[:engine])
    end
  }
)
