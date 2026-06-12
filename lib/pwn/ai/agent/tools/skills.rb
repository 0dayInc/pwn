# frozen_string_literal: true

require 'fileutils'
require 'pwn/ai/agent/registry'

# Thin wrappers around the PWN::Skills store (~/.pwn/skills/*.md) so the
# model can list/read/write reusable procedures. PromptBuilder injects
# the index (name + first line); skill_view loads the full body on demand.

PWN::AI::Agent::Registry.register(
  name: 'skill_list',
  toolset: 'skills',
  schema: {
    name: 'skill_list',
    description: 'List available pwn-ai skills (name + first line of content).',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |_args|
    PWN::Skills.map do |name, meta|
      { name: name, type: meta[:type], summary: meta[:content].to_s.lines.first.to_s.strip[0, 120] }
    end
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_view',
  toolset: 'skills',
  schema: {
    name: 'skill_view',
    description: 'Read the full content of a named skill.',
    parameters: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: %w[name]
    }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |args|
    key = args[:name].to_s.to_sym
    meta = PWN::Skills[key]
    raise ArgumentError, "no such skill: #{key}" unless meta

    { name: key, type: meta[:type], path: meta[:path], content: meta[:content] }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_create',
  toolset: 'skills',
  schema: {
    name: 'skill_create',
    description: 'Save a new reusable skill (markdown procedure) to ~/.pwn/skills/. ' \
                 'It will be listed in every future pwn-ai system prompt.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'lowercase, hyphens/underscores only' },
        content: { type: 'string', description: 'Full markdown body of the skill.' }
      },
      required: %w[name content]
    }
  },
  check: -> { defined?(PWN::Config) && PWN::Config.respond_to?(:pwn_skills_path) },
  handler: lambda { |args|
    name = args[:name].to_s.gsub(/[^a-z0-9_-]/i, '_')
    raise ArgumentError, 'name is required' if name.empty?

    dir = PWN::Config.pwn_skills_path
    FileUtils.mkdir_p(dir)
    path = File.join(dir, "#{name}.md")
    File.write(path, args[:content].to_s)
    PWN::Config.load_skills(pwn_skills_path: dir) # refresh PWN::Skills const
    { saved: true, path: path, total: PWN::Skills.keys.length }
  }
)
