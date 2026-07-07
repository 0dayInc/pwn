# frozen_string_literal: true

require 'fileutils'
require 'pwn/ai/agent/registry'

# Thin wrappers around the PWN::Skills store (~/.pwn/skills/*.md) so the
# model can list/read/write reusable procedures. PromptBuilder injects
# the index (name + first line); skill_view loads the full body on demand.
#
# Each skill may carry a :references Array (URLs, CWE/CVE/ATT&CK ids,
# NIST 800-53 controls, docs) parsed from YAML front-matter or a
# "## References" markdown section. References let the agent cite
# authoritative sources when applying a skill and mirror the
# PWN::SAST::*.security_references convention.

PWN::AI::Agent::Registry.register(
  name: 'skill_list',
  toolset: 'skills',
  schema: {
    name: 'skill_list',
    description: 'List available pwn-ai skills (name + first line + reference count).',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |_args|
    PWN::Skills.map do |name, meta|
      {
        name: name,
        type: meta[:type],
        summary: meta[:content].to_s.lines.first.to_s.strip[0, 120],
        references: Array(meta[:references]).length
      }
    end
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_view',
  toolset: 'skills',
  schema: {
    name: 'skill_view',
    description: 'Read the full content of a named skill, including its references.',
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

    {
      name: key,
      type: meta[:type],
      path: meta[:path],
      references: Array(meta[:references]),
      content: meta[:content]
    }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_create',
  toolset: 'skills',
  schema: {
    name: 'skill_create',
    description: 'Save a new reusable skill (markdown procedure) to ~/.pwn/skills/. ' \
                 'It will be listed in every future pwn-ai system prompt. Optionally ' \
                 'attach references (URLs, CWE/CVE ids, MITRE ATT&CK, NIST 800-53, docs).',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'lowercase, hyphens/underscores only' },
        content: { type: 'string', description: 'Full markdown body of the skill.' },
        references: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional list of reference URLs / identifiers (CWE-79, T1059, ' \
                       'https://..., NIST SI-3, etc.). Written as YAML front-matter and ' \
                       'a "## References" section.'
        }
      },
      required: %w[name content]
    }
  },
  check: -> { defined?(PWN::Config) && PWN::Config.respond_to?(:pwn_skills_path) },
  handler: lambda { |args|
    name = args[:name].to_s.gsub(/[^a-z0-9_-]/i, '_')
    raise ArgumentError, 'name is required' if name.empty?

    body = args[:content].to_s
    refs = Array(args[:references]).map(&:to_s).map(&:strip).reject(&:empty?).uniq

    unless refs.empty?
      # YAML front-matter (only if body doesn't already have one)
      unless body.start_with?("---\n")
        fm = "---\nreferences:\n#{refs.map { |r| "  - #{r}" }.join("\n")}\n---\n"
        body = fm + body
      end
      # ## References section (only if not already present)
      body = "#{body.rstrip}\n\n## References\n#{refs.map { |r| "- #{r}" }.join("\n")}\n" unless body =~ /^\#{1,3}\s*References\s*$/i
    end

    dir = PWN::Config.pwn_skills_path
    FileUtils.mkdir_p(dir)
    path = File.join(dir, "#{name}.md")
    File.write(path, body)
    PWN::Config.load_skills(pwn_skills_path: dir) # refresh PWN::Skills const
    { saved: true, path: path, references: refs, total: PWN::Skills.keys.length }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_add_reference',
  toolset: 'skills',
  schema: {
    name: 'skill_add_reference',
    description: 'Append one or more references (URL, CWE/CVE id, MITRE ATT&CK ' \
                 'technique, NIST control, doc link) to an existing skill.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Existing skill name.' },
        references: { type: 'array', items: { type: 'string' } }
      },
      required: %w[name references]
    }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |args|
    key  = args[:name].to_s.to_sym
    meta = PWN::Skills[key]
    raise ArgumentError, "no such skill: #{key}" unless meta

    new_refs = Array(args[:references]).map(&:to_s).map(&:strip).reject(&:empty?)
    raise ArgumentError, 'references must be a non-empty array' if new_refs.empty?

    body     = File.read(meta[:path])
    existing = Array(meta[:references])
    add      = (new_refs - existing)

    if body =~ /^(\#{1,3}\s*References\s*)$/i
      # Append bullets right after the References heading block (end of file safest)
      body = "#{body.rstrip}\n#{add.map { |r| "- #{r}" }.join("\n")}\n" unless add.empty?
    else
      body = "#{body.rstrip}\n\n## References\n#{(existing + add).uniq.map { |r| "- #{r}" }.join("\n")}\n"
    end

    File.write(meta[:path], body)
    PWN::Config.load_skills(pwn_skills_path: File.dirname(meta[:path]))
    {
      saved: true,
      name: key,
      path: meta[:path],
      added: add,
      references: Array(PWN::Skills[key][:references])
    }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_delete',
  toolset: 'skills',
  schema: {
    name: 'skill_delete',
    description: 'Delete a skill from ~/.pwn/skills/ by name. Use to prune ' \
                 'low-quality auto-distilled skills so they stop appearing ' \
                 'in every future system prompt. Irreversible.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Existing skill name (basename without extension).' }
      },
      required: %w[name]
    }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |args|
    key  = args[:name].to_s.to_sym
    meta = PWN::Skills[key]
    raise ArgumentError, "no such skill: #{key}" unless meta

    path = meta[:path]
    dir  = File.dirname(path)
    FileUtils.rm_f(path)
    PWN::Config.load_skills(pwn_skills_path: dir)
    { deleted: true, name: key, path: path, remaining: PWN::Skills.keys.length }
  }
)
