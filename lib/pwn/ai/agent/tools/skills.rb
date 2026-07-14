# frozen_string_literal: true

require 'fileutils'
require 'pwn/ai/agent/registry'

# Thin wrappers around the PWN::Skills store so the model can list / read /
# write reusable procedures. PromptBuilder injects the index (name +
# description); skill_view loads the full body on demand — the two-tier
# progressive-disclosure pattern from https://agentskills.io/specification.
#
# On disk (spec-conformant, written by PWN::Config.write_skill):
#   ~/.pwn/skills/<name>/SKILL.md      ← YAML frontmatter (name, description, …)
#   ~/.pwn/skills/<name>/scripts/      ← optional executable helpers
#   ~/.pwn/skills/<name>/references/   ← optional supporting docs
#
# Legacy flat ~/.pwn/skills/<name>.md files are still LOADED (format:
# :legacy) so existing installs keep working; new writes always use the
# directory layout. Run PWN::Config.migrate_legacy_skills to convert.
#
# Each skill may carry a :references Array (URLs, CWE/CVE/ATT&CK ids,
# NIST 800-53 controls, docs) parsed from frontmatter `metadata.references`
# and/or a "## References" markdown section — mirroring the
# PWN::SAST::*.security_references convention.

PWN::AI::Agent::Registry.register(
  name: 'skill_list',
  toolset: 'skills',
  schema: {
    name: 'skill_list',
    description: 'List available pwn-ai skills (name + description + reference count + format).',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |_args|
    PWN::Skills.map do |name, meta|
      {
        name: name,
        type: meta[:type],
        format: meta[:format] || :legacy,
        description: (meta[:description] || meta[:content].to_s.lines.first.to_s.strip)[0, 200],
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
    description: 'Read the full content of a named skill, including its frontmatter and references.',
    parameters: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: %w[name]
    }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |args|
    key = args[:name].to_s.to_sym
    meta = PWN::Skills[key] || PWN::Skills[PWN::Config.sanitize_skill_name(name: key).to_sym]
    raise ArgumentError, "no such skill: #{key}" unless meta

    {
      name: key,
      type: meta[:type],
      format: meta[:format] || :legacy,
      path: meta[:path],
      dir: meta[:dir],
      description: meta[:description],
      frontmatter: meta[:frontmatter] || {},
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
    description: 'Save a new reusable skill to ~/.pwn/skills/<name>/SKILL.md ' \
                 '(agentskills.io format: required name + description YAML ' \
                 'frontmatter). Appears in every future pwn-ai system prompt. ' \
                 'Optionally attach references (URLs, CWE/CVE ids, MITRE ' \
                 'ATT&CK, NIST 800-53, docs) and an allowed-tools allowlist.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Free-form; sanitised to [a-z0-9-]{1,64} per spec.' },
        description: { type: 'string', description: '1..1024 char summary shown in the SKILLS index. Derived from body when omitted.' },
        content: { type: 'string', description: 'Full markdown body of the skill (WITHOUT frontmatter — it is generated).' },
        references: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional list of reference URLs / identifiers (CWE-79, T1059, ' \
                       'https://..., NIST SI-3, etc.). Written under frontmatter ' \
                       'metadata.references and as a "## References" section.'
        },
        license: { type: 'string', description: 'Optional SPDX identifier or free text.' },
        allowed_tools: { type: 'array', items: { type: 'string' }, description: 'Optional toolset allowlist for this skill.' },
        metadata: { type: 'object', description: 'Optional arbitrary metadata hash.' }
      },
      required: %w[name content]
    }
  },
  check: -> { defined?(PWN::Config) && PWN::Config.respond_to?(:write_skill) },
  handler: lambda { |args|
    root = PWN::Config.pwn_skills_path
    out  = PWN::Config.write_skill(
      name: args[:name],
      description: args[:description],
      content: args[:content],
      references: args[:references],
      license: args[:license],
      allowed_tools: args[:allowed_tools],
      metadata: args[:metadata],
      pwn_skills_path: root
    )
    PWN::Config.load_skills(pwn_skills_path: root)
    out.merge(saved: true, total: PWN::Skills.keys.length)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_add_reference',
  toolset: 'skills',
  schema: {
    name: 'skill_add_reference',
    description: 'Append one or more references (URL, CWE/CVE id, MITRE ATT&CK ' \
                 'technique, NIST control, doc link) to an existing skill. ' \
                 'Rewrites frontmatter metadata.references + ## References section.',
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
    meta = PWN::Skills[key] || PWN::Skills[PWN::Config.sanitize_skill_name(name: key).to_sym]
    raise ArgumentError, "no such skill: #{key}" unless meta

    new_refs = Array(args[:references]).map(&:to_s).map(&:strip).reject(&:empty?)
    raise ArgumentError, 'references must be a non-empty array' if new_refs.empty?

    root     = PWN::Config.pwn_skills_path
    existing = Array(meta[:references])
    combined = (existing + new_refs).uniq
    added    = combined - existing

    if meta[:format] == :agentskills
      # Rewrite via the canonical writer so frontmatter stays valid.
      body = PWN::Config.parse_skill_frontmatter(content: meta[:content])[:body]
                        .to_s.sub(/^\#{1,3}\s*References\s*$.*\z/mi, '').rstrip
      PWN::Config.write_skill(
        name: key.to_s,
        description: meta[:description],
        content: body,
        references: combined,
        license: (meta[:frontmatter] || {})['license'],
        allowed_tools: meta[:allowed_tools],
        metadata: (meta[:frontmatter] || {})['metadata'],
        pwn_skills_path: root
      )
    else
      # Legacy flat file — append to (or create) the ## References section in place.
      body = File.read(meta[:path])
      body = if body =~ /^(\#{1,3}\s*References\s*)$/i
               "#{body.rstrip}\n#{added.map { |r| "- #{r}" }.join("\n")}\n"
             else
               "#{body.rstrip}\n\n## References\n#{combined.map { |r| "- #{r}" }.join("\n")}\n"
             end
      File.write(meta[:path], body)
    end

    PWN::Config.load_skills(pwn_skills_path: root)
    reloaded = PWN::Skills[key] || PWN::Skills[PWN::Config.sanitize_skill_name(name: key).to_sym]
    {
      saved: true,
      name: key,
      path: reloaded[:path],
      added: added,
      references: Array(reloaded[:references])
    }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_delete',
  toolset: 'skills',
  schema: {
    name: 'skill_delete',
    description: 'Delete a skill from ~/.pwn/skills/ by name. Removes the ' \
                 'entire <name>/ directory (agentskills format) or the flat ' \
                 'file (legacy). Use to prune low-quality auto-distilled ' \
                 'skills so they stop appearing in every future system prompt. ' \
                 'Irreversible.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Existing skill name.' }
      },
      required: %w[name]
    }
  },
  check: -> { defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) },
  handler: lambda { |args|
    key  = args[:name].to_s.to_sym
    meta = PWN::Skills[key] || PWN::Skills[PWN::Config.sanitize_skill_name(name: key).to_sym]
    raise ArgumentError, "no such skill: #{key}" unless meta

    root = PWN::Config.pwn_skills_path
    path = meta[:path]
    if meta[:format] == :agentskills && meta[:dir] && File.basename(File.dirname(path)) == File.basename(meta[:dir])
      FileUtils.rm_rf(meta[:dir])
    else
      FileUtils.rm_f(path)
    end
    PWN::Config.load_skills(pwn_skills_path: root)
    { deleted: true, name: key, path: path, remaining: PWN::Skills.keys.length }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'skill_migrate_legacy',
  toolset: 'skills',
  schema: {
    name: 'skill_migrate_legacy',
    description: 'One-shot: convert every legacy flat ~/.pwn/skills/*.md into ' \
                 'a spec-conformant <name>/SKILL.md with backfilled name + ' \
                 'description frontmatter. Idempotent; safe to re-run.',
    parameters: {
      type: 'object',
      properties: {
        delete_legacy: { type: 'boolean', default: true, description: 'Remove the flat file after migration.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Config) && PWN::Config.respond_to?(:migrate_legacy_skills) },
  handler: lambda { |args|
    PWN::Config.migrate_legacy_skills(delete_legacy: args.fetch(:delete_legacy, true))
  }
)
