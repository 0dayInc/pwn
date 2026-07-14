# frozen_string_literal: true

require 'spec_helper'

# ─────────────────────────────────────────────────────────────────────────────
#  #10 — docs drift is a recurring RECENT FAILURES theme. NON-BLOCKING:
#  filesystem + regex only. Bidirectional checks are direction-gated so
#  the spec asserts the invariants that CANNOT drift silently while
#  leaving the softer "not yet documented / not yet spec'd" to a warning.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'documentation ↔ code sync', :aggregate_failures do
  root    = File.expand_path('../..', __dir__)
  doc_dir = File.join(root, 'documentation')

  it 'every registered toolset is documented; every documented tool is still registered' do
    PWN::AI::Agent::Registry.discover(force: true)
    entries = PWN::AI::Agent::Registry.all
    body    = File.read(File.join(doc_dir, 'Agent-Tool-Registry.md'))

    # HARD: a toolset the model can be granted must be explained in docs.
    missing_sets = entries.map(&:toolset).uniq.reject { |ts| body.include?("`#{ts}`") }
    expect(missing_sets).to be_empty, "toolsets registered but undocumented: #{missing_sets}"

    # HARD: dead docs — a `tool_name` in the "| toolset | tools |" table
    # that is no longer registered (only the ·-separated tools column is
    # scanned so config keys mentioned in prose don't false-positive).
    reg_names = entries.map(&:name)
    doc_tools = body.lines.grep(/\A\|\s*`[a-z_]+`\s*\|/).flat_map do |row|
      row.split('|')[2].to_s.scan(/`([a-z][a-z0-9_]+)`/).flatten
    end.uniq
    dead = doc_tools - reg_names
    expect(dead).to be_empty, "documented tools that are no longer registered: #{dead}"

    # SOFT: individual registered-but-undocumented tools → surface, don't fail
    # (promote to `expect` once Agent-Tool-Registry.md is caught up).
    undoc = reg_names.reject { |n| body.include?(n) }
    warn "[doc-sync] tools registered but undocumented: #{undoc}" unless undoc.empty?
  end

  it 'every documentation/*.md relative link / image resolves to an existing file' do
    broken = []
    Dir[File.join(doc_dir, '**', '*.md')].each do |md|
      File.read(md).scan(/\]\((?!https?:|#|mailto:)([^)\s]+)\)/).flatten.each do |ref|
        clean = ref.split('#', 2).first.to_s
        next if clean.empty?

        candidates = [
          File.expand_path(clean, File.dirname(md)),
          File.expand_path(clean, doc_dir),
          File.expand_path(clean, root)
        ]
        broken << "#{File.basename(md)} -> #{ref}" unless candidates.any? { |p| File.exist?(p) }
      end
    end
    expect(broken).to be_empty, "broken relative links:\n  #{broken.join("\n  ")}"
  end

  it 'every RL feature-id described in reinforced_feedback_loop_spec.rb is documented' do
    rl_doc  = File.read(File.join(doc_dir, 'Reinforcement-Learning.md'))
    rl_spec = File.read(File.join(root, 'spec', 'integration', 'reinforced_feedback_loop_spec.rb'))
    doc_ids  = rl_doc.scan(/\b([RWCEMS][1-9])\b/).flatten.uniq
    spec_ids = rl_spec.scan(/describe '([RWCEMS][1-9]) ·/).flatten.uniq
    undoc = spec_ids - doc_ids
    expect(undoc).to be_empty, "RL spec exercises undocumented feature-ids: #{undoc}"
    warn "[doc-sync] documented-but-unspec'd RL ids: #{(doc_ids - spec_ids).sort}" unless (doc_ids - spec_ids).empty?
  end

  it 'every PWN::Setup::PROFILES key is mentioned in Installation.md' do
    body = File.read(File.join(doc_dir, 'Installation.md'))
    missing = PWN::Setup::PROFILES.keys.map(&:to_s).reject { |k| body.include?(k) }
    expect(missing).to be_empty, "setup profiles undocumented in Installation.md: #{missing}"
  end
end
