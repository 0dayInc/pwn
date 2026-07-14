# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/curriculum'

# Expose the self-play / weight-loop layer so the model (or a cron job) can
# trigger practice on its own weaknesses, and so an operator can kick off
# the LoRA A/B gate from inside the REPL.

PWN::AI::Agent::Registry.register(
  name: 'curriculum_practice',
  toolset: 'learning',
  schema: {
    name: 'curriculum_practice',
    description: 'S1 — Mistake-driven auto-curriculum. Reads the top-N ' \
                 'unresolved Mistakes, generates minimal reproducer prompts, ' \
                 'self-plays each under Reward.judge, and auto-resolves any ' \
                 'signature the practice run solved. THE AGENT PRACTISES ITS ' \
                 'OWN WEAKNESSES. Cron this nightly.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 3, description: 'Top-N unresolved mistakes to practise.' },
        prompts_per: { type: 'integer', default: 2 },
        dry_run: { type: 'boolean', default: false, description: 'Generate prompts but do not self-play.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Curriculum) },
  handler: ->(args) { PWN::AI::Agent::Curriculum.practice(limit: args[:limit], prompts_per: args[:prompts_per], dry_run: args[:dry_run]) }
)

PWN::AI::Agent::Registry.register(
  name: 'curriculum_train',
  toolset: 'learning',
  schema: {
    name: 'curriculum_train',
    description: 'W2 — Online LoRA A/B with regression gate. export_finetune + ' \
                 'export_dpo → unsloth/axolotl LoRA → ollama create pwn-vN+1 → ' \
                 'replay Mistakes.top on vN vs vN+1 under Reward.judge → ' \
                 'promote iff resolved(N+1) > resolved(N). Fully autonomous ' \
                 'weight-level self-improvement. dry_run:true (default) exports ' \
                 'datasets + eval set + manual CLI without training.',
    parameters: {
      type: 'object',
      properties: {
        base_model: { type: 'string' },
        trainer: { type: 'string', enum: %w[unsloth axolotl auto] },
        dry_run: { type: 'boolean', default: true }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Curriculum) },
  handler: ->(args) { PWN::AI::Agent::Curriculum.train_and_gate(base_model: args[:base_model], trainer: args[:trainer], dry_run: args.key?(:dry_run) ? args[:dry_run] : true) }
)

PWN::AI::Agent::Registry.register(
  name: 'curriculum_hindsight',
  toolset: 'learning',
  schema: {
    name: 'curriculum_hindsight',
    description: 'C3 — Hindsight Experience Replay. On a failed goal, ask the ' \
                 'judge "what DID this trajectory accomplish?" and relabel it ' \
                 'as success:true for the achieved-goal. Free positive samples ' \
                 'from failures — first HER on real tool traces.',
    parameters: {
      type: 'object',
      properties: {
        request: { type: 'string' },
        final: { type: 'string' },
        session_id: { type: 'string' }
      },
      required: %w[request final session_id]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Curriculum) },
  handler: ->(args) { PWN::AI::Agent::Curriculum.hindsight(request: args[:request], final: args[:final], session_id: args[:session_id]) }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_purge_noise',
  toolset: 'learning',
  schema: {
    name: 'learning_purge_noise',
    description: 'One-shot GC of pre-R1 garbage in PWN::Memory: drops every ' \
                 '`SUCCESS: <req> — <final>` and `Avoid repeating failure ' \
                 'pattern from X: {"success":true` shaped :lesson. Run once ' \
                 'after upgrading — subsequent writes never produce these.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: ->(_args) { PWN::AI::Agent::Learning.purge_noise }
)
