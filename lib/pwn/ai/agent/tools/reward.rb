# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/reward'

# Expose the Outcome/Process Reward Model + preference-pair ledger to the
# model so it can (a) score itself, (b) inspect whether its own success
# metric is reward-hacked, and (c) export DPO datasets for weight-level
# self-improvement.

PWN::AI::Agent::Registry.register(
  name: 'reward_judge',
  toolset: 'learning',
  schema: {
    name: 'reward_judge',
    description: 'R1 — LLM Outcome Reward Model. Score a (request, final) pair ' \
                 '→ {score:0..1, verdict: solved|partial|wrong|refused, ' \
                 'rationale:}. Grounds via extro_verify when the final ' \
                 'contains a checkable claim (E3). This is the reward signal ' \
                 'that replaced the regex proxy.',
    parameters: {
      type: 'object',
      properties: {
        request: { type: 'string' },
        final: { type: 'string' },
        session_id: { type: 'string', description: 'Adds tool trace for evidence.' }
      },
      required: %w[request final]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Reward) },
  handler: lambda { |args|
    PWN::AI::Agent::Reward.judge(request: args[:request], final: args[:final], session_id: args[:session_id], commit: false)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'reward_prm',
  toolset: 'learning',
  schema: {
    name: 'reward_prm',
    description: 'R2 — Process Reward Model. Per-tool-step credit assignment: ' \
                 'which steps in a session ADVANCED the goal (+1), were ' \
                 'neutral (0), or regressed (−1). Tags each transcript line ' \
                 'with step_reward so distill_skill / exemplars_for keep only ' \
                 'the minimal sufficient trace (C4).',
    parameters: {
      type: 'object',
      properties: {
        request: { type: 'string' },
        session_id: { type: 'string' }
      },
      required: %w[request session_id]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Reward) },
  handler: ->(args) { PWN::AI::Agent::Reward.prm(request: args[:request], session_id: args[:session_id]) }
)

PWN::AI::Agent::Registry.register(
  name: 'reward_sentinel',
  toolset: 'learning',
  schema: {
    name: 'reward_sentinel',
    description: 'R3 — Reward-hacking detector. Compares proxy success_rate ' \
                 'vs judge_mean vs (1 − user_correction_rate). When they ' \
                 'diverge by >0.15 the reward signal itself is fingerprinted ' \
                 'as a Mistake so KNOWN MISTAKES warns "your success_rate is ' \
                 'a lie".',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::AI::Agent::Reward) },
  handler: ->(_args) { PWN::AI::Agent::Reward.sentinel }
)

PWN::AI::Agent::Registry.register(
  name: 'reward_preferences',
  toolset: 'learning',
  schema: {
    name: 'reward_preferences',
    description: 'W1 — Read the preference-pair ledger (~/.pwn/preferences.jsonl). ' \
                 'Every user_correction, mistakes_resolve, counterfactual A/B, ' \
                 'and critic self-correct produces a (prompt, rejected, chosen) ' \
                 'triple here — the raw material for DPO.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 50 },
        source: { type: 'string', enum: %w[user_correction mistakes_resolve counterfactual critic curriculum] }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Reward) },
  handler: ->(args) { PWN::AI::Agent::Reward.preferences(limit: args[:limit] || 50, source: args[:source]) }
)

PWN::AI::Agent::Registry.register(
  name: 'reward_export_dpo',
  toolset: 'learning',
  schema: {
    name: 'reward_export_dpo',
    description: 'W1 — Export the preference-pair ledger as a DPO/KTO/ORPO ' \
                 'jsonl dataset under ~/.pwn/finetune/. Enforces ≤40% per ' \
                 'source (DPO_SOURCE_CAP) so resolve-monoculture cannot poison ' \
                 'LoRA; pass balance:false for a raw dump. Pair with ' \
                 'curriculum_train for the weight loop.',
    parameters: {
      type: 'object',
      properties: {
        format: { type: 'string', enum: %w[dpo kto orpo], default: 'dpo' },
        out: { type: 'string' },
        balance: { type: 'boolean', default: true, description: 'Downsample to ≤40% per source (default true).' },
        source_cap: { type: 'number', description: 'Override DPO_SOURCE_CAP (default 0.40).' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Reward) },
  handler: lambda { |args|
    PWN::AI::Agent::Reward.export_dpo(
      format: args[:format],
      out: args[:out],
      balance: args.key?(:balance) ? args[:balance] : true,
      source_cap: args[:source_cap]
    )
  }
)
