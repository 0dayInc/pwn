# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/mistakes'

# Expose the negative-feedback ledger to the model so it can inspect its
# own recurring failure patterns, RECORD mistakes it recognises
# semantically (not just tool-dispatch errors), and — critically — RESOLVE
# them with an explicit fix, which is then re-injected into every future
# system prompt as an actionable "do THIS instead" lesson AND handed
# straight back inline on the next recurrence via
# Mistakes.correction_hint.

PWN::AI::Agent::Registry.register(
  name: 'mistakes_list',
  toolset: 'learning',
  schema: {
    name: 'mistakes_list',
    description: 'List recorded failure fingerprints from ~/.pwn/mistakes.json ' \
                 '(signature, tool, normalised error, count, first/last seen, ' \
                 'resolved, fix). Sorted by recurrence count. These are the ' \
                 'specific mistakes the agent keeps making — inspect before ' \
                 'attempting the same tool again, and call mistakes_resolve ' \
                 'once a working alternative is found.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 20 },
        unresolved_only: { type: 'boolean', default: true }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Mistakes) },
  handler: lambda { |args|
    PWN::AI::Agent::Mistakes.top(
      limit: args[:limit] || 20,
      unresolved_only: args.key?(:unresolved_only) ? args[:unresolved_only] : true
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'mistakes_record',
  toolset: 'learning',
  schema: {
    name: 'mistakes_record',
    description: 'Proactively fingerprint a mistake YOU just made (wrong ' \
                 'assumption, wrong file edited, bad approach, hallucinated ' \
                 'API) so the negative-feedback loop captures failures that ' \
                 'are NOT tool-dispatch errors. The (tool, error) pair is ' \
                 'normalised and its cross-session count incremented; once ' \
                 'count ≥ 3 it is flagged [REPEATING] in every future system ' \
                 'prompt. Follow up with mistakes_resolve when you find the fix.',
    parameters: {
      type: 'object',
      properties: {
        tool: {
          type: 'string',
          description: 'Component / area the mistake was in (e.g. "assumption", "shell", "pwn_eval", "plan", a module name).'
        },
        error: { type: 'string', description: 'What went wrong, in your own words.' },
        args: { type: 'string', description: 'Optional sample of the input that triggered it.' }
      },
      required: %w[tool error]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Mistakes) },
  handler: lambda { |args|
    sid = (PWN::Env.dig(:ai, :session_id) if defined?(PWN::Env))
    PWN::AI::Agent::Mistakes.record(
      tool: args[:tool], error: args[:error], args: args[:args],
      session_id: sid, source: :model
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'mistakes_resolve',
  toolset: 'learning',
  schema: {
    name: 'mistakes_resolve',
    description: 'Mark a recorded mistake as RESOLVED and attach the fix ' \
                 '(what to do INSTEAD). The fix is (a) promoted to a ' \
                 'PWN::Memory :lesson so every future run sees "AVOID X — ' \
                 'FIX: Y" in its system prompt, AND (b) handed straight back ' \
                 'inline via correction_hint the next time that signature ' \
                 'recurs. If the same signature recurs after resolution it is ' \
                 'automatically re-opened and tagged [REGRESSED]. Call this ' \
                 'the moment you find a working alternative to a ' \
                 'previously-failing approach.',
    parameters: {
      type: 'object',
      properties: {
        signature: { type: 'string', description: 'Mistake signature from mistakes_list / KNOWN MISTAKES block / correction_hint.' },
        fix: { type: 'string', description: 'What to do instead next time.' }
      },
      required: %w[signature fix]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Mistakes) },
  handler: lambda { |args|
    PWN::AI::Agent::Mistakes.resolve(signature: args[:signature], fix: args[:fix])
  }
)

PWN::AI::Agent::Registry.register(
  name: 'mistakes_reset',
  toolset: 'learning',
  schema: {
    name: 'mistakes_reset',
    description: 'Wipe ~/.pwn/mistakes.json (all recorded failure fingerprints ' \
                 'and their fixes). Use only when moving to a new host/engagement ' \
                 'where prior failure patterns no longer apply. IRREVERSIBLE — ' \
                 'must pass confirm:true.',
    parameters: {
      type: 'object',
      properties: {
        confirm: { type: 'boolean', description: 'Must be true to actually reset.' }
      },
      required: %w[confirm]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Mistakes) },
  handler: lambda { |args|
    raise ArgumentError, 'refusing to reset mistakes without confirm:true' unless args[:confirm] == true

    before = PWN::AI::Agent::Mistakes.load.keys.length
    PWN::AI::Agent::Mistakes.reset
    { reset: true, mistakes_cleared: before, file: PWN::AI::Agent::Mistakes::MISTAKES_FILE }
  }
)
