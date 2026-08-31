# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/sessions'

PWN::AI::Agent::Registry.register(
  name: 'session_recall',
  toolset: 'sessions',
  schema: {
    name: 'session_recall',
    description: 'Search previous pwn-ai session transcripts (~/.pwn/sessions) ' \
                 'for how a similar request was solved. Current session is ' \
                 'already in RECENT TURNS — this is for older sessions. ' \
                 'Call before pwn_eval / shell when prior method matters.',
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Keywords to match in prior user/assistant turns.' },
        limit: { type: 'integer', default: 12, description: 'Max hits (newest / highest score first).' },
        include_current: { type: 'boolean', default: false, description: 'Also search the active session.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Sessions) },
  handler: lambda { |args|
    exclude = ''
    exclude = PWN::Memory.current_session_id if defined?(PWN::Memory) && PWN::Memory.respond_to?(:current_session_id)
    PWN::Sessions.recall(
      query: args[:query],
      limit: args[:limit] || 12,
      exclude_session_id: exclude,
      include_current: args[:include_current] == true
    ).tap do |hits|
      sid = exclude.to_s
      next if sid.empty? || !defined?(PWN::Plugins::ArtifactRegistry)

      artifacts = PWN::Plugins::ArtifactRegistry.list(session_id: sid)
      hits[:artifacts] = artifacts if hits.is_a?(Hash)
      hits << { artifacts: artifacts } if hits.is_a?(Array) && artifacts.any?
    end
  }
)

# Thin wrappers around PWN::Sessions so the model can DISCOVER and INSPECT
# the JSONL transcripts that learning_reflect / learning_distill_skill
# consume. Without these the model has to blindly `shell("ls ~/.pwn/sessions")`
# and guess a session_id — this closes that gap in the learning loop.

PWN::AI::Agent::Registry.register(
  name: 'sessions_list',
  toolset: 'sessions',
  schema: {
    name: 'sessions_list',
    description: 'List every pwn-ai session transcript in ~/.pwn/sessions ' \
                 '(id, path, size_bytes, mtime, line_count) newest-first. ' \
                 'Use to discover a session_id for learning_reflect / ' \
                 'learning_distill_skill / sessions_view.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 25, description: 'Max sessions to return (newest first).' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Sessions) },
  handler: lambda { |args|
    limit = (args[:limit] || 25).to_i
    PWN::Sessions.list.sort_by { |s| s[:mtime].to_s }.reverse.first(limit)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'sessions_view',
  toolset: 'sessions',
  schema: {
    name: 'sessions_view',
    description: 'Load a session transcript by id and return its entries ' \
                 '(role, timestamp, truncated content). Inspect BEFORE ' \
                 'calling learning_reflect / learning_distill_skill on it.',
    parameters: {
      type: 'object',
      properties: {
        session_id: { type: 'string', description: 'PWN::Sessions id (basename without .jsonl).' },
        max_entries: { type: 'integer', default: 200, description: 'Cap on transcript entries returned.' },
        truncate: { type: 'integer', default: 400, description: 'Chars to keep per entry content.' }
      },
      required: %w[session_id]
    }
  },
  check: -> { defined?(PWN::Sessions) },
  handler: lambda { |args|
    sid   = args[:session_id].to_s
    cap   = (args[:max_entries] || 200).to_i
    trunc = (args[:truncate] || 400).to_i
    rows  = PWN::Sessions.load(session_id: sid)
    raise ArgumentError, "no such session: #{sid}" if rows.empty?

    entries = rows.first(cap).map do |e|
      {
        role: e[:role],
        timestamp: e[:timestamp],
        content: e[:content].to_s[0, trunc]
      }
    end
    { session_id: sid, total_entries: rows.length, returned: entries.length, entries: entries }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'sessions_delete',
  toolset: 'sessions',
  schema: {
    name: 'sessions_delete',
    description: 'Delete a session transcript (~/.pwn/sessions/<id>.jsonl). ' \
                 'Use to prune noisy / failed / dev-experiment transcripts ' \
                 'so the reflect() corpus stays high-signal. Irreversible.',
    parameters: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        force: {
          type: 'boolean',
          description: 'Bypass pin policy for hot/gold/mistake sessions (default false).'
        }
      },
      required: %w[session_id]
    }
  },
  check: -> { defined?(PWN::Sessions) },
  handler: lambda { |args|
    sid = args[:session_id].to_s
    raise ArgumentError, 'session_id is required' if sid.empty?

    {
      session_id: sid,
      deleted: PWN::Sessions.delete(session_id: sid, force: args[:force] == true)
    }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'sessions_stats',
  toolset: 'sessions',
  schema: {
    name: 'sessions_stats',
    description: 'Aggregate stats over all session transcripts: total_sessions, ' \
                 'total_lines, oldest, newest, disk_bytes.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::Sessions) },
  handler: lambda { |_args|
    listing = PWN::Sessions.list
    PWN::Sessions.stats.merge(
      disk_bytes: listing.sum { |s| s[:size].to_i },
      dir: PWN::Sessions.sessions_dir
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'sessions_current',
  toolset: 'sessions',
  schema: {
    name: 'sessions_current',
    description: 'Return the ACTIVE pwn-ai session_id (the one this ' \
                 'conversation is being appended to). Pass it directly to ' \
                 'learning_reflect / learning_distill_skill / sessions_view ' \
                 'without copy-pasting from the system-prompt banner.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::Sessions) },
  handler: lambda { |_args|
    sid = nil
    sid = PWN::Env.dig(:ai, :session_id) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
    sid ||= (Pry.config.pwn_ai_session_id if defined?(Pry) && Pry.respond_to?(:config) && Pry.config.respond_to?(:pwn_ai_session_id))
    path = sid ? File.join(PWN::Sessions.sessions_dir, "#{sid}.jsonl") : nil
    {
      session_id: sid,
      path: path,
      exists: (path && File.exist?(path)) || false
    }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'sessions_lean',
  toolset: 'sessions',
  schema: {
    name: 'sessions_lean',
    description: 'Prune/compact ~/.pwn/sessions: delete stubs and unreferenced aged ' \
                 'transcripts; compact oversized tool/assistant content. Pins gold ' \
                 'learning outcomes and open-mistake session refs. dry_run:true plans only.',
    parameters: {
      type: 'object',
      properties: {
        dry_run: { type: 'boolean', default: false },
        retain_days: { type: 'integer', default: 30 },
        max_files: { type: 'integer', default: 400 }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Sessions) && PWN::Sessions.respond_to?(:lean!) },
  handler: lambda { |args|
    PWN::Sessions.lean!(
      dry_run: args[:dry_run] ? true : false,
      retain_days: args[:retain_days],
      max_files: args[:max_files]
    )
  }
)
