# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/cron'

# Thin wrappers around PWN::Cron so the model can schedule, inspect, run,
# enable/disable and remove recurring pwn-ai jobs (~/.pwn/cron/jobs.yml).
# Jobs may carry a pwn-ai `prompt`, a `ruby` snippet, or an external
# `script` path; system-cron installation is opt-in via :install_crontab.

PWN::AI::Agent::Registry.register(
  name: 'cron_list',
  toolset: 'cron',
  schema: {
    name: 'cron_list',
    description: 'List all pwn-ai cron jobs from ~/.pwn/cron/jobs.yml ' \
                 '(id, name, schedule, enabled, last_run, last_status).',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::Cron) },
  handler: lambda { |_args|
    PWN::Cron.list.map do |id, job|
      {
        id: id,
        name: job[:name],
        schedule: job[:schedule],
        enabled: job[:enabled],
        delivery: job[:delivery],
        prompt: job[:prompt].to_s[0, 120],
        ruby: job[:ruby].to_s[0, 120],
        script: job[:script],
        last_run: job[:last_run],
        last_status: job[:last_status]
      }
    end
  }
)

PWN::AI::Agent::Registry.register(
  name: 'cron_create',
  toolset: 'cron',
  schema: {
    name: 'cron_create',
    description: 'Create a scheduled pwn-ai job. Provide exactly one of ' \
                 'prompt (sent to the active AI engine), ruby (evaluated ' \
                 'in-process), or script (external path). Set ' \
                 'install_crontab:true to also append a system crontab ' \
                 'entry that invokes PWN::Cron.run for this job id.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Human-friendly job name (default job-<id>).' },
        schedule: {
          type: 'string',
          description: 'Cron expression, e.g. "0 * * * *". Required when ' \
                       'install_crontab is true; otherwise informational.'
        },
        prompt: { type: 'string', description: 'pwn-ai prompt to run against the active engine.' },
        ruby: { type: 'string', description: 'Ruby snippet evaluated in TOPLEVEL_BINDING.' },
        script: { type: 'string', description: 'Path to an external executable script.' },
        delivery: { type: 'string', enum: %w[log stdout], default: 'log' },
        enabled: { type: 'boolean', default: true },
        install_crontab: {
          type: 'boolean',
          default: false,
          description: 'Also append a `crontab -l` entry that runs this job id via pwn.'
        }
      },
      required: %w[schedule]
    }
  },
  check: -> { defined?(PWN::Cron) },
  handler: lambda { |args|
    PWN::Cron.create(
      name: args[:name],
      schedule: args[:schedule],
      prompt: args[:prompt],
      ruby: args[:ruby],
      script: args[:script],
      delivery: args[:delivery],
      enabled: args.fetch(:enabled, true),
      install_crontab: args[:install_crontab]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'cron_run',
  toolset: 'cron',
  schema: {
    name: 'cron_run',
    description: 'Execute a cron job immediately by id (or name) and ' \
                 'return { job:, result:, duration:, status: }. Updates ' \
                 'last_run / last_status in jobs.yml.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Job id or job name.' }
      },
      required: %w[id]
    }
  },
  check: -> { defined?(PWN::Cron) },
  handler: lambda { |args|
    PWN::Cron.run(id: args[:id])
  }
)

PWN::AI::Agent::Registry.register(
  name: 'cron_enable',
  toolset: 'cron',
  schema: {
    name: 'cron_enable',
    description: 'Set enabled:true on a cron job by id.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: %w[id]
    }
  },
  check: -> { defined?(PWN::Cron) },
  handler: lambda { |args|
    { id: args[:id], job: PWN::Cron.enable(id: args[:id]) }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'cron_disable',
  toolset: 'cron',
  schema: {
    name: 'cron_disable',
    description: 'Set enabled:false on a cron job by id.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: %w[id]
    }
  },
  check: -> { defined?(PWN::Cron) },
  handler: lambda { |args|
    { id: args[:id], job: PWN::Cron.disable(id: args[:id]) }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'cron_remove',
  toolset: 'cron',
  schema: {
    name: 'cron_remove',
    description: 'Delete a cron job by id from ~/.pwn/cron/jobs.yml. ' \
                 'Does NOT scrub any system crontab entry — remove that ' \
                 'manually with `crontab -e` if install_crontab was used.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: %w[id]
    }
  },
  check: -> { defined?(PWN::Cron) },
  handler: lambda { |args|
    { id: args[:id], removed: PWN::Cron.remove(id: args[:id]) }
  }
)
