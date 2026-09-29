# frozen_string_literal: true

require 'shellwords'
require 'stringio'
require 'securerandom'

module PWN
  module Plugins
    module REPL
      # Console-owned controller over the existing Swarm persona APIs.
      module AISwarm
        # One cancellable persona job. Model waits can be interrupted; tools finish.
        class JobControl < PWN::AI::Agent::Loop::Steering
          class Stopped < Exception; end # rubocop:disable Lint/InheritException

          def stop
            @stopping = true
            submit('Stop this swarm job.')
          end

          def checkpoint(messages:, phase: :boundary, &block)
            if @stopping
              block&.call
              raise Stopped, 'Swarm job cancelled at a safe boundary; completed work is not undone.'
            end
            super
          end

          def check_stop
            raise Stopped, 'Swarm job cancelled at a safe boundary; completed work is not undone.' if @stopping
          end
        end

        # Session-scoped swarm jobs. Workers never draw the terminal.
        class Controller # rubocop:disable Metrics/ClassLength -- one session-scoped swarm command surface
          MAX_JOBS = 8
          ACTIVE = %w[queued running steering cancelling].freeze

          def initialize(session_id:)
            @session_id = session_id.to_s
            @mutex = Mutex.new
            @jobs = {}
            @swarm_id = nil
            @closed = false
          end

          def execute(opts = {})
            line = opts[:line].to_s.strip
            tokens = Shellwords.split(line)
            tokens.shift if tokens.first == '/swarm'
            command = tokens.shift || 'help'
            dispatch(command, tokens, opts)
          rescue StandardError => e
            { ok: false, error: "#{e.class}: #{e.message}" }
          end

          def snapshot
            @mutex.synchronize do
              {
                swarm_id: @swarm_id,
                jobs: @jobs.values.map { |job| job.slice(:id, :agent, :state, :command, :result, :error, :last_tool).transform_values { |value| value.is_a?(String) ? value.dup : value } }
              }
            end
          end

          def completion_context
            snap = snapshot
            { swarm_id: snap[:swarm_id], jobs: snap[:jobs], agents: agents }
          end

          def busy?
            snapshot[:jobs].any? { |job| ACTIVE.include?(job[:state]) }
          end

          def roster
            PWN::AI::Agent::Swarm.personas(swarm_id: @swarm_id).map do |name, persona|
              { name: name.to_s, role: persona[:role].to_s, engine: (persona[:engine] || 'inherit').to_s, model: (persona[:model] || 'provider default').to_s }
            end
          end

          def cancel_all
            ids = snapshot[:jobs].select { |job| ACTIVE.include?(job[:state]) }.map { |job| job[:id] }
            ids.each { |id| cancel(id) }
            { ok: true, cancelled: ids.length }
          end

          def close
            @closed = true
            cancel_all
            workers.each { |worker| worker.join(30) }
            { ok: true }
          end

          private

          def dispatch(command, tokens, opts)
            case command
            when 'help', 'dashboard' then help_text
            when 'roster' then { ok: true, agents: roster, swarm_id: @swarm_id }
            when 'status' then status(tokens.first)
            when 'create' then create(tokens.join(' '))
            when 'use' then use(tokens.first)
            when 'spawn' then spawn(tokens)
            when 'retire' then retire(tokens.first)
            when 'ask' then ask(tokens, opts)
            when 'debate' then debate(tokens, opts)
            when 'broadcast' then broadcast(tokens, opts)
            when 'tail' then tail(tokens.first)
            when 'steer' then steer(tokens, opts)
            when 'cancel' then cancel(tokens.first)
            else { ok: false, error: "unknown /swarm command: #{command}", hint: help_text[:usage] }
            end
          end

          def help_text
            {
              ok: true,
              usage: '/swarm roster|status [JOB]|create [topic]|use ID|spawn NAME ROLE [--engine E --model M --toolsets a,b]|retire NAME|ask NAME REQUEST|debate NAMES TOPIC [--rounds N]|broadcast REQUEST [--names a,b]|tail [N]|steer JOB INSTRUCTION|cancel JOB|all'
            }
          end

          def create(topic)
            return { ok: false, error: 'cannot create a swarm while jobs are active' } if busy?

            created = PWN::AI::Agent::Swarm.create(topic: topic.empty? ? @session_id : topic)
            @mutex.synchronize { @swarm_id = created[:swarm_id] }
            { ok: true, swarm_id: created[:swarm_id] }
          end

          def use(swarm_id)
            return { ok: false, error: 'swarm id required' } unless identifier?(swarm_id)
            return { ok: false, error: 'cannot switch swarm while jobs are active' } if busy?

            @mutex.synchronize { @swarm_id = swarm_id }
            { ok: true, swarm_id: swarm_id }
          end

          def spawn(tokens)
            flags, positional = split_flags(tokens)
            name = positional[0]
            role = positional[1..]&.join(' ')
            return { ok: false, error: 'usage: spawn NAME ROLE [--engine E --model M --toolsets a,b]' } if name.to_s.empty? || role.to_s.empty?
            return { ok: false, error: 'invalid persona name' } unless identifier?(name)

            ensure_swarm
            result = PWN::AI::Agent::Swarm.spawn(
              swarm_id: @swarm_id, name: name, role: role, engine: flags['engine'], model: flags['model'],
              toolsets: flags['toolsets']&.split(','), ephemeral: true
            )
            { ok: true, persona: result[:name], swarm_id: @swarm_id, scope: :swarm }
          end

          def retire(name)
            return { ok: false, error: 'invalid persona name' } unless identifier?(name)

            result = PWN::AI::Agent::Swarm.retire(name: name, swarm_id: @swarm_id, local: true)
            { ok: result[:removed], scope: result[:scope], name: name }
          end

          def ask(tokens, opts)
            name = tokens.shift
            request = tokens.join(' ')
            return { ok: false, error: 'usage: ask NAME REQUEST' } if name.to_s.empty? || request.empty?

            start_job(agent: name, command: 'ask', opts: opts) do |job|
              PWN::AI::Agent::Swarm.ask(name: name, request: request, swarm_id: ensure_swarm, steering: job[:control], usage_observer: opts[:usage_observer], on_tool: tool_callback(job, opts))
            end
          end

          def debate(tokens, opts)
            flags, positional = split_flags(tokens)
            names = positional.shift.to_s.split(',')
            topic = positional.join(' ')
            rounds = (flags['rounds'] || 1).to_i
            return { ok: false, error: 'usage: debate NAME,NAME TOPIC [--rounds N]' } if names.length < 2 || topic.empty?
            return { ok: false, error: 'rounds must be between 1 and 10' } unless rounds.between?(1, 10)

            start_job(agent: names.join(','), command: 'debate', opts: opts) do |job|
              transcript = []
              rounds.times do
                names.each do |name|
                  request = transcript.empty? ? topic : "#{topic}\n\nPrevious speaker: #{transcript.last}\nRespond, critique, or advance the objective."
                  job[:control].check_stop
                  result = PWN::AI::Agent::Swarm.ask(name: name, request: request, swarm_id: @swarm_id, steering: job[:control], usage_observer: opts[:usage_observer], on_tool: tool_callback(job, opts))
                  transcript << "#{name}: #{result[:reply]}"
                end
              end
              { reply: transcript.join("\n") }
            end
          end

          def broadcast(tokens, opts)
            flags, positional = split_flags(tokens)
            request = positional.join(' ')
            names = flags['names']&.split(',') || agents
            return { ok: false, error: 'usage: broadcast REQUEST [--names a,b]' } if request.empty? || names.empty?

            start_job(agent: names.join(','), command: 'broadcast', opts: opts) do |job|
              replies = names.map do |name|
                job[:control].check_stop
                result = PWN::AI::Agent::Swarm.ask(name: name, request: request, swarm_id: ensure_swarm, steering: job[:control], usage_observer: opts[:usage_observer], on_tool: tool_callback(job, opts))
                "#{name}: #{result[:reply]}"
              end
              { reply: replies.join("\n") }
            end
          end

          def steer(tokens, opts)
            id = tokens.shift
            instruction = tokens.join(' ')
            job = find_job(id)
            return { ok: false, error: 'job not found' } unless job
            return { ok: false, error: 'instruction required' } if instruction.empty?
            return { ok: false, error: 'job is no longer active' } unless update_active(job, 'steering')

            job[:control].submit(instruction)
            opts[:on_event]&.call(:notice, "Steering #{job[:id]} (#{job[:agent]}): waiting for a safe boundary.")
            { ok: true, job_id: job[:id] }
          end

          def cancel(id)
            return cancel_all if id.nil? || id == 'all'

            job = find_job(id)
            return { ok: false, error: 'job not found' } unless job

            return { ok: false, error: 'job is no longer active' } unless update_active(job, 'cancelling')

            job[:control].stop
            { ok: true, job_id: job[:id] }
          end

          def status(id)
            jobs = snapshot[:jobs]
            jobs = jobs.select { |job| job[:id] == id } if id
            { ok: true, swarm_id: @swarm_id, jobs: jobs }
          end

          def tail(limit)
            return { ok: false, error: 'no swarm selected' } if @swarm_id.to_s.empty?

            { ok: true, messages: PWN::AI::Agent::Swarm.bus_tail(swarm_id: @swarm_id, limit: (limit || 8).to_i) }
          end

          def start_job(agent:, command:, opts:)
            return { ok: false, error: 'swarm controller is closed' } if @closed
            return { ok: false, error: "job limit #{MAX_JOBS} reached" } if busy_count >= MAX_JOBS

            ensure_swarm
            id = SecureRandom.hex(3)
            locals = Thread.current.keys.grep(/^pwn_/).to_h { |key| [key, Thread.current[key]] }
            variables = Thread.current.thread_variables.grep(/^pwn_/).to_h { |key| [key, Thread.current.thread_variable_get(key)] }
            ready = Queue.new
            job = { id: id, agent: agent, command: command, state: 'queued' }
            @mutex.synchronize { @jobs[id] = job }
            job[:worker] = Thread.new do
              locals.each { |key, value| Thread.current[key] = value }
              variables.each { |key, value| Thread.current.thread_variable_set(key, value) }
              job[:control] = JobControl.new(input: StringIO.new, output: StringIO.new)
              Thread.current[:pwn_steering_input] = job[:control]
              ready << true
              update(job, 'running')
              result = yield(job)
              job[:control].check_stop
              update(job, 'completed', result: summarize(result))
              opts[:on_event]&.call(:assistant, "#{agent} [#{id}] #{command} complete\n#{summarize(result)}")
              result
            rescue JobControl::Stopped => e
              update(job, 'cancelled', error: e.message)
              opts[:on_event]&.call(:warning, "#{agent} [#{id}] #{e.message}")
            rescue StandardError => e
              update(job, 'failed', error: "#{e.class}: #{e.message}")
              opts[:on_event]&.call(:warning, "#{agent} [#{id}] #{e.class}: #{e.message}")
            end
            job[:worker].report_on_exception = false
            ready.pop
            { ok: true, job_id: id, state: 'queued' }
          end

          def tool_callback(job, opts)
            lambda do |name, args, result|
              update(job, job[:state], last_tool: name)
              opts[:on_event]&.call(:tool, "#{job[:agent]} [#{job[:id]}] #{name}\n#{args.inspect}")
              opts[:on_event]&.call(:result, result.to_s)
            end
          end

          def summarize(result)
            return result[:reply].to_s if result.is_a?(Hash) && result[:reply]
            return result[:transcript].map { |row| "#{row[:name]}: #{row[:reply]}" }.join("\n") if result.is_a?(Hash) && result[:transcript]

            result.to_s
          end

          def update(job, state, **outcome)
            clean = outcome.transform_values { |value| PWN::Redaction.redact(value: value.to_s) }
            @mutex.synchronize { job.merge!(clean).merge!(state: state) }
          end

          def update_active(job, state)
            @mutex.synchronize do
              return false unless ACTIVE.include?(job[:state])

              job[:state] = state
            end
          end

          def find_job(id)
            @mutex.synchronize { @jobs[id] }
          end

          def controls
            @mutex.synchronize { @jobs.values.map { |job| job[:control] } }
          end

          def workers
            @mutex.synchronize { @jobs.values.filter_map { |job| job[:worker] } }
          end

          def busy_count
            snapshot[:jobs].count { |job| ACTIVE.include?(job[:state]) }
          end

          def ensure_swarm
            @swarm_id || create('console')[:swarm_id]
          end

          def agents
            roster.map { |row| row[:name] }
          end

          def identifier?(value)
            value.to_s.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z/)
          end

          def split_flags(tokens)
            flags = {}
            positional = []
            index = 0
            while index < tokens.length
              token = tokens[index]
              if token == '--'
                positional.concat(tokens[(index + 1)..])
                break
              elsif %w[--engine --model --toolsets --names --rounds].include?(token)
                flags[token.delete_prefix('--')] = tokens[index + 1].to_s
                index += 2
              else
                positional << token
                index += 1
              end
            end
            [flags, positional]
          end
        end

        public_class_method def self.authors
          'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
        end

        public_class_method def self.help
          puts "USAGE:
            # Build a session-scoped controller. Jobs call the existing Swarm APIs.
            controller = #{self}::Controller.new(
              session_id: 'required - console session id'
            )

            # Return module authors.
            #{self}.authors
          "
        end
      end
    end
  end
end
