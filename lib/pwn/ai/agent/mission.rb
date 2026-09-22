# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'securerandom'
require 'yaml'

module PWN
  module AI
    module Agent
      # Durable mission ledger. A killed turn resumes the bound DAG instead of re-inferring a plan.
      module Mission
        ROOT = File.join(Dir.home, '.pwn', 'missions')

        public_class_method def self.begin!(opts = {})
          request = opts[:request].to_s.strip
          raise 'ERROR: request is required' if request.empty?

          id = (opts[:id] || SecureRandom.hex(6)).to_s
          raise ArgumentError, 'mission id must be a simple identifier' unless id.match?(/\A[a-zA-Z0-9_-]+\z/)

          row = mutate!(id: id) do |locked|
            locked[:id] = id
            locked[:request] = request
            locked[:status] = 'open'
            locked[:unattended] = opts[:unattended] == true || locked[:unattended] == true
            locked[:min_seconds] = Integer(opts[:min_seconds] || locked[:min_seconds] || 0)
            locked[:started_at] ||= Time.now.utc.iso8601
            locked[:hosts] = Array(locked[:hosts])
            locked[:techniques] = Array(locked[:techniques])
            locked[:finding_ids] = Array(locked[:finding_ids])
            locked[:loot_handles] = Array(locked[:loot_handles])
            locked[:lost_jobs] = Array(locked[:lost_jobs])
            locked[:jobs] = Array(locked[:jobs])
            locked[:shell_exceptions] = Array(locked[:shell_exceptions])
          end
          write_active(id: id) if row[:unattended]
          row
        end

        public_class_method def self.plan!(opts = {})
          request = opts[:request].to_s
          row = begin!(id: opts[:id], request: request, unattended: true, min_seconds: opts[:min_seconds])
          dag = PWN::AI::Agent::TaskDAG.plan(request: request)
          dir = File.join(ROOT, row[:id])
          FileUtils.mkdir_p(dir)
          File.write(File.join(dir, 'dag.yaml'), YAML.dump(JSON.parse(JSON.generate(dag))))
          PWN::AI::Agent::OpenGoal.begin!(request: request, mission_id: row[:id]) if defined?(PWN::AI::Agent::OpenGoal)
          dag.merge(mission_id: row[:id])
        end

        public_class_method def self.current(opts = {})
          id = opts[:id].to_s
          return nil if id.empty?

          read_row(id: id)
        end

        public_class_method def self.active(opts = {})
          id = (opts[:id] || active_id).to_s
          return nil if id.empty?

          current(id: id)
        end

        public_class_method def self.active_id(opts = {})
          return opts[:id].to_s unless opts[:id].to_s.empty?

          path = File.join(ROOT, 'active')
          return nil unless File.file?(path)

          File.read(path).strip
        rescue StandardError
          nil
        end

        public_class_method def self.bind_run!(opts = {})
          mutate!(id: opts[:id]) do |row|
            raise 'ERROR: mission is required' if row.empty?

            row[:run_id] = opts[:run_id].to_s
            raise 'ERROR: run_id is required' if row[:run_id].empty?

            row[:root] = opts[:root].to_s unless opts[:root].to_s.empty?
            row[:approved] = true
          end
        end

        public_class_method def self.resume_run(opts = {})
          row = current(id: opts[:id])
          return { resumed: false, reason: 'missing' } unless row
          return { resumed: false, reason: 'no run' } if row[:run_id].to_s.empty?

          report = PWN::AI::Agent::TaskDAG.resume(
            run_id: row[:run_id],
            root: row[:root],
            approved: row[:approved] == true,
            unattended: row[:unattended]
          )
          ids = Array(report[:results]).map { |step| step[:id] || step['id'] }.compact
          mutate!(id: row[:id]) do |locked|
            locked[:last_completed_step] = ids.last if ids.any?
            locked[:status] = 'open'
          end
          complete!(id: row[:id])
          report.merge(resumed: true, text: report_text(report: report, request: row[:request]))
        end

        public_class_method def self.done?(opts = {})
          row = current(id: opts[:id])
          return true unless row
          return false if row[:min_seconds].to_i.positive? && !elapsed?(row: row)
          return false unless Array(row[:lost_jobs]).empty?

          row[:status].to_s == 'done'
        end

        public_class_method def self.complete!(opts = {})
          row = current(id: opts[:id])
          return { ok: false, reason: 'missing' } unless row
          return { ok: false, reason: 'duration' } if row[:min_seconds].to_i.positive? && !elapsed?(row: row)
          return { ok: false, reason: 'lost' } unless Array(row[:lost_jobs]).empty?
          return { ok: false, reason: 'checkpoints' } unless checkpoints_done?(row: row)
          return { ok: false, reason: 'findings' } if row[:request].to_s.match?(/finding/i) && Array(row[:finding_ids]).empty?
          return { ok: false, reason: 'loot' } if row[:request].to_s.match?(/loot/i) && Array(row[:loot_handles]).empty?

          mutate!(id: row[:id]) { |locked| locked[:status] = 'done' }
          clear_active(id: row[:id])
          { ok: true }
        end

        public_class_method def self.note_finding!(opts = {})
          mutate!(id: opts[:id] || active_id) do |row|
            append_unique(row: row, key: :finding_ids, value: opts[:finding_id])
            append_unique(row: row, key: :hosts, value: opts[:host])
          end
        end

        public_class_method def self.note_loot!(opts = {})
          mutate!(id: opts[:id] || active_id) do |row|
            append_unique(row: row, key: :loot_handles, value: opts[:handle])
            append_unique(row: row, key: :hosts, value: opts[:host])
          end
        end

        public_class_method def self.note_technique!(opts = {})
          mutate!(id: opts[:id] || active_id) do |row|
            append_unique(row: row, key: :techniques, value: opts[:technique])
          end
        end

        public_class_method def self.note_job!(opts = {})
          mutate!(id: opts[:id] || active_id) do |row|
            row[:jobs] = Array(row[:jobs])
            jid = opts[:job_id].to_s
            row[:jobs].reject! { |job| (job[:id] || job['id']).to_s == jid }
            row[:jobs] << {
              id: jid,
              idempotent: opts[:idempotent] == true,
              log_offset: opts[:log_offset],
              command: opts[:command].to_s,
              idempotency_key: opts[:idempotency_key].to_s
            }
          end
        end

        public_class_method def self.note_shell_exception!(opts = {})
          mutate!(id: opts[:id] || active_id) do |row|
            row[:shell_exceptions] = Array(row[:shell_exceptions]) | Array(opts[:step_ids]).map(&:to_s)
          end
        end

        public_class_method def self.record_lost(opts = {})
          row = mutate!(id: opts[:id]) do |locked|
            lost = Array(opts[:jobs]).select { |job| job.is_a?(Hash) && job[:status].to_s == 'LOST' }
            locked[:lost_jobs] = lost.map { |job| job[:id].to_s }.reject(&:empty?)
            locked[:status] = 'open'
          end
          { success: false, lost: row[:lost_jobs] }
        end

        public_class_method def self.recover!(opts = {})
          id = (opts[:id] || active_id).to_s
          row = current(id: id)
          return { success: false, lost: [], reattach: [] } if id.empty? || row.nil?

          lost = []
          reattach = []
          Array(row[:jobs]).each do |job|
            jid = (job[:id] || job['id']).to_s
            status = PWN::Plugins::Jobs.status(id: jid)
            next unless status[:status].to_s == 'LOST'

            offset = job[:log_offset]
            offset = job['log_offset'] if offset.nil?
            if (job[:idempotent] || job['idempotent']) && !offset.nil?
              reattach << jid
            else
              lost << status
            end
          end
          record_lost(id: id, jobs: lost) unless lost.empty?
          { success: false, lost: lost.map { |job| job[:id] }, reattach: reattach }
        rescue StandardError
          { success: false, lost: [], reattach: [] }
        end

        public_class_method def self.busy?(opts = {})
          row = current(id: opts[:id] || active_id)
          return false unless row

          Array(row[:jobs]).any? do |job|
            PWN::Plugins::Jobs.status(id: (job[:id] || job['id']).to_s)[:status].to_s == 'RUNNING'
          end
        rescue StandardError
          false
        end

        public_class_method def self.ledger_text(opts = {})
          _request = opts[:request]
          row = current(id: opts[:id] || active_id)
          return '' unless row

          jobs = Array(row[:jobs]).map { |job| job[:id] || job['id'] }.join(',')
          "MISSION #{row[:id]} status=#{row[:status]} last=#{row[:last_completed_step]} jobs=#{jobs} findings=#{Array(row[:finding_ids]).join(',')} loot=#{Array(row[:loot_handles]).join(',')}\nDecide the next step from this ledger. Do not read job tails."
        end

        public_class_method def self.report_text(opts = {})
          report = opts[:report] || {}
          ids = Array(report[:results]).map { |step| step[:id] || step['id'] }
          "Resumed mission for #{opts[:request]}. Completed steps: #{ids.join(', ')}. Named-duration work stays open until wall time elapses."
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Persist an open mission for the original request.
            #{self}.begin!(
              request: 'required - original operator request',
              id: 'optional - simple mission identifier',
              unattended: 'optional - true fails closed without an approved DAG',
              min_seconds: 'optional - named duration that must elapse before done?'
            )

            # Write the mission ledger and a YAML DAG without running tools.
            #{self}.plan!(
              request: 'required - original operator request',
              id: 'optional - simple mission identifier',
              min_seconds: 'optional - named duration that must elapse before done?'
            )

            # Load one mission ledger.
            #{self}.current(
              id: 'required - mission identifier'
            )

            # Load the active unattended mission.
            #{self}.active(
              id: 'optional - mission identifier; defaults to the active pointer'
            )

            # Read the active mission identifier.
            #{self}.active_id(
              id: 'optional - explicit identifier override'
            )

            # Bind a checkpointed TaskDAG run to this mission.
            #{self}.bind_run!(
              id: 'required - mission identifier',
              run_id: 'required - TaskDAG run id',
              root: 'optional - runs directory'
            )

            # Resume the bound DAG, skipping completed checkpoints.
            #{self}.resume_run(
              id: 'required - mission identifier'
            )

            # False while a named duration or a LOST job is still open.
            #{self}.done?(
              id: 'required - mission identifier'
            )

            # Set status done only when checkpoints, duration, and requested evidence exist.
            #{self}.complete!(
              id: 'required - mission identifier'
            )

            # Append a finding id under the mission file lock.
            #{self}.note_finding!(
              id: 'optional - mission identifier; defaults to the active mission',
              finding_id: 'required - finding identifier',
              host: 'optional - host to record on the ledger'
            )

            # Append a loot handle under the mission file lock.
            #{self}.note_loot!(
              id: 'optional - mission identifier; defaults to the active mission',
              handle: 'required - loot handle',
              host: 'optional - host to record on the ledger'
            )

            # Append a technique name under the mission file lock.
            #{self}.note_technique!(
              id: 'optional - mission identifier; defaults to the active mission',
              technique: 'required - technique or tool name'
            )

            # Append a durable job id under the mission file lock.
            #{self}.note_job!(
              id: 'optional - mission identifier; defaults to the active mission',
              job_id: 'required - Jobs identifier',
              idempotent: 'optional - true when the launch key can be reused',
              log_offset: 'optional - recorded log offset required for reattach',
              command: 'optional - command string stored for a later re-run',
              idempotency_key: 'optional - durable launch key'
            )

            # Record operator-written shell steps that were explicitly allowed.
            #{self}.note_shell_exception!(
              id: 'optional - mission identifier; defaults to the active mission',
              step_ids: 'required - Array of hand-written shell step ids'
            )

            # Record LOST jobs as unknown outcomes, never as success.
            #{self}.record_lost(
              id: 'required - mission identifier',
              jobs: 'required - Array of job status hashes'
            )

            # Classify stored jobs as reattach or LOST without marking success.
            #{self}.recover!(
              id: 'optional - mission identifier; defaults to the active mission'
            )

            # True when a stored job supervisor is still RUNNING.
            #{self}.busy?(
              id: 'optional - mission identifier; defaults to the active mission'
            )

            # Ledger summary for the next model turn. Does not read job logs.
            #{self}.ledger_text(
              id: 'optional - mission identifier; defaults to the active mission',
              request: 'optional - unused request placeholder so the method reads opts'
            )

            # One-line resume report.
            #{self}.report_text(
              report: 'required - TaskDAG resume hash',
              request: 'optional - original request'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.mutate!(opts = {})
          id = opts[:id].to_s
          raise 'ERROR: id is required' if id.empty?

          FileUtils.mkdir_p(ROOT)
          File.open(File.join(ROOT, "#{id}.lock"), File::RDWR | File::CREAT, 0o600) do |lock|
            lock.flock(File::LOCK_EX)
            row = read_row(id: id) || {}
            yield row
            write_row(row: row)
            row
          end
        end

        private_class_method def self.read_row(opts = {})
          path = path_for(id: opts[:id])
          return nil unless File.file?(path)

          JSON.parse(File.read(path), symbolize_names: true)
        rescue StandardError
          nil
        end

        private_class_method def self.write_row(opts = {})
          row = opts[:row]
          row[:updated_at] = Time.now.utc.iso8601
          path = path_for(id: row[:id])
          File.write(path, "#{JSON.pretty_generate(row)}\n")
          File.chmod(0o600, path)
          row
        end

        private_class_method def self.path_for(opts = {})
          File.join(ROOT, "#{opts[:id]}.json")
        end

        private_class_method def self.write_active(opts = {})
          FileUtils.mkdir_p(ROOT)
          File.write(File.join(ROOT, 'active'), opts[:id].to_s)
        end

        private_class_method def self.clear_active(opts = {})
          path = File.join(ROOT, 'active')
          return unless File.file?(path) && File.read(path).strip == opts[:id].to_s

          File.delete(path)
        rescue StandardError
          nil
        end

        private_class_method def self.append_unique(opts = {})
          row = opts[:row]
          key = opts[:key]
          value = opts[:value].to_s
          row[key] = Array(row[key])
          row[key] << value unless value.empty? || row[key].include?(value)
        end

        private_class_method def self.checkpoints_done?(opts = {})
          row = opts[:row]
          return false if row[:run_id].to_s.empty?

          dir = File.join(row[:root].to_s, row[:run_id].to_s)
          path = File.join(dir, 'dag.yaml')
          return false unless File.file?(path)

          dag = YAML.safe_load_file(path)
          steps = Array(dag['steps'] || dag[:steps]).map { |step| (step['id'] || step[:id]).to_s }
          done_path = File.join(dir, 'checkpoints.jsonl')
          return false unless File.file?(done_path)

          done = File.readlines(done_path).each_with_object({}) do |line, acc|
            parsed = JSON.parse(line)
            acc[parsed['id']] = true if parsed['status'] == 'completed'
          rescue JSON::ParserError
            next
          end
          !steps.empty? && steps.all? { |step_id| done[step_id] }
        rescue StandardError
          false
        end

        private_class_method def self.elapsed?(opts = {})
          row = opts[:row]
          started = Time.parse(row[:started_at].to_s)
          Time.now - started >= row[:min_seconds].to_i
        rescue StandardError
          false
        end
      end
    end
  end
end
