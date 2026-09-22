# frozen_string_literal: true

require 'yaml'
require 'json'
require 'fileutils'
require 'time'
require 'securerandom'

module PWN
  module AI
    module Agent
      # Planner/executor split: YAML task DAGs with per-step checkpoints.
      module TaskDAG
        ROOT = File.join(Dir.home, '.pwn', 'runs')

        public_class_method def self.required_bins
          []
        end

        # Emit a YAML-serializable DAG with zero tool side effects.
        public_class_method def self.plan(opts = {})
          request = opts[:request].to_s
          raise 'ERROR: request is required' if request.strip.empty?

          steps = Array(opts[:steps])
          steps = infer_steps(request: request) if steps.empty?
          {
            version: 1,
            request: request,
            steps: steps.map { |step| normalize_step(step: step) }
          }
        end

        # Run an approved DAG; completed checkpoints are skipped on resume.
        public_class_method def self.execute(opts = {})
          refuse_operator_shell!(opts)
          root = opts[:root] || ROOT
          run_id = (opts[:run_id] || SecureRandom.hex(8)).to_s
          dir = File.join(root, run_id)
          FileUtils.mkdir_p(dir)
          dag = load_dag(opts.merge(dir: dir))
          refuse_unapproved!(dag: dag, opts: opts)
          File.write(File.join(dir, 'dag.yaml'), YAML.dump(JSON.parse(JSON.generate(dag)))) unless File.file?(File.join(dir, 'dag.yaml'))
          File.write(File.join(dir, 'run_id'), run_id)
          done = load_done(dir: dir)
          steps = Array(dag['steps'] || dag[:steps]).map { |step| normalize_step(step: step) }
          results = []
          remaining = steps.reject { |step| done[step['id']] }
          until remaining.empty?
            ready = remaining.select { |step| Array(step['dependencies']).all? { |need| done[need] } }
            raise ArgumentError, 'task DAG deadlock or missing dependencies' if ready.empty?

            ready.each do |step|
              remaining.delete(step)
              row = run_step(step: step, dir: dir)
              done[step['id']] = true
              results << row
              persist_checkpoint(dir: dir, step: step, row: row)
              return { run_id: run_id, dir: dir, results: results, halted: step['id'] } if opts[:halt_after].to_s == step['id']
            end
          end
          { run_id: run_id, dir: dir, results: results, ok: results.all? { |row| row[:ok] != false } }
        end

        # Resume a checkpointed run, skipping completed steps.
        public_class_method def self.resume(opts = {})
          execute(opts)
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # List host binaries this module expects to be installed.
            #{self}.required_bins

            # Emit a YAML-serializable DAG with zero tool side effects.
            #{self}.plan(
              request: 'required - operator request to decompose',
              steps: 'optional - Array of step hashes; inferred from the request when omitted'
            )

            # Run an approved DAG; completed checkpoints are skipped on resume.
            #{self}.execute(
              dag: 'optional - Hash DAG; required unless path or run_id is set',
              path: 'optional - YAML DAG path',
              run_id: 'optional - existing run to resume; generated when omitted',
              root: 'optional - runs directory; defaults to ~/.pwn/runs',
              halt_after: 'optional - step id used by tests to stop after a checkpoint',
              approved: 'optional - true allows shell steps on an unattended mission',
              unattended: 'optional - true refuses inferred shell steps unless approved',
              operator: 'optional - true rejects inferred shell steps even when approved',
              mission_id: 'optional - mission that records a hand-written shell exception'
            )

            # Resume a checkpointed run, skipping completed steps.
            #{self}.resume(
              run_id: 'required - run id previously returned by execute',
              root: 'optional - runs directory; defaults to ~/.pwn/runs'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.refuse_operator_shell!(opts = {})
          return unless opts[:operator]
          return unless opts[:path] || opts[:dag]

          dag = load_dag(opts)
          steps = Array(dag['steps'] || dag[:steps])
          inferred = steps.any? do |step|
            tool = (step['tool'] || step[:tool]).to_s
            written = step['hand_written'] == true || step[:hand_written] == true
            tool == 'shell' && !written
          end
          raise ArgumentError, 'operator execute refuses inferred shell steps' if inferred

          written = steps.select { |step| (step['tool'] || step[:tool]).to_s == 'shell' && (step['hand_written'] == true || step[:hand_written] == true) }
          return if written.empty? || opts[:mission_id].to_s.empty?

          PWN::AI::Agent::Mission.note_shell_exception!(id: opts[:mission_id], step_ids: written.map { |step| step['id'] || step[:id] })
        end

        private_class_method def self.refuse_unapproved!(opts = {})
          return unless opts[:opts][:unattended]
          return if opts[:opts][:approved]

          dag = opts[:dag]
          steps = Array(dag['steps'] || dag[:steps])
          shell = steps.any? { |step| (step['tool'] || step[:tool]).to_s == 'shell' }
          raise ArgumentError, 'unattended mission refuses inferred shell steps until the DAG is approved' if shell
        end

        private_class_method def self.infer_steps(opts = {})
          parts = opts[:request].to_s.split(/\s+then\s+|;\s*|\n+/i).map(&:strip).reject(&:empty?)
          parts = [opts[:request].to_s.strip] if parts.empty?
          prev = nil
          parts.each_with_index.map do |clause, idx|
            id = "s#{idx + 1}"
            tool, args = map_clause(clause: clause)
            step = {
              'id' => id,
              'tool' => tool,
              'args' => args,
              'side_effect' => side_effect_tier(tool: tool, args: args),
              'dependencies' => prev ? [prev] : []
            }
            prev = id
            step
          end
        end

        private_class_method def self.map_clause(opts = {})
          clause = opts[:clause].to_s
          case clause
          when /\bnmap\b|\bnmap_scan\b/i
            ['nmap_scan', { 'xml' => clause }]
          when /\bnuclei\b/i
            ['nuclei_scan', { 'target' => clause }]
          when /\b(pwn_eval|ruby)\b/i
            ['pwn_eval', { 'code' => clause }]
          else
            ['shell', { 'command' => clause }]
          end
        end

        private_class_method def self.side_effect_tier(opts = {})
          tool = opts[:tool].to_s
          args = opts[:args] || {}
          payload = args['command'] || args[:command] || args['code'] || args[:code] || JSON.generate(args)
          kind = PWN::Plugins::AISandbox.classify(payload: payload, side_effect: opts[:side_effect])
          case kind.to_s
          when 'write' then 'destructive'
          when 'network' then 'active_scan'
          else
            tool.match?(/scan|nuclei|nmap|fuzz/) ? 'active_scan' : 'read_only'
          end
        end

        private_class_method def self.normalize_step(opts = {})
          step = opts[:step]
          step = step.transform_keys(&:to_s) if step.is_a?(Hash)
          raise ArgumentError, 'each step needs id, tool, and args' unless step.is_a?(Hash)

          args = step['args'] || {}
          args = args.transform_keys(&:to_s) if args.is_a?(Hash)
          {
            'id' => step['id'].to_s,
            'tool' => step['tool'].to_s,
            'args' => args,
            'side_effect' => (step['side_effect'] || side_effect_tier(tool: step['tool'], args: args)).to_s,
            'hand_written' => step['hand_written'] == true || step[:hand_written] == true,
            'dependencies' => Array(step['dependencies']).map(&:to_s)
          }
        end

        private_class_method def self.load_dag(opts = {})
          if opts[:dag]
            dag = opts[:dag]
            return dag.transform_keys(&:to_s) if dag.is_a?(Hash)

            return dag
          end
          path = opts[:path].to_s
          path = File.join(opts[:dir], 'dag.yaml') if path.empty?
          raise 'ERROR: dag, path, or an existing run is required' unless File.file?(path)

          YAML.safe_load_file(path)
        end

        private_class_method def self.load_done(opts = {})
          path = File.join(opts[:dir], 'checkpoints.jsonl')
          return {} unless File.file?(path)

          File.readlines(path).each_with_object({}) do |line, acc|
            row = JSON.parse(line)
            acc[row['id']] = true if row['status'] == 'completed'
          rescue JSON::ParserError
            next
          end
        end

        private_class_method def self.persist_checkpoint(opts = {})
          path = File.join(opts[:dir], 'checkpoints.jsonl')
          rec = { id: opts[:step]['id'], status: 'completed', at: Time.now.utc.iso8601, result: opts[:row] }
          File.open(path, 'a') do |file|
            file.flock(File::LOCK_EX)
            file.puts(JSON.generate(rec))
            file.flush
            file.fsync
          end
        end

        private_class_method def self.run_step(opts = {})
          step = opts[:step]
          PWN::AI::Agent::Registry.discover
          raw = PWN::AI::Agent::Dispatch.call(
            tool_call: { function: { name: step['tool'], arguments: JSON.generate(step['args']) } },
            scope_path: File.join(opts[:dir], 'absent.yaml')
          )
          body = JSON.parse(raw, symbolize_names: true)
          result = body[:result] || body
          ok = !result.is_a?(Hash) || result[:error].nil?
          PWN::AI::Agent::Mission.note_technique!(technique: step['tool']) if ok && defined?(PWN::AI::Agent::Mission) && PWN::AI::Agent::Mission.active_id
          { id: step['id'], ok: ok, result: result }
        rescue StandardError => e
          { id: step['id'], ok: false, error: "#{e.class}: #{e.message}" }
        end
      end
    end
  end
end
