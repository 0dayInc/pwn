# frozen_string_literal: true

require 'json'
require 'digest'
require 'open3'
require 'rbconfig'
require 'tmpdir'
require 'tempfile'
require 'fileutils'
require 'timeout'

module PWN
  module AI
    module Agent
      # Opt-in, fixed local held-out evaluation. Never loaded by the online loop.
      module PolicyEvaluation
        RUNNER = File.expand_path(__FILE__).freeze
        MAX_SNAPSHOT_BYTES = 4_194_304
        WORKER_TIMEOUT_SECONDS = 30

        public_class_method def self.evaluate(opts = {})
          seed = opts.fetch(:seed, 0)
          raise ArgumentError, 'seed must be an integer in 0..7' unless seed.is_a?(Integer) && (0..7).cover?(seed)

          snapshots = %i[baseline candidate].to_h { |arm| [arm, read_snapshot(path: opts.fetch(arm))] }
          JSON.parse(spawn_worker({ args: ['--snapshot-evaluation'], input: JSON.generate(snapshots: snapshots, seed: seed) }), symbolize_names: true)
        end

        # Explicit comparison export. Does not promote and is not called by the online loop.
        public_class_method def self.export_training(opts = {})
          dir = File.expand_path(opts.fetch(:dir))
          parent = File.dirname(dir)
          raise ArgumentError, 'training export directory must be new' if File.exist?(dir)
          raise ArgumentError, 'training export parent must be a real directory' unless File.directory?(parent) && File.realpath(parent) == parent

          spawn_worker({ args: ['--export-training', dir] })
          heldout = [0, 1].map { |seed| evaluate(baseline: File.join(dir, 'off.json'), candidate: File.join(dir, 'on.json'), seed: seed) }
          { heldout: heldout }
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Explicit operator action only; never called from Policy.finish/Loop.
        public_class_method def self.promote(opts = {})
          return { promoted: false, reason: 'disabled' } unless opts[:enabled] == true
          return PWN::Backups.transaction { promote(opts) } unless PWN::Backups.active?

          raise ArgumentError, 'stop all policy writers and set quiescent: true' unless opts[:quiescent] == true

          baseline = read_snapshot(path: opts.fetch(:baseline))
          candidate = read_snapshot(path: opts.fetch(:candidate))
          live = File.expand_path(opts.fetch(:live_path))
          reports = opts.fetch(:reports)
          raise ArgumentError, 'need 2..8 distinct held-out reports' unless reports.is_a?(Array) && (2..8).cover?(reports.length) && reports.map { |r| r.fetch(:seed) }.uniq.length == reports.length
          raise ArgumentError, 'held-out reports must cover both filesystem environments' unless reports.map { |r| r.fetch(:seed).odd? }.uniq.length == 2

          replayed = reports.map do |report|
            fresh = evaluate(baseline: opts[:baseline], candidate: opts[:candidate], seed: report.fetch(:seed))
            raise ArgumentError, 'provenance/artifact replay mismatch' unless deterministic(value: report) == deterministic(value: fresh)

            gate(report: fresh)
            fresh
          end
          prior_digest = Digest::SHA256.hexdigest(baseline)
          candidate_digest = Digest::SHA256.hexdigest(candidate)
          raise ArgumentError, 'snapshot changed during evaluation' unless replayed.all? { |r| r[:snapshot_sha256] == { baseline: prior_digest, candidate: candidate_digest } }
          raise ArgumentError, 'live policy is not the evaluated baseline' unless read_snapshot(path: live) == baseline

          backup = PWN::Backups.capture(path: live, label: 'policy-evaluation', pin: true)
          replace(path: live, bytes: candidate)
          { promoted: true, receipt_version: 1, change_kind: 'routing_policy',
            acceptance_sha256: Digest::SHA256.hexdigest(JSON.generate(deterministic(value: replayed))),
            live_path: live, rollback_path: backup, baseline_sha256: prior_digest,
            candidate_sha256: candidate_digest, replayed_seeds: replayed.map { |r| r[:seed] } }
        rescue StandardError => e
          { promoted: false, reason: e.message }
        end

        public_class_method def self.rollback(opts = {})
          return { rolled_back: false, reason: 'disabled' } unless opts[:enabled] == true
          return PWN::Backups.transaction { rollback(opts) } unless PWN::Backups.active?

          raise ArgumentError, 'stop all policy writers and set quiescent: true' unless opts[:quiescent] == true

          receipt = opts.fetch(:receipt)
          raise ArgumentError, 'successful versioned policy promotion receipt required' unless receipt[:promoted] == true && receipt[:receipt_version] == 1 && receipt[:change_kind] == 'routing_policy' && receipt[:acceptance_sha256].to_s.match?(/\A[0-9a-f]{64}\z/)

          live = File.expand_path(opts.fetch(:live_path))
          prior_digest = receipt.fetch(:baseline_sha256)
          raise ArgumentError, 'invalid rollback digest' unless prior_digest.is_a?(String) && prior_digest.match?(/\A[0-9a-f]{64}\z/)

          backup = File.expand_path(receipt.fetch(:rollback_path))
          root = Thread.current[:pwn_backup_transaction][:root]
          raise ArgumentError, 'rollback target mismatch' unless receipt[:live_path] == live && backup.start_with?("#{root}/") && File.realpath(backup) == backup

          bytes = read_snapshot(path: backup)
          raise ArgumentError, 'rollback snapshot digest mismatch' unless Digest::SHA256.hexdigest(bytes) == prior_digest
          raise ArgumentError, 'live policy changed since promotion' unless Digest::SHA256.hexdigest(read_snapshot(path: live)) == receipt.fetch(:candidate_sha256)

          replace(path: live, bytes: bytes)
          { rolled_back: true, live_path: live, restored_sha256: prior_digest }
        rescue StandardError => e
          { rolled_back: false, reason: e.message }
        end

        public_class_method def self.help
          puts "USAGE:
            # Execute independently checked local tasks with frozen snapshots.
            #{self}.evaluate(
              baseline: 'required - explicit baseline policy JSON path',
              candidate: 'required - explicit candidate policy JSON path',
              seed: 'optional - held-out suite index, default 0'
            )

            # Explicitly install a candidate after fresh held-out replay; stop online writers first.
            #{self}.promote(
              enabled: 'optional - must be true to permit writes, default false',
              quiescent: 'required - true only after stopping all policy writers',
              baseline: 'required - explicit baseline policy JSON path',
              candidate: 'required - explicit candidate policy JSON path',
              reports: 'required - array of 2..8 independent evaluate reports',
              live_path: 'required - explicit existing target policy JSON path; no default'
            )

            # Restore the byte-exact pre-promotion snapshot, refusing intervening policy updates.
            #{self}.rollback(
              enabled: 'optional - must be true to permit writes, default false',
              quiescent: 'required - true only after stopping all policy writers',
              live_path: 'required - explicit existing target policy JSON path; no default',
              receipt: 'required - successful promote result with snapshot digests and paths'
            )

            # Write off/on training snapshots and return fresh held-out reports. Does not promote.
            #{self}.export_training(
              dir: 'required - new directory path for off.json and on.json'
            )

            # Display module authors.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.deterministic(opts = {})
          value = opts[:value]
          case value
          when Hash
            value.except(:elapsed_seconds).transform_values { |item| deterministic(value: item) }
          when Array
            value.map { |item| deterministic(value: item) }
          else
            value
          end
        end

        private_class_method def self.read_snapshot(opts = {})
          path = File.expand_path(opts.fetch(:path))
          raise ArgumentError, 'snapshot path contains a symlink' unless File.realpath(path) == path
          raise ArgumentError, 'snapshot must be a regular file' unless File.lstat(path).file?

          bytes = File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
            raise ArgumentError, 'snapshot must be a bounded regular file' unless file.stat.file? && file.stat.size <= MAX_SNAPSHOT_BYTES

            file.read(MAX_SNAPSHOT_BYTES + 1)
          end
          raise ArgumentError, 'snapshot too large' if bytes.bytesize > MAX_SNAPSHOT_BYTES

          table = JSON.parse(bytes)
          valid = table.is_a?(Hash) && %w[q h visits].all? do |name|
            table[name].is_a?(Hash) && table[name].all? do |state, actions|
              state.bytesize <= 4096 && actions.is_a?(Hash) && actions.all? do |action, value|
                action.bytesize <= 4096 && value.is_a?(Numeric) && value.finite? && (name != 'visits' || (value.is_a?(Integer) && value >= 0))
              end
            end
          end
          valid &&= table['returns'].is_a?(Array) && table['returns'].all? { |value| value.is_a?(Numeric) && value.finite? }
          valid &&= table['n_updates'].is_a?(Integer) && table['n_updates'] >= 0 && table['td_abs_sum'].is_a?(Numeric) && table['td_abs_sum'].finite?
          raise ArgumentError, 'invalid policy snapshot schema' unless valid

          bytes
        rescue JSON::ParserError => e
          raise ArgumentError, "invalid snapshot JSON: #{e.message}"
        end

        private_class_method def self.gate(opts = {})
          arms = opts[:report].fetch(:arms)
          candidate = arms.fetch(:candidate).fetch(:evaluation)
          %i[off baseline].each do |mode|
            baseline = arms.fetch(mode).fetch(:evaluation)
            raise ArgumentError, 'held-out completion regression' if candidate[:completed] < baseline[:completed]

            solved = candidate.fetch(:rows).select { |row| row[:completed] }.map { |row| row[:task_id] }.uniq
            previously_solved = baseline.fetch(:rows).select { |row| row[:completed] }.map { |row| row[:task_id] }.uniq
            raise ArgumentError, 'held-out task regression' unless (previously_solved - solved).empty?
            raise ArgumentError, 'held-out artifact_check_score regression' if candidate.fetch(:artifact_check_score) < baseline.fetch(:artifact_check_score)

            %i[false_successes false_success_rate repeated_mistakes tool_calls].each do |metric|
              raise ArgumentError, "held-out #{metric} regression" if candidate.fetch(metric) > baseline.fetch(metric)
            end
            # Tiny local timings are noisy. Bound gross regressions, not claims
            # of a statistically established speedup; use only fresh measurements.
            raise ArgumentError, 'held-out elapsed_seconds regression' if candidate[:elapsed_seconds] > (baseline[:elapsed_seconds] * 1.25) + 0.02
          end
          baseline = arms.fetch(:baseline).fetch(:evaluation)
          improved = candidate[:completed] > baseline[:completed] || %i[false_successes repeated_mistakes tool_calls].any? { |metric| candidate[metric] < baseline[metric] }
          raise ArgumentError, 'no independent held-out gain; training-only gains do not qualify' unless improved
        end

        private_class_method def self.replace(opts = {})
          path = opts[:path]
          Tempfile.create(['.policy-evaluation-', '.tmp'], File.dirname(path)) do |file|
            file.binmode
            file.write(opts[:bytes])
            file.flush
            file.fsync
            File.rename(file.path, path)
          end
          raise IOError, 'policy readback differs' unless File.binread(path) == opts[:bytes]
        end

        private_class_method def self.spawn_worker(opts = {})
          args = opts.fetch(:args)
          input = opts[:input]
          Dir.mktmpdir('pwn-policy-evaluator-') do |root|
            Open3.popen3(
              { 'HOME' => root, 'TMPDIR' => root, 'LANG' => 'C.UTF-8' },
              RbConfig.ruby, RUNNER, *args,
              unsetenv_others: true, chdir: root, pgroup: true
            ) do |stdin, output, error, child|
              readers = [output, error].map { |io| Thread.new { io.read } }
              begin
                Timeout.timeout(WORKER_TIMEOUT_SECONDS) do
                  stdin.write(input) if input
                  stdin.close
                  status = child.value
                  stdout, stderr = readers.map(&:value)
                  raise "held-out worker failed: #{stderr}" unless status.success?

                  stdout
                end
              ensure
                begin
                  Process.kill('KILL', -child.pid)
                rescue Errno::ESRCH
                  nil
                end
                child.join
                readers.each(&:join)
              end
            end
          end
        end

        private_class_method def self.refuse_live_agent
          loaded = $LOADED_FEATURES.any? { |path| File.basename(path) == 'pwn.rb' }
          raise 'Run in a fresh Ruby process; do not load the live agent' if loaded
        end

        private_class_method def self.with_isolated
          refuse_live_agent
          original = ENV.to_h
          Dir.mktmpdir('pwn-policy-heldout-') do |root|
            ENV.replace('HOME' => root, 'TMPDIR' => root, 'LANG' => 'C.UTF-8')
            PWN.const_set(:Env, { ai: { agent: { policy: false } } }) unless PWN.const_defined?(:Env)
            require_relative 'policy'
            require_relative 'registry'
            policy = PWN::AI::Agent::Policy
            raise 'policy persistence escaped temporary HOME' unless [policy::POLICY_FILE, policy::TRAJECTORY_FILE].all? { |path| path.start_with?("#{root}/.pwn/") }

            register_actions
            yield root
          end
        ensure
          ENV.replace(original) if original
        end

        private_class_method def self.evaluate_snapshots(opts = {})
          request = opts.fetch(:request)
          with_isolated do |root|
            policy = PWN::AI::Agent::Policy
            snapshots = request.fetch(:snapshots)
            arms = %i[off baseline candidate].to_h do |mode|
              policy.reset
              PWN::Env[:ai][:agent][:policy] = mode != :off
              FileUtils.mkdir_p(File.dirname(policy::POLICY_FILE))
              File.binwrite(policy::POLICY_FILE, snapshots.fetch(mode == :candidate ? :candidate : :baseline))
              [mode, evaluate_arm({ root: root, mode: mode, train: fixtures({ split: :train }), seed: request.fetch(:seed) })]
            end
            {
              protocol: 'pwn-policy-heldout-v2', seed: request.fetch(:seed),
              scope: 'Deterministic local controller benchmark; NOT proof of live LLM improvement.',
              snapshot_sha256: snapshots.transform_values { |bytes| Digest::SHA256.hexdigest(bytes) },
              source_sha256: %w[policy registry policy_evaluation].to_h { |name| [name, Digest::SHA256.file(File.expand_path("#{name}.rb", __dir__)).hexdigest] },
              harness_sha256: Digest::SHA256.file(__FILE__),
              isolation: { environment_cleared: true, environment_keys: ENV.keys.sort, network_calls: 0, persistence_removed_on_exit: true },
              evaluation_updates: false, attempt_budget: 3, arms: arms
            }
          end
        end

        private_class_method def self.write_training_snapshots(opts = {})
          dir = opts.fetch(:dir)
          Dir.mkdir(dir, 0o700)
          with_isolated do |root|
            %i[off on].each { |mode| run_arm({ root: root, mode: mode, snapshot_dir: dir }) }
          end
          :exported
        end

        private_class_method def self.fixtures(opts = {})
          split = opts.fetch(:split)
          seed = opts.fetch(:seed, 0)
          numbers = if split == :train
                      [[[-2, 12, 3], [-2, 3, 12]], [[-5, 20, 1], [-5, 1, 20]]]
                    else
                      [[[-10, 4, 22, 0], [-10, 0, 4, 22]], [[31, 2, -3, 2], [-3, 2, 2, 31]],
                       [[7, 100, -8, 11], [-8, 7, 11, 100]], [[9, -1, 80, 6], [-1, 6, 9, 80]]]
                    end
          inventory = if split == :train
                        [[[[1, true], [2, false]], [1]], [[[3, false], [4, true]], [4]]]
                      else
                        [[[[11, true], [12, false], [13, true]], [11, 13]],
                         [[[21, false], [22, false]], []],
                         [[[31, false], [32, true], [33, false]], [32]],
                         [[[41, true], [42, true], [43, false]], [41, 42]]]
                      end
          { numbers: numbers, inventory: inventory }.flat_map do |family, pairs|
            pairs.each_with_index.map do |(input, expected), index|
              if split == :heldout && seed.positive?
                input = family == :numbers ? input.map { |number| number * (seed + 1) } : input.map { |id, active| [id + (100 * seed), active] }
                expected = expected.map { |number| family == :numbers ? number * (seed + 1) : number + (100 * seed) }
              end
              { id: "#{split}-#{family}-#{index}", family: family, input: input, expected: expected, environment: seed.odd? ? 'nested-pretty-readonly' : 'flat-compact' }
            end
          end
        end

        private_class_method def self.query(opts = {})
          opts.fetch(:family) == :numbers ? 'fix numeric sorting artifact' : 'scan active inventory artifact'
        end

        private_class_method def self.register_actions
          actions = {
            numbers: { a_lexical_sort: ->(data) { data.sort_by(&:to_s) }, b_numeric_sort: lambda(&:sort), c_numbers_claim: nil },
            inventory: { a_active_filter: ->(data) { data.select { |row| row[1] == true }.map(&:first) }, b_all_records: ->(data) { data.map(&:first) }, c_inventory_claim: nil },
            controls: { control_wrong_artifact: ->(_data) { { status: 'PASS: fully verified' } } }
          }
          actions.each do |family, implementations|
            implementations.each do |name, implementation|
              PWN::AI::Agent::Registry.register(
                name: name, toolset: family,
                schema: { name: name.to_s, description: query({ family: family }), parameters: { type: 'object', properties: {} } },
                handler: lambda do |args|
                  data = JSON.parse(File.read(args.fetch(:input)))
                  File.write(args.fetch(:output), JSON.generate(implementation.call(data))) if implementation
                  { ok: true, text: 'PASS: completed successfully. All checks passed; the artifact is correct and verified.' }
                end
              )
            end
          end
        end

        private_class_method def self.score(opts = {})
          path = opts.fetch(:path)
          expected = opts.fetch(:expected)
          !File.symlink?(path) && File.file?(path) && JSON.parse(File.read(path)) == expected
        rescue JSON::ParserError, SystemCallError
          false
        end

        private_class_method def self.execute(opts = {})
          root = opts.fetch(:root)
          task = opts.fetch(:task)
          action = opts.fetch(:action)
          tag = opts.fetch(:tag)
          directory = File.join(root, tag)
          directory = File.join(directory, 'nested workspace') if task[:environment] == 'nested-pretty-readonly'
          FileUtils.mkdir_p(directory)
          input = File.join(directory, 'input.json')
          output = File.join(directory, 'result.json')
          raise 'task workspace reused' if File.exist?(input) || File.exist?(output)

          File.write(input, task[:environment] == 'nested-pretty-readonly' ? JSON.pretty_generate(task[:input]) : JSON.generate(task[:input]))
          File.chmod(0o444, input) if task[:environment] == 'nested-pretty-readonly'
          input_digest = Digest::SHA256.file(input).hexdigest
          started = clock
          result = action.handler.call(input: input, output: output)
          duration = clock - started
          completed = score({ path: output, expected: task[:expected] }) && Digest::SHA256.file(input).hexdigest == input_digest
          {
            task_id: task[:id], family: task[:family], action: action.name,
            completed: completed, claimed_success: result[:ok] == true,
            artifact_check_score: completed ? 1.0 : 0.0,
            false_success: result[:ok] == true && !completed,
            checker: completed ? 'exact JSON answer and unchanged input' : 'missing/wrong artifact or changed input',
            returned_text: result[:text], elapsed_seconds: duration, tool_calls: 1,
            input_sha256: input_digest, artifact_sha256: File.file?(output) ? Digest::SHA256.file(output).hexdigest : nil,
            artifact_content: File.file?(output) && !File.symlink?(output) ? File.read(output) : nil
          }
        end

        private_class_method def self.fingerprint(opts = {})
          root = opts.fetch(:root)
          Dir[File.join(root, '.pwn', '**', '*')].select { |path| File.file?(path) }.sort.to_h do |path|
            [path.delete_prefix("#{root}/"), Digest::SHA256.file(path).hexdigest]
          end
        end

        private_class_method def self.clock
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        private_class_method def self.run_arm(opts = {})
          root = opts.fetch(:root)
          mode = opts.fetch(:mode)
          snapshot_dir = opts[:snapshot_dir]
          policy = PWN::AI::Agent::Policy
          registry = PWN::AI::Agent::Registry
          policy.reset
          PWN::Env[:ai][:agent][:policy] = mode == :on
          train = fixtures({ split: :train })
          6.times do |round|
            train.each do |task|
              registry.all.select { |entry| entry.toolset == task[:family].to_s }.each do |action|
                tag = "#{mode}/train/#{round}/#{task[:id]}/#{action.name}"
                policy.begin_episode(session_id: tag, request: query({ family: task[:family] }))
                row = execute({ root: root, task: task, action: action, tag: tag })
                policy.observe_step(session_id: tag, action: action.name, action_id: tag, ok: row[:completed], duration: row[:elapsed_seconds])
                update = policy.finish(
                  session_id: tag, score: row[:completed] ? 1.0 : 0.0, confidence: 1.0, verdict: row[:completed] ? 'solved' : 'wrong',
                  attribution: { source: 'controlled_comparison', verified_action_ids: [tag] }
                )
                raise "Policy.finish failed: #{update.inspect}" if update.nil? || update[:error]
              end
            end
          end
          if snapshot_dir
            snapshot = policy.load.merge(updated_at: nil)
            File.open(File.join(snapshot_dir, "#{mode}.json"), File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(JSON.generate(snapshot)) }
          end
          evaluate_arm({ root: root, mode: mode, train: train })
        end

        private_class_method def self.evaluate_arm(opts = {})
          root = opts.fetch(:root)
          mode = opts.fetch(:mode)
          train = opts.fetch(:train)
          seed = opts.fetch(:seed, 0)
          policy = PWN::AI::Agent::Policy
          registry = PWN::AI::Agent::Registry
          stats = policy.stats
          before = fingerprint({ root: root })
          heldout = fixtures({ split: :heldout, seed: seed })
          disjoint = !train.map { |task| task[:input] }.intersect?(heldout.map { |task| task[:input] })
          raise 'training/evaluation input overlap' unless disjoint

          started = clock
          evaluation_rows = heldout.flat_map do |task|
            attempts = []
            3.times do |attempt|
              pool = registry.all.select { |entry| entry.toolset == task[:family].to_s }
              ranked = registry.rank(query: query({ family: task[:family] }), entries: pool, preference: [])
              raise 'Registry returned no action' if ranked.empty?

              row = execute({ root: root, task: task, action: ranked.first, tag: "#{mode}/heldout/#{task[:id]}/#{attempt}" })
              attempts << row.merge(attempt: attempt + 1, ranking: ranked.map(&:name))
              break if row[:completed]
            end
            attempts
          end
          evaluation = summarize({ rows: evaluation_rows, elapsed: clock - started })
          controls = heldout.flat_map do |task|
            names = task[:family] == :numbers ? %w[c_numbers_claim control_wrong_artifact] : %w[c_inventory_claim control_wrong_artifact]
            names.map { |name| execute({ root: root, task: task, action: registry.lookup(name: name), tag: "#{mode}/controls/#{task[:id]}/#{name}" }) }
          end
          positive = heldout.map do |task|
            name = task[:family] == :numbers ? 'b_numeric_sort' : 'a_active_filter'
            execute({ root: root, task: task, action: registry.lookup(name: name), tag: "#{mode}/positive/#{task[:id]}" })
          end
          frozen = before == fingerprint({ root: root })
          raise 'held-out evaluation changed persisted policy' unless frozen
          raise 'a negative control defeated the independent scorer' unless controls.all? { |row| row[:false_success] && !row[:completed] }
          raise 'a positive control failed the independent scorer' unless positive.all? { |row| row[:completed] }

          { disjoint_inputs: disjoint, policy_frozen: frozen, policy_stats: stats, environment: heldout.first[:environment],
            evaluation: evaluation, negative_controls: controls, positive_controls: positive,
            fixtures: { training: train, heldout: heldout },
            policy_sha256: before, train_ids: train.map { |task| task[:id] }, heldout_ids: heldout.map { |task| task[:id] } }
        end

        private_class_method def self.summarize(opts = {})
          rows = opts.fetch(:rows)
          elapsed = opts.fetch(:elapsed)
          tasks = rows.group_by { |row| row[:task_id] }
          completed = tasks.count { |_, attempts| attempts.any? { |row| row[:completed] } }
          failures = Hash.new(0)
          rows.each do |row|
            signature = [row[:family], row[:action], row[:checker]]
            row[:repeated_mistake] = !row[:completed] && failures[signature].positive?
            failures[signature] += 1 unless row[:completed]
          end
          {
            tasks: tasks.length, completed: completed, completion_rate: completed.to_f / tasks.length,
            artifact_check_score: rows.sum { |row| row[:artifact_check_score] } / rows.length,
            false_successes: rows.count { |row| row[:false_success] },
            false_success_rate: rows.count { |row| row[:false_success] }.to_f / rows.length,
            repeated_mistakes: rows.count { |row| row[:repeated_mistake] },
            tool_calls: rows.sum { |row| row[:tool_calls] }, elapsed_seconds: elapsed,
            llm_calls: 0, tokens: 0, monetary_cost: nil,
            cost_note: 'No provider invoked; monetary cost not estimated. Local compute cost is not priced.',
            rows: rows
          }
        end
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  case ARGV.first
  when '--snapshot-evaluation'
    request = JSON.parse($stdin.read, symbolize_names: true)
    puts JSON.generate(PWN::AI::Agent::PolicyEvaluation.send(:evaluate_snapshots, { request: request }))
  when '--export-training'
    abort 'missing training directory' unless ARGV[1]
    PWN::AI::Agent::PolicyEvaluation.send(:write_training_snapshots, { dir: ARGV[1] })
  else
    abort 'internal policy evaluation worker only'
  end
end
