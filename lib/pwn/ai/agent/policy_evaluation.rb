# frozen_string_literal: true

require 'json'
require 'digest'
require 'open3'
require 'rbconfig'
require 'tmpdir'
require 'tempfile'
require 'timeout'

module PWN
  module AI
    module Agent
      # Opt-in, fixed local held-out evaluation. Never loaded by the online loop.
      module PolicyEvaluation
        RUNNER = File.expand_path('../../../../scripts/benchmark_policy.rb', __dir__).freeze
        MAX_SNAPSHOT_BYTES = 4_194_304
        WORKER_TIMEOUT_SECONDS = 30

        public_class_method def self.evaluate(opts = {})
          seed = opts.fetch(:seed, 0)
          raise ArgumentError, 'seed must be an integer in 0..7' unless seed.is_a?(Integer) && (0..7).cover?(seed)

          snapshots = %i[baseline candidate].to_h { |arm| [arm, read_snapshot(path: opts.fetch(arm))] }
          Dir.mktmpdir('pwn-policy-evaluator-', '/tmp') do |root|
            Open3.popen3(
              { 'HOME' => root, 'TMPDIR' => root, 'LANG' => 'C.UTF-8' },
              RbConfig.ruby, RUNNER, '--snapshot-evaluation',
              unsetenv_others: true, chdir: root, pgroup: true
            ) do |input, output, error, child|
              readers = [output, error].map { |io| Thread.new { io.read } }
              begin
                Timeout.timeout(WORKER_TIMEOUT_SECONDS) do
                  input.write(JSON.generate(snapshots: snapshots, seed: seed))
                  input.close
                  status = child.value
                  stdout, stderr = readers.map(&:value)
                  raise "held-out worker failed: #{stderr}" unless status.success?

                  JSON.parse(stdout, symbolize_names: true)
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

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Explicit operator action only; never called from Policy.finish/Loop.
        public_class_method def self.promote(opts = {})
          return { promoted: false, reason: 'disabled' } unless opts[:enabled] == true
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

          backup = "#{live}.rollback-#{prior_digest}.json"
          if File.exist?(backup)
            raise ArgumentError, 'rollback snapshot differs' unless read_snapshot(path: backup) == baseline
          else
            File.open(backup, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(baseline) }
          end
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
          raise ArgumentError, 'stop all policy writers and set quiescent: true' unless opts[:quiescent] == true

          receipt = opts.fetch(:receipt)
          raise ArgumentError, 'successful versioned policy promotion receipt required' unless receipt[:promoted] == true && receipt[:receipt_version] == 1 && receipt[:change_kind] == 'routing_policy' && receipt[:acceptance_sha256].to_s.match?(/\A[0-9a-f]{64}\z/)

          live = File.expand_path(opts.fetch(:live_path))
          prior_digest = receipt.fetch(:baseline_sha256)
          raise ArgumentError, 'invalid rollback digest' unless prior_digest.is_a?(String) && prior_digest.match?(/\A[0-9a-f]{64}\z/)

          backup = "#{live}.rollback-#{prior_digest}.json"
          raise ArgumentError, 'rollback target mismatch' unless receipt[:live_path] == live && receipt[:rollback_path] == backup

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
      end
    end
  end
end
