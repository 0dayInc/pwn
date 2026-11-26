# frozen_string_literal: true

require 'digest'
require 'json'
require 'securerandom'

module PWN
  module AI
    module Agent
      # One private, metadata-only receipt per top-level submission. Neither
      # delivery nor a controller decision is an independent correctness label.
      module Submission
        STATUSES = %w[complete incomplete blocked cancelled verification_error].freeze
        GOALS = (STATUSES + %w[partial awaiting_input]).freeze
        STAGES = %w[admission controller planning provider tool verification clarification cancellation finalization].freeze
        DELIVERIES = %w[displayed not_displayed].freeze
        ID = /\A[0-9a-f]{32}\z/
        DIGEST = /\A[0-9a-f]{64}\z/
        DIGEST_FIELDS = %i[request_key request_digest].freeze
        CATEGORIES = { status: (STATUSES + ['pending']).freeze, goal_status: (GOALS + ['pending']).freeze, stage: STAGES,
                       delivery: (DELIVERIES + ['unknown']).freeze, adjudication: %w[pass fail unknown].freeze }.freeze

        # Misuse of an explicit reservation, as distinct from optional I/O.
        class InvalidClaim < ArgumentError; end

        # Identity of this invocation, not just its reusable session/request ID.
        # Children share a correlation ID but cannot claim or close the receipt.
        class Scope
          attr_reader :id, :root_id, :role

          def initialize(opts)
            parent = Thread.current[:pwn_loop_submission_scope]
            nested = parent || opts[:nested] == true || Thread.current[:pwn_swarm_depth].to_i.positive? || TurnFinalizer.user_path? || Thread.current[TurnFinalizer::INLINE_KEY]
            @role = nested ? 'nested' : 'top_level'
            if nested
              runtime = Thread.current[:pwn_request_runtime]
              @root_id = parent&.root_id || Thread.current[:pwn_review_submission_id] || Policy.current_episode&.dig(:submission_id) || (runtime.submission_id if runtime.respond_to?(:submission_id))
            else
              @id = Submission.optional { opts[:submission_id].nil? ? Submission.open!(claimed: true) : Submission.claim!(submission_id: opts[:submission_id]) }
              @root_id = @id
            end
          end

          def owns?(episode)
            episode && episode[:submission_scope].equal?(self)
          end

          def notify(callback, row, failure)
            callback&.call(row)
          rescue StandardError, SecurityError
            raise unless failure # An observer is not a replacement for the original request error.
          end

          def close(runtime, request, interrupted: false)
            row = runtime&.outcome || { status: interrupted ? 'cancelled' : 'blocked', stage: interrupted ? 'cancellation' : 'admission' }
            return row unless id

            receipt = Submission.optional do
              Submission.close!(submission_id: id, outcome: row, request_key: (Digest::SHA256.hexdigest(runtime.request_id) if runtime),
                                request_digest: Digest::SHA256.hexdigest(runtime ? runtime.request : request.to_s))
            end
            if receipt
              checked = Submission.optional do
                report = runtime&.submission_report
                Submission.adjudicate!(submission_id: id, report: report.merge(submission_id: id)) if report
              end
            end
            row.merge(checked || receipt || { submission_id: id })
          end
        end

        public_class_method def self.open!(opts = {})
          claimed = opts.fetch(:claimed, false)
          raise ArgumentError, 'claimed must be a boolean' unless [true, false].include?(claimed)

          id = SecureRandom.hex(16)
          edit(id: id, create: true) do
            { submission_id: id, claimed: claimed, status: 'pending', goal_status: 'pending', stage: 'admission', delivery: 'unknown', adjudication: 'unknown' }
          end
          id
        end

        public_class_method def self.claim!(opts = {})
          id = opts[:submission_id]
          raise InvalidClaim, 'invalid submission identity' unless id.is_a?(String) && ID.match?(id)

          edit(id: id, claim: true) do |row|
            raise InvalidClaim, 'submission unavailable' if row[:claimed] || row[:status] != 'pending'

            row.merge(claimed: true)
          end
          id
        end

        # Parent-only recovery after admission failure or reaping the worker.
        public_class_method def self.abandon!(opts = {})
          status = enum(value: opts[:status], allowed: %w[blocked incomplete cancelled])
          stage = enum(value: opts[:stage], allowed: %w[admission controller cancellation])
          edit(id: opts[:submission_id]) { |row| row[:status] == 'pending' ? row.merge(status: status, goal_status: status, stage: stage) : row }
        end

        public_class_method def self.close!(opts = {})
          outcome = opts.fetch(:outcome)
          fields = { status: enum(value: outcome[:status], allowed: STATUSES),
                     goal_status: enum(value: outcome.fetch(:goal_status, outcome[:status]), allowed: GOALS),
                     stage: enum(value: outcome.fetch(:stage, 'controller'), allowed: STAGES) }
          DIGEST_FIELDS.each do |key|
            value = opts[key]
            next if value.nil?
            raise ArgumentError, 'invalid request digest' unless value.is_a?(String) && DIGEST.match?(value)

            fields[key] = value
          end
          edit(id: opts[:submission_id]) do |row|
            raise ArgumentError, 'submission is not claimed' unless row[:claimed]
            raise ArgumentError, 'submission already closed differently' unless row[:status] == 'pending' || row.slice(*fields.keys) == fields

            row.merge(fields)
          end
        end

        public_class_method def self.delivery!(opts = {})
          edit(id: opts[:submission_id]) do |row|
            observe(row: row, key: :delivery, value: enum(value: opts[:delivery], allowed: DELIVERIES))
          end
        end

        # Trusted host API, not a tool. Never accept a bare verdict or retain
        # the report (which can contain private criteria, paths or answers).
        public_class_method def self.adjudicate!(opts = {})
          edit(id: opts[:submission_id]) do |row|
            raise ArgumentError, 'submission has not closed' if row[:status] == 'pending'

            verdict = checked_verdict(row: row, report: opts[:report])
            observe(row: row, key: :adjudication, value: verdict)
          end
        end

        public_class_method def self.stats
          totals = { total: 0, unknown: 0, unreadable: 0, checked_blocks: 0, checked_completions: 0, false_blocks: 0, false_completions: 0,
                     false_block_rate: nil, false_completion_rate: nil, by_status: Hash.new(0), by_goal: Hash.new(0), by_delivery: Hash.new(0), by_stage: Hash.new(0) }
          begin
            File.lstat(root)
          rescue Errno::ENOENT
            return totals
          end

          locked(shared: true) do |directory|
            Dir.each_child(directory) do |name|
              next unless ID.match?(name)

              totals[:total] += 1
              begin
                tally(row: read(path: File.join(directory, name)), totals: totals)
              rescue IOError, SystemCallError, JSON::ParserError, ArgumentError, KeyError, TypeError
                totals[:unknown] += 1
                totals[:unreadable] += 1
              end
            end
          end
          totals[:false_block_rate] = totals[:false_blocks].fdiv(totals[:checked_blocks]) if totals[:checked_blocks].positive?
          totals[:false_completion_rate] = totals[:false_completions].fdiv(totals[:checked_completions]) if totals[:checked_completions].positive?
          totals
        end

        # Only wrap optional metadata operations, never request execution,
        # authorization, checkpointing, or calls to an acceptance checker.
        public_class_method def self.optional
          yield
        rescue InvalidClaim
          raise
        rescue StandardError, SecurityError
          nil
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Reserve one top-level receipt before admission.
            #{self}.open!(
              claimed: 'optional - true for a Loop that opens its own receipt; false reserves it for a child'
            )
            # Claim a pending parent reservation exactly once.
            #{self}.claim!(
              submission_id: 'required - opaque identity returned by open!'
            )
            # Close a still-pending reservation after admission fails or a worker is reaped.
            #{self}.abandon!(
              submission_id: 'required - identity of the reserved submission',
              status: 'required - blocked, incomplete or cancelled',
              stage: 'required - admission, controller or cancellation'
            )
            # Record the controller decision without storing private request content.
            #{self}.close!(
              submission_id: 'required - claimed submission identity',
              outcome: 'required - terminal status and optional goal_status and stage',
              request_key: 'optional - SHA-256 of the stable runtime request identifier',
              request_digest: 'optional - SHA-256 of the effective request, needed for independent adjudication'
            )
            # Record what the presentation owner actually observed.
            #{self}.delivery!(
              submission_id: 'required - submission whose presentation was observed',
              delivery: 'required - displayed or not_displayed; do not infer this from controller completion'
            )
            # Attach a separately observed native acceptance check to its submission.
            #{self}.adjudicate!(
              submission_id: 'required - identity of the closed submission checked by the host',
              report: 'required - native Verification.run report bound by the host to this submission_id and effective request digest'
            )
            # Count submissions, checked disagreements, and unknown observations.
            #{self}.stats
            # Isolate optional receipt I/O without swallowing an invalid explicit claim.
            #{self}.optional { ... }
            # Display module author information.
            #{self}.authors
          "
        end

        private_class_method def self.checked_verdict(opts = {})
          row = opts[:row]
          report = opts[:report]
          unless report.is_a?(Hash) && report[:runner_version] == 1 && report[:attribution].is_a?(Hash) && report.dig(:attribution, :source) == 'independent_verifier' &&
                 report[:submission_id] == row[:submission_id] && row[:request_digest] && report[:request_digest] == row[:request_digest]
            raise ArgumentError, 'bound native verification report required'
          end

          requirements = report[:requirements]
          checks = report[:checks]
          unless requirements.is_a?(Array) && !requirements.empty? && requirements.all? { |r| r.is_a?(String) && !r.strip.empty? } &&
                 checks.is_a?(Array) && checks.all? { |c| c.is_a?(Hash) && requirements.include?(c[:criterion]) && [true, false, nil].include?(c[:passed]) && !c[:evidence].to_s.empty? }
            raise ArgumentError, 'invalid verification criteria or checks'
          end

          missing = requirements - checks.map { |c| c[:criterion] }
          verdict = if checks.any? { |c| c[:passed] == false } then 'fail'
                    elsif missing.empty? && checks.all? { |c| c[:passed] == true } then 'pass'
                    else 'unknown'
                    end
          raise ArgumentError, 'inconsistent verification report' unless report[:missing] == missing && report[:status].to_s == verdict

          verdict
        end

        private_class_method def self.observe(opts = {})
          row, key, value = opts.values_at(:row, :key, :value)
          raise ArgumentError, "conflicting #{key} acknowledgment" unless ['unknown', value].include?(row.fetch(key))

          row.merge(key => value)
        end

        private_class_method def self.tally(opts = {})
          row = opts[:row]
          totals = opts[:totals]
          totals[:by_status][row[:status]] += 1
          totals[:by_goal][row[:goal_status]] += 1
          totals[:by_stage][row[:stage]] += 1
          totals[:by_delivery][row[:delivery]] += 1
          if row[:adjudication] == 'unknown'
            totals[:unknown] += 1
          elsif row[:status] == 'blocked'
            totals[:checked_blocks] += 1
            totals[:false_blocks] += 1 if row[:adjudication] == 'pass'
          elsif row[:goal_status] == 'complete'
            totals[:checked_completions] += 1
            totals[:false_completions] += 1 if row[:adjudication] == 'fail'
          end
        end

        private_class_method def self.enum(opts = {})
          value = opts[:value].to_s
          raise ArgumentError, 'invalid submission metadata' unless opts[:allowed].include?(value)

          value
        end

        private_class_method def self.root
          File.join(PWN::Sessions.sessions_dir(read_only: true), 'support', 'submissions')
        end

        private_class_method def self.locked(opts = {})
          shared = opts[:shared]
          PWN::AI::Sandbox.control_directory(path: root) do |directory|
            stat = File.stat(directory)
            raise IOError, 'unsafe submission directory' unless stat.owned? && stat.mode.nobits?(0o077)

            flags = shared ? File::RDONLY : File::RDWR | File::CREAT
            File.open(File.join(directory, '.lock'), flags | File::NOFOLLOW | File::NONBLOCK, 0o600) do |lock|
              private_file!(stat: lock.stat)
              # A stalled reader/writer must never stall ordinary admission.
              mode = (shared ? File::LOCK_SH : File::LOCK_EX) | File::LOCK_NB
              deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.25
              until lock.flock(mode)
                raise IOError, 'submission index busy' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

                sleep 0.005
              end
              yield directory
            end
          end
        end

        private_class_method def self.private_file!(opts = {})
          stat = opts[:stat]
          raise IOError, 'unsafe submission file' unless stat.file? && stat.nlink == 1 && stat.owned? && stat.mode.nobits?(0o077)
        end

        private_class_method def self.valid_row?(opts = {})
          row = opts[:row]
          row.is_a?(Hash) && row[:submission_id] == opts[:id] && [true, false].include?(row[:claimed]) &&
            (row.keys - CATEGORIES.keys - DIGEST_FIELDS - %i[submission_id claimed]).empty? &&
            CATEGORIES.all? { |key, values| values.include?(row[key]) } &&
            DIGEST_FIELDS.all? { |key| row[key].nil? || (row[key].is_a?(String) && DIGEST.match?(row[key])) }
        end

        private_class_method def self.read(opts = {})
          path = opts[:path]
          File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
            private_file!(stat: file.stat)
            data = file.read(1025)
            raise IOError, 'invalid submission receipt' unless data && data.bytesize <= 1024

            row = JSON.parse(data, symbolize_names: true)
            raise IOError, 'invalid submission metadata' unless valid_row?(row: row, id: File.basename(path))

            row
          end
        end

        private_class_method def self.edit(opts = {})
          id = opts[:id]
          raise ArgumentError, 'invalid submission identity' unless id.is_a?(String) && ID.match?(id)

          locked do |directory|
            path = File.join(directory, id)
            raise IOError, 'submission identity collision' if opts[:create] && (File.exist?(path) || File.symlink?(path))

            begin
              old = read(path: path) unless opts[:create]
            rescue Errno::ENOENT
              raise InvalidClaim, 'submission unavailable' if opts[:claim]

              raise
            end
            row = yield old
            next row if old == row

            temp = "#{path}.#{SecureRandom.hex(8)}.tmp"
            owned = false
            File.open(temp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
              owned = true
              file.write(JSON.generate(row))
              file.fsync
            end
            File.rename(temp, path)
            owned = false
            row
          ensure
            File.unlink(temp) if owned
          end
        end
      end
    end
  end
end
