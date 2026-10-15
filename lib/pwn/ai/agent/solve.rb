# frozen_string_literal: true

require 'digest'
require 'json'
require 'tmpdir'
require 'shellwords'
require 'stringio'
require 'open3'
require 'find'
require 'timeout'

module PWN
  module AI
    module Agent
      # Revision-bound, single-writer team coordinator. Role replies are proposals,
      # never observations. Only host-executed checks can become evidence.
      module Solve
        ROLES = %w[protagonist antagonist verifier integrator].freeze

        # Steering belongs to the objective, not to one child's replacement request.
        class Control < Loop::Steering
          class Stopped < Exception; end # rubocop:disable Lint/InheritException -- escape provider retry handlers
          class Limit < Exception; end # rubocop:disable Lint/InheritException -- bounded role dispatch

          def initialize(**args)
            super
            @solve_mutex = Mutex.new
            @guidance = []
            @paused = false
            @stopped = false
          end

          def submit(instruction)
            return if instruction.to_s.strip.empty?

            @solve_mutex.synchronize { @guidance << instruction.to_s.dup }
          end

          def guidance
            @solve_mutex.synchronize { @guidance.dup }
          end

          def begin_turn
            @model_calls = 0
          end

          def model(messages:, &block)
            check_stop
            @model_calls = @model_calls.to_i + 1
            raise Limit, 'Role model-call limit reached (25); objective remains incomplete.' if @model_calls > 25

            super
          end

          def stop
            @solve_mutex.synchronize { @stopped = true }
            request_model_cancel
          end

          def pause(value)
            @solve_mutex.synchronize { @paused = value }
          end

          def check_stop
            loop do
              stopped, paused = @solve_mutex.synchronize { [@stopped, @paused] }
              raise Stopped, 'Solve cancelled at a safe boundary; completed work is not undone.' if stopped
              break unless paused

              sleep 0.05
            end
          end

          def checkpoint(**options)
            @phase = options[:phase] || :boundary
            check_stop
          rescue Stopped
            yield if block_given?
            raise
          end
        end

        # Detached edit isolation, not a security sandbox. No commits or source-index writes.
        class Worktree # rubocop:disable Metrics/ClassLength -- ownership, snapshot and guarded patch lifecycle
          attr_reader :metadata, :path

          def initialize(source)
            @source = source
          end

          def create
            root = git(@source, 'rev-parse', '--show-toplevel').strip
            raise ArgumentError, 'worktree workspace must be the Git repository root' unless File.realpath(root) == @source
            raise ArgumentError, 'worktree requires a clean checkout including untracked/ignored files; commit, stash, or use a clean clone first' unless git(@source, 'status', '--porcelain', '--untracked-files=all', '--ignored').empty?

            base = git(@source, 'rev-parse', 'HEAD').strip
            original = snapshot(@source)
            index = index_hash
            @owner = Dir.mktmpdir('pwn-solve-worktree-')
            @path = File.join(@owner, 'checkout')
            @metadata = { source: @source, path: @path, owner: @owner, token: SecureRandom.hex(32), base: base,
                          original: original, original_index: index }
            File.write(File.join(@owner, 'owner.json'), JSON.generate(@metadata), perm: 0o600)
            git(@source, 'worktree', 'add', '--detach', @path, base)
            raise 'source changed while creating worktree' unless snapshot(@source) == original && index_hash == index && git(@source, 'rev-parse', 'HEAD').strip == base
            raise 'checkout differs from source (hidden dirty files, permissions, or filters); use a clean clone' unless snapshot == original

            @path
          end

          def snapshot(root = @path)
            rows = {}
            bytes = 0
            Find.find(root) do |path|
              next if path == root

              relative = path.delete_prefix("#{root}/")
              Find.prune if relative == '.git'
              raise ArgumentError, "unsupported nested repository: #{relative}" if File.basename(path) == '.git'

              stat = File.lstat(path)
              raise ArgumentError, "unsupported symlink or special file: #{relative}" unless stat.directory? || stat.file?
              next if stat.directory?

              bytes += stat.size
              raise ArgumentError, 'worktree snapshot exceeds 10000 files or 256 MiB' if rows.length >= 10_000 || bytes > 268_435_456

              rows[relative] = [Digest::SHA256.file(path).hexdigest, stat.mode & 0o777]
            end
            rows.sort.to_h
          end

          def export(directory, revision, tested)
            current = snapshot
            patch = File.join(directory, 'candidate.patch')
            index = File.join(@owner, 'patch.index')
            env = { 'GIT_INDEX_FILE' => index }
            git(@path, 'read-tree', @metadata[:base], env: env)
            git(@path, 'add', '--all', '--force', '--', '.', env: env)
            bytes = git(@path, 'diff', '--cached', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', @metadata[:base], '--', env: env)
            raise 'worktree changed while exporting patch' unless snapshot == current

            File.binwrite(patch, bytes)
            File.chmod(0o600, patch)
            @metadata = @metadata.merge(patch_path: patch, patch_sha256: Digest::SHA256.hexdigest(bytes), candidate: current,
                                        tested_revision: tested ? revision : nil, revision: revision)
            verify_patch(patch, current) if tested
            @metadata
          ensure
            File.unlink(index) if index && File.file?(index)
          end

          def recover(record_path)
            @record_path = File.realpath(record_path)
            @record = JSON.parse(File.read(@record_path))
            @metadata = @record.fetch('worktree').transform_keys(&:to_sym)
            @source = File.realpath(@metadata.fetch(:source))
            @owner = File.realpath(@metadata.fetch(:owner))
            @path = File.realpath(@metadata.fetch(:path))
            raise 'not an owned temporary worktree' unless File.dirname(@owner) == File.realpath(Dir.tmpdir) && File.basename(@owner).start_with?('pwn-solve-worktree-') && @path == File.join(@owner, 'checkout')

            marker = JSON.parse(File.read(File.join(@owner, 'owner.json')))
            %i[source path owner token base original original_index].each do |key|
              raise 'worktree ownership mismatch' unless marker[key.to_s] == @metadata[key]
            end
            registered = git(@source, 'worktree', 'list', '--porcelain').lines.any? { |line| line.chomp == "worktree #{@path}" }
            raise 'worktree is not registered to source' unless registered

            self
          end

          def guarded
            lock_path = File.join(Dir.tmpdir, "pwn-solve-#{Digest::SHA256.hexdigest(@source)}.lock")
            File.open(lock_path, File::RDWR | File::CREAT, 0o600) do |lock|
              raise 'another solve owns this workspace' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

              yield
            end
          end

          def candidate_guard
            raise 'candidate changed since snapshot' unless snapshot == @metadata.fetch(:candidate)
            raise 'worktree HEAD changed' unless git(@path, 'rev-parse', 'HEAD').strip == @metadata.fetch(:base)
          end

          def source_guard
            raise 'source changed since snapshot; review and rerun in a clean worktree' unless snapshot(@source) == @metadata.fetch(:original) && index_hash == @metadata.fetch(:original_index) && git(@source, 'rev-parse', 'HEAD').strip == @metadata.fetch(:base)
          end

          def apply(revision, confirmation)
            guarded do
              raise ArgumentError, 'human confirmation must exactly match APPLY and the tested revision' unless revision.is_a?(String) && !revision.empty? && confirmation == "APPLY #{revision}"
              raise 'only an accepted tested revision may be applied' unless @record['status'] == 'accepted' && @record['revision'] == revision && @metadata[:tested_revision] == revision

              revision_guard(revision)
              source_guard
              candidate_guard
              patch = @metadata.fetch(:patch_path)
              raise 'patch changed since snapshot' unless Digest::SHA256.file(patch).hexdigest == @metadata.fetch(:patch_sha256)

              verify_patch(patch, @metadata[:candidate])
              git(@source, 'apply', '--check', '--', patch) unless File.empty?(patch)
              source_guard
              git(@source, 'apply', '--', patch) unless File.empty?(patch)
              raise 'applied files differ from tested snapshot; inspect source' unless snapshot(@source) == @metadata[:candidate] && index_hash == @metadata[:original_index]

              result = { ok: true, status: 'applied', revision: revision, patch_sha256: @metadata[:patch_sha256] }
              persist('application', result)
              result
            end
          end

          def revision_guard(revision)
            manifest = @record.fetch('revision_manifest')
            raise 'revision manifest digest mismatch' unless Digest::SHA256.hexdigest(JSON.generate(manifest)) == revision
            raise 'revision manifest does not match candidate/base/objective' unless manifest['tree'] == @metadata[:candidate] && manifest['base'] == @metadata[:base] && manifest['request'] == @record['request']

            evidence = @record.fetch('evidence')
            raise 'revision has no verified evidence' if evidence.empty? || evidence.any? { |row| row['passed'] != true || row['revision'] != revision }
            raise 'revision has uncovered requirements' unless (manifest.fetch('requirements').keys - evidence.flat_map { |row| row.fetch('requirements') }).empty?
          end

          def verify_patch(patch, candidate)
            source_guard
            Dir.mktmpdir('pwn-solve-apply-') do |copy|
              @metadata[:original].each_key do |relative|
                target = File.join(copy, relative)
                FileUtils.mkdir_p(File.dirname(target))
                FileUtils.cp(File.join(@source, relative), target, preserve: true)
              end
              raise 'source changed while copying patch inputs' unless snapshot(copy) == @metadata[:original]

              git(copy, 'apply', '--', patch) unless File.empty?(patch)
              raise 'patch cannot reproduce tested snapshot (including permissions)' unless snapshot(copy) == candidate
            end
          end

          def cleanup(confirmation)
            guarded do
              token = @metadata[:revision] || @metadata.fetch(:token)
              raise ArgumentError, 'human confirmation must exactly match DISCARD and the revision (or ownership token before a revision exists)' unless confirmation == "DISCARD #{token}"

              candidate_guard
              git(@source, 'worktree', 'remove', '--force', '--', @path)
              raise 'worktree still exists after cleanup' if File.exist?(@path)

              result = { ok: true, status: 'removed', patch_path: @metadata[:patch_path] }
              persist('cleanup', result)
              result
            end
          end

          def persist(key, value)
            @record[key] = value
            File.write(@record_path, JSON.pretty_generate(@record), perm: 0o600)
          end

          def index_hash
            path = git(@source, 'rev-parse', '--path-format=absolute', '--git-path', 'index').strip
            Digest::SHA256.file(path).hexdigest
          end

          def git(root, *args, env: {})
            environment = %w[GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES].to_h { |key| [key, nil] }
            environment.merge!('GIT_OPTIONAL_LOCKS' => '0', 'GIT_TERMINAL_PROMPT' => '0')
            Open3.popen3(environment.merge(env), 'git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', root, *args, pgroup: true) do |stdin, stdout, stderr, wait|
              stdin.close
              readers = [stdout, stderr].map { |io| Thread.new { io.read } }
              begin
                status, out, err = Timeout.timeout(30) { [wait.value, *readers.map(&:value)] }
                raise "git #{args.first} failed: #{err}" unless status.success?

                out
              ensure
                Process.kill('KILL', -wait.pid) if wait.alive?
                readers.each { |thread| thread.kill if thread.alive? }
              end
            end
          end
        end

        # Serial role dispatch ensures there is exactly one model writer.
        class Run # rubocop:disable Metrics/ClassLength -- one revision-bound coordinator lifecycle
          def initialize(opts)
            @opts = opts
            @request = opts[:request].to_s.dup.freeze
            raise ArgumentError, 'request is required' if @request.strip.empty?

            @workspace = File.realpath(opts[:workspace] || Dir.pwd)
            @rounds = Integer(opts.fetch(:rounds, 3))
            raise ArgumentError, 'rounds must be between 1 and 10' unless @rounds.between?(1, 10)

            @control = opts[:steering] || Control.new(input: StringIO.new, output: StringIO.new)
            raise ArgumentError, 'solve requires Solve::Control for coordinator-wide steering' unless @control.is_a?(Control)

            @verification_timeout = Integer(opts.fetch(:verification_timeout, 60))
            raise ArgumentError, 'verification_timeout must be 1..600 seconds' unless @verification_timeout.between?(1, 600)

            @role_timeout = Integer(opts.fetch(:role_timeout, 300))
            raise ArgumentError, 'role_timeout must be 1..600 seconds' unless @role_timeout.between?(1, 600)

            @requirements = { 'R0' => @request }
            @states = ROLES.to_h { |role| [role, 'waiting'] }
            @records = []
            @evidence = []
            @objections = []
            @artifacts = {}
            @dependencies = {}
            @revision = nil
            @repair = nil
            @guidance = []
          end

          def run
            prepare
            assessment = turn('antagonist', 'assess')
            Array(assessment.fetch(:requirements)).each_with_index { |text, i| @requirements["R#{i + 1}"] = text.to_s }
            @assessment = assessment
            @rounds.times do |index|
              @round = index + 1
              boundary
              @guidance = guidance
              @guidance.each_with_index { |instruction, i| @requirements["S#{i + 1}"] = instruction }
              candidate = turn('protagonist', 'build')
              @artifacts = observe(candidate.fetch(:artifacts))
              @dependencies = observe(candidate.fetch(:dependencies, []))
              raise ArgumentError, 'candidate must declare at least one existing artifact' if @artifacts.empty?

              @tree_snapshot = @worktree&.snapshot
              check_manifest
              @input_modes = input_modes(@workspace)
              @revision_manifest = JSON.parse(JSON.generate(run: @sid, round: @round, request: @request, requirements: @requirements, artifacts: @artifacts,
                                                            dependencies: @dependencies, modes: @input_modes, tree: @tree_snapshot, base: @worktree&.metadata&.dig(:base), guidance: @guidance))
              @revision = digest(@revision_manifest)
              @records << { role: 'coordinator', phase: 'candidate', revision: @revision, artifacts: @artifacts.dup, round: @round }
              @candidate = candidate
              critique = turn('antagonist', 'critique')
              @objections = Array(critique.fetch(:objections))
              verification = turn('verifier', 'verify')
              @evidence = execute_checks(verification.fetch(:checks))
              integration = turn('integrator', 'integrate')
              boundary
              return result('accepted', integration[:summary].to_s) if integration[:decision] == 'accept' && acceptable?

              @repair = { instruction: integration[:repair], objections: @objections, evidence: @evidence,
                          stale: !current?, uncovered: uncovered }
              emit
            end
            result('incomplete', 'Round limit reached; unresolved, stale, or unverified requirements remain.')
          rescue Control::Stopped => e
            result('cancelled', e.message)
          rescue Control::Limit => e
            result('incomplete', e.message)
          rescue StandardError => e
            result('incomplete', "#{e.class}: #{e.message}")
          ensure
            @lock&.flock(File::LOCK_UN)
            @lock&.close
          end

          private

          def prepare
            Registry.discover
            # A file lock also excludes another process's solve writer in this workspace.
            lock_path = File.join(Dir.tmpdir, "pwn-solve-#{Digest::SHA256.hexdigest(@workspace)}.lock")
            @lock = File.open(lock_path, File::RDWR | File::CREAT, 0o600)
            raise 'another solve owns this workspace' unless @lock.flock(File::LOCK_EX | File::LOCK_NB)

            @sid = Swarm.create(topic: @request)[:swarm_id]
            if @opts[:worktree]
              @worktree = Worktree.new(@workspace)
              @workspace = @worktree.create
            end
            configured = Swarm.personas(swarm_id: @opts[:swarm_id])
            @personas = ROLES.to_h do |role|
              persona = configured[:"solve_#{role}"] || {}
              engine = (persona[:engine] || Thread.current[:pwn_swarm_engine] || PWN::Env.dig(:ai, :active)).to_s
              raise ArgumentError, "unsupported solve provider: #{engine}" unless Loop::ENGINE_MODS.key?(engine.to_sym)

              provider = PWN::Env.dig(:ai, engine.to_sym) || {}
              credentials = [provider[:key], provider.dig(:oauth, :bearer_token), provider.dig(:oauth, :refresh_token)]
              raise ArgumentError, "solve_#{role}: configure #{engine} credentials first; solve never starts a login" if engine != 'ollama' && credentials.none? { |value| !value.to_s.strip.empty? && !value.to_s.match?(/\A(?:optional|required)\s*-/) }

              writer_tools = @worktree ? ['terminal'] : %w[terminal pwn]
              [role, persona.merge(engine: engine, toolsets: role == 'protagonist' ? writer_tools : [],
                                   role: "#{persona[:role]}\nBuilt-in solve #{role}. Follow the structured handoff; original request is the sole objective.")]
            end
          end

          def turn(role, phase)
            boundary
            @control.begin_turn
            @states[role] = phase
            emit
            payload = { phase: phase, role: role, original_request: @request, requirements: @requirements,
                        workspace: @workspace, worktree: !@worktree.nil?, round: @round, revision: @revision, guidance: guidance,
                        assessment: @assessment, candidate: @candidate, artifacts: artifact_text, dependencies: @dependencies,
                        objections: @objections, evidence: @evidence, repair: @repair }
            prior = Thread.current[:pwn_solve_tools]
            prior_workspace = Thread.current[:pwn_solve_workspace]
            Thread.current[:pwn_solve_workspace] = @workspace if @worktree
            writer_tools = @worktree ? ['shell'] : %w[shell pwn_eval]
            Thread.current[:pwn_solve_tools] = role == 'protagonist' ? writer_tools : []
            reply = Timeout.timeout(@role_timeout, Control::Limit, "#{role} deadline exceeded (#{@role_timeout}s); objective remains incomplete.") do
              Swarm.ask(name: "solve_#{role}", persona: @personas.fetch(role), request: @request,
                        swarm_id: @sid, handoff: "#{contract(phase)}\nSOLVE HANDOFF\n#{JSON.generate(payload)}",
                        steering: @control, usage_observer: @opts[:usage_observer], on_tool: @opts[:on_tool])
            end
            row = JSON.parse(reply.fetch(:reply), symbolize_names: true)
            raise ArgumentError, "#{role} handoff must be an object" unless row.is_a?(Hash)
            raise ArgumentError, "#{role} returned a stale revision" if %w[critique verify integrate].include?(phase) && row[:revision] != @revision

            @records << { role: role, phase: phase, revision: @revision, data: row }
            @states[role] = 'done'
            emit
            row
          ensure
            Thread.current[:pwn_solve_tools] = prior
            Thread.current[:pwn_solve_workspace] = prior_workspace
          end

          def contract(phase)
            shapes = {
              'assess' => '{"requirements":["every atomic requirement in original request"],"risks":["independent risk assessment"]}',
              'build' => '{"artifacts":["relative/file"],"dependencies":["relative/test-or-input"],"summary":"what changed"}',
              'critique' => '{"revision":"exact revision","objections":["unresolved correctness issue; empty only if none"]}',
              'verify' => '{"revision":"exact revision","checks":[{"requirements":["R0","R1"],"command":"real test command","timeout":60,"contract":{"type":"stdout","equals":"exact bytes"}}]}',
              'integrate' => '{"revision":"exact revision","decision":"accept or repair","repair":"targeted repair for protagonist","summary":"integrated result"}'
            }
            "Return ONLY a JSON object matching #{shapes.fetch(phase)}. Do not replace the objective. " \
              'Protagonist alone may change files. Review roles have no tool access. Verification commands run by the coordinator ' \
              'in a disposable copy of declared artifacts and dependencies, not the working tree. Declare every test dependency explicitly. ' \
              'In worktree mode declare all changed files (including deletions) as artifacts; do not commit or change the original checkout. Worktrees are NOT security sandboxes. ' \
              'Contracts: stdout with equals (legacy stdout also supported); exit_status for silent exit 0; json_field with path array and equals; ' \
              'test_results with format rspec_json (stdout summary: positive integer example_count, zero failure_count and pending_count); ' \
              'artifact with declared path and exists boolean, sha256 and/or size in bytes. Every contract requires an executed command exiting 0. ' \
              'Checks must test the named requirements, not print a success claim. R0 covers the ENTIRE original request. ' \
              'Never accept missing evidence, unresolved objections, or omitted requirements. Integration requests repairs; it does not write.'
          end

          def observe(paths)
            Array(paths).to_h do |relative|
              raise ArgumentError, 'artifact path must be relative' unless relative.is_a?(String) && !relative.start_with?('/')

              expanded = File.expand_path(relative, @workspace)
              raise ArgumentError, 'artifact path must be canonical and within workspace' unless expanded.start_with?("#{@workspace}/") && expanded.delete_prefix("#{@workspace}/") == relative && !relative.split('/').include?('.git')
              next [relative, nil] if @worktree && !File.exist?(expanded) && !File.symlink?(expanded)

              path = File.realpath(expanded)
              raise ArgumentError, "artifact outside workspace: #{relative}" unless path.start_with?("#{@workspace}/")
              raise ArgumentError, "artifact must be a regular file: #{relative}" unless File.file?(path)
              raise ArgumentError, "artifact symlink is not supported: #{relative}" unless path == File.expand_path(relative, @workspace)

              [relative, Digest::SHA256.file(path).hexdigest]
            end
          end

          def artifact_text
            @artifacts.to_h do |path, sha|
              next [path, { deleted: true }] if sha.nil?

              file = File.join(@workspace, path)
              bytes = File.binread(file, 131_072)
              [path, { sha256: sha, bytes: File.size(file), truncated: File.size(file) > 131_072,
                       text: bytes.encode('UTF-8', invalid: :replace, undef: :replace) }]
            end
          end

          def execute_checks(checks)
            raise ArgumentError, 'verifier must supply 1..32 checks' unless checks.is_a?(Array) && checks.length.between?(1, 32)

            @states['verifier'] = 'checking'
            emit
            @evidence = []
            checks.each do |check|
              boundary
              ids = Array(check[:requirements]).map(&:to_s)
              raise ArgumentError, 'check must name known requirements' if ids.empty? || (ids - @requirements.keys).any?
              raise ArgumentError, 'check needs a command' if check[:command].to_s.strip.empty?

              check[:contract] ||= { type: 'stdout', equals: check.fetch(:stdout) }
              raise ArgumentError, 'unsupported verification contract' unless %w[stdout exit_status json_field test_results artifact].include?(check[:contract][:type])

              check[:timeout] = Integer(check.fetch(:timeout, @verification_timeout))
              raise ArgumentError, "check timeout must be 1..#{@verification_timeout} seconds" unless check[:timeout].between?(1, @verification_timeout)

              @evidence << execute_check(check, ids)
              @records << { role: 'verifier', phase: 'check', revision: @revision, evidence: @evidence.last }
            end
            @states['verifier'] = 'done'
            @records << { role: 'verifier', phase: 'verification', revision: @revision, evidence: @evidence.dup }
            emit
            @evidence
          end

          def execute_check(check, ids)
            Dir.mktmpdir('pwn-solve-verify') do |copy|
              inputs.each do |path, sha|
                next if sha.nil?

                destination = File.expand_path(path, copy)
                raise ArgumentError, 'invalid artifact copy path' unless destination.start_with?("#{copy}/")

                FileUtils.mkdir_p(File.dirname(destination))
                FileUtils.cp(File.join(@workspace, path), destination, preserve: true)
              end
              copied = inputs.to_h { |path, _sha| [path, File.file?(File.join(copy, path)) ? Digest::SHA256.file(File.join(copy, path)).hexdigest : nil] }
              raise 'candidate changed while copying verification inputs' unless copied == inputs && input_modes(copy) == @input_modes

              prior = Thread.current[:pwn_solve_tools]
              Thread.current[:pwn_solve_tools] = ['shell']
              command = "cd #{Shellwords.escape(copy)} && (\n#{check[:command]}\n)"
              # Each independent contract owns its deadline ledger; a timed-out check
              # must not force unrelated checks or later missions to retry its payload.
              raw = Dispatch.call(budget_ledger: {}, tool_call: { id: SecureRandom.hex(8), function: { name: 'shell', arguments: JSON.generate(command: command, timeout: check[:timeout]) } })
              @opts[:on_tool]&.call('shell', { command: command }, raw)
              response = JSON.parse(raw, symbolize_names: true)
              observed = response[:result].is_a?(Hash) ? response[:result] : {}
              unchanged = inputs.all? do |path, sha|
                target = File.join(copy, path)
                !File.symlink?(target) && (sha.nil? ? !File.exist?(target) : File.file?(target) && Digest::SHA256.file(target).hexdigest == sha)
              end
              unchanged &&= input_modes(copy) == @input_modes
              matches = contract_matches?(check[:contract], observed, copy)
              { requirements: ids, revision: @revision, command: check[:command], contract: check[:contract], stdout: observed[:stdout],
                stderr: observed[:stderr], exitstatus: observed[:exit], raw: raw, timeout: check[:timeout], inputs: inputs.dup,
                passed: response[:success] == true && observed[:exit].is_a?(Integer) && observed[:exit].zero? && matches && unchanged && current? }
            ensure
              Thread.current[:pwn_solve_tools] = prior
            end
          end

          def inputs
            @dependencies.merge(@artifacts)
          end

          def input_modes(root)
            inputs.to_h { |path, sha| [path, sha.nil? ? nil : File.stat(File.join(root, path)).mode & 0o777] }
          end

          def check_manifest
            return unless @worktree

            base = @worktree.metadata[:original]
            changed = (base.keys | @tree_snapshot.keys).reject { |path| base[path] == @tree_snapshot[path] }
            omitted = changed - @artifacts.keys
            raise ArgumentError, "declare all changed files as artifacts: #{omitted.join(', ')}" unless omitted.empty?
          end

          def contract_matches?(contract, observed, copy)
            case contract.fetch(:type)
            when 'exit_status' then true
            when 'stdout' then contract.fetch(:equals).is_a?(String) && observed[:stdout] == contract[:equals]
            when 'json_field'
              path = contract.fetch(:path)
              return false unless path.is_a?(Array) && !path.empty?

              value = JSON.parse(observed.fetch(:stdout))
              path.each do |key|
                return false unless (value.is_a?(Hash) && key.is_a?(String)) || (value.is_a?(Array) && key.is_a?(Integer) && key >= 0)

                value = value.fetch(key)
              end
              value == contract.fetch(:equals)
            when 'test_results'
              return false unless contract[:format] == 'rspec_json'

              summary = JSON.parse(observed.fetch(:stdout)).fetch('summary')
              %w[example_count failure_count pending_count].all? { |key| summary[key].is_a?(Integer) } &&
                summary['example_count'].positive? && summary['failure_count'].zero? && summary['pending_count'].zero?
            when 'artifact'
              relative = contract.fetch(:path)
              return false unless inputs.key?(relative)

              path = File.join(copy, relative)
              return false if File.symlink?(path)
              return false unless contract.keys.intersect?(%i[exists sha256 size])
              return false if contract.key?(:exists) && (![true, false].include?(contract[:exists]) || File.file?(path) != contract[:exists])
              return false if contract.key?(:sha256) && (!File.file?(path) || Digest::SHA256.file(path).hexdigest != contract[:sha256])
              return false if contract.key?(:size) && (!File.file?(path) || File.size(path) != contract[:size])

              true
            end
          rescue TypeError, IndexError, JSON::ParserError
            false
          end

          def current?
            guidance == @guidance && observe(inputs.keys) == inputs && input_modes(@workspace) == @input_modes && (!@worktree || @worktree.snapshot == @tree_snapshot)
          rescue StandardError
            false
          end

          def uncovered
            @requirements.keys - @evidence.select { |row| row[:passed] && row[:revision] == @revision }.flat_map { |row| row[:requirements] }
          end

          def acceptable?
            !@evidence.empty? && @evidence.all? { |row| row[:passed] } && uncovered.empty? && @objections.empty? && current?
          end

          def digest(value)
            Digest::SHA256.hexdigest(JSON.generate(value))
          end

          def guidance
            @control.respond_to?(:guidance) ? @control.guidance : []
          end

          def boundary
            @control&.check_stop
          end

          def emit
            path = File.join(Swarm::SWARM_ROOT, @sid, 'solve.json') if @sid
            state = { status: 'running', roles: @states, request: @request, requirements: @requirements,
                      artifacts: @artifacts, objections: @objections, round: @round, revision: @revision,
                      evidence: @evidence, records: @records, uncovered: uncovered, repair: @repair,
                      record_path: path, workspace: @workspace, checkpoint_at: Time.now.utc.iso8601,
                      routing: (@personas || {}).transform_values { |row| row.slice(:engine, :model) } }
            state = Marshal.load(Marshal.dump(state))
            persist_checkpoint(path, state) if path
            @opts[:on_state]&.call(state)
          end

          def persist_checkpoint(path, data)
            temporary = "#{path}.#{Process.pid}.#{Thread.current.object_id}.tmp"
            File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
              file.write(JSON.pretty_generate(data))
              file.flush
              file.fsync
            end
            File.rename(temporary, path)
            File.open(File.dirname(path), File::RDONLY, &:fsync)
          ensure
            File.unlink(temporary) if temporary && File.exist?(temporary)
          end

          def result(status, summary)
            path = File.join(Swarm::SWARM_ROOT, @sid, 'solve.json') if @sid
            worktree = export_worktree(path, status)
            if worktree && (worktree[:export_error] || (status == 'accepted' && worktree[:candidate] != @tree_snapshot))
              status = 'incomplete' if status == 'accepted'
              summary = "#{summary}\nPatch not verified: #{worktree[:export_error] || 'candidate changed during export'}"
              worktree[:tested_revision] = nil
            end
            @states.transform_values! { |state| %w[waiting done].include?(state) ? state : status }
            emit
            report = ["#{status.upcase}: #{summary}", "Original request: #{@request}", "Revision: #{@revision || 'none'}",
                      "Artifacts: #{@artifacts.keys.join(', ')}", "Evidence coverage: #{(@requirements.keys - uncovered).join(', ')}",
                      "Unverified: #{uncovered.join(', ')}", "Open objections: #{@objections.join('; ')}", "Record: #{path}"].join("\n")
            outcome = { ok: status == 'accepted', status: status, request: @request, swarm_id: @sid, revision: @revision, workspace: @workspace,
                        roles: @states.dup, revision_manifest: @revision_manifest,
                        worktree: worktree, patch_path: worktree&.dig(:patch_path), patch_sha256: worktree&.dig(:patch_sha256),
                        requirements: @requirements, artifacts: @artifacts, dependencies: @dependencies, objections: @objections, evidence: @evidence,
                        records: @records, uncovered: uncovered, reply: report, record_path: path }
            persist_checkpoint(path, outcome) if path
            @opts[:on_state]&.call(Marshal.load(Marshal.dump(outcome)))
            outcome
          end

          def export_worktree(path, status)
            return unless @worktree&.metadata

            @worktree.export(path ? File.dirname(path) : @worktree.metadata[:owner], @revision, status == 'accepted')
          rescue StandardError => e
            @worktree.metadata.merge(export_error: "#{e.class}: #{e.message}")
          end
        end

        # Apply a reviewed accepted patch after explicit human confirmation; never stages or commits.
        # Supported Method Parameters::
        #   PWN::AI::Agent::Solve.apply_patch(
        #     record_path: 'required - persisted solve JSON record',
        #     revision: 'required - exact tested revision shown in the review',
        #     confirmation: 'required - human-entered APPLY followed by a space and that revision'
        #   )
        public_class_method def self.apply_patch(opts = {})
          Worktree.new(nil).recover(opts[:record_path]).apply(opts[:revision], opts[:confirmation])
        rescue StandardError => e
          { ok: false, error: "#{e.class}: #{e.message}" }
        end

        # Discard only the recorded owned worktree; preserve the durable patch and evidence.
        # Supported Method Parameters::
        #   PWN::AI::Agent::Solve.cleanup_worktree(
        #     record_path: 'required - persisted solve JSON record',
        #     confirmation: 'required - human-entered DISCARD followed by a space and revision or ownership token'
        #   )
        public_class_method def self.cleanup_worktree(opts = {})
          Worktree.new(nil).recover(opts[:record_path]).cleanup(opts[:confirmation])
        rescue StandardError => e
          { ok: false, error: "#{e.class}: #{e.message}" }
        end

        public_class_method def self.authors
          'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
        end

        public_class_method def self.help
          puts "USAGE:
            # Run a revision-bound team through the public Swarm solve entry point.
            PWN::AI::Agent::Swarm.solve(request: 'required - original objective')
            # Apply a reviewed patch without staging or committing.
            #{self}.apply_patch(
              record_path: 'required - persisted solve JSON record',
              revision: 'required - exact tested revision',
              confirmation: 'required - human-entered APPLY followed by a space and revision'
            )
            # Discard only an unchanged owned temporary worktree, retaining patch and evidence.
            #{self}.cleanup_worktree(
              record_path: 'required - persisted solve JSON record',
              confirmation: 'required - human-entered DISCARD followed by a space and revision or ownership token'
            )
            # Return module authors.
            #{self}.authors
          "
        end
      end
    end
  end
end
