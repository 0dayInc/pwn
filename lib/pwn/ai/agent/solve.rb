# frozen_string_literal: true

require 'digest'
require 'json'
require 'tmpdir'
require 'shellwords'
require 'stringio'

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

            @requirements = { 'R0' => @request }
            @states = ROLES.to_h { |role| [role, 'waiting'] }
            @records = []
            @evidence = []
            @objections = []
            @artifacts = {}
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
              raise ArgumentError, 'candidate must declare at least one existing artifact' if @artifacts.empty?

              @revision = digest(run: @sid, round: @round, request: @request, requirements: @requirements, artifacts: @artifacts, guidance: @guidance)
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

            configured = Swarm.personas(swarm_id: @opts[:swarm_id])
            @sid = Swarm.create(topic: @request)[:swarm_id]
            @personas = ROLES.to_h do |role|
              persona = configured[:"solve_#{role}"] || {}
              engine = (persona[:engine] || Thread.current[:pwn_swarm_engine] || PWN::Env.dig(:ai, :active)).to_s
              raise ArgumentError, "unsupported solve provider: #{engine}" unless Loop::ENGINE_MODS.key?(engine.to_sym)

              provider = PWN::Env.dig(:ai, engine.to_sym) || {}
              credentials = [provider[:key], provider.dig(:oauth, :bearer_token), provider.dig(:oauth, :refresh_token)]
              raise ArgumentError, "solve_#{role}: configure #{engine} credentials first; solve never starts a login" if engine != 'ollama' && credentials.none? { |value| !value.to_s.strip.empty? && !value.to_s.match?(/\A(?:optional|required)\s*-/) }

              [role, persona.merge(engine: engine, toolsets: role == 'protagonist' ? %w[terminal pwn] : [],
                                   role: "#{persona[:role]}\nBuilt-in solve #{role}. Follow the structured handoff; original request is the sole objective.")]
            end
          end

          def turn(role, phase)
            boundary
            @control.begin_turn
            @states[role] = phase
            emit
            payload = { phase: phase, role: role, original_request: @request, requirements: @requirements,
                        workspace: @workspace, round: @round, revision: @revision, guidance: guidance,
                        assessment: @assessment, candidate: @candidate, artifacts: artifact_text,
                        objections: @objections, evidence: @evidence, repair: @repair }
            prior = Thread.current[:pwn_solve_tools]
            Thread.current[:pwn_solve_tools] = role == 'protagonist' ? %w[shell pwn_eval] : []
            reply = Swarm.ask(name: "solve_#{role}", persona: @personas.fetch(role), request: @request,
                              swarm_id: @sid, handoff: "#{contract(phase)}\nSOLVE HANDOFF\n#{JSON.generate(payload)}",
                              steering: @control, usage_observer: @opts[:usage_observer], on_tool: @opts[:on_tool])
            row = JSON.parse(reply.fetch(:reply), symbolize_names: true)
            raise ArgumentError, "#{role} handoff must be an object" unless row.is_a?(Hash)
            raise ArgumentError, "#{role} returned a stale revision" if %w[critique verify integrate].include?(phase) && row[:revision] != @revision

            @records << { role: role, phase: phase, revision: @revision, data: row }
            @states[role] = 'done'
            emit
            row
          ensure
            Thread.current[:pwn_solve_tools] = prior
          end

          def contract(phase)
            shapes = {
              'assess' => '{"requirements":["every atomic requirement in original request"],"risks":["independent risk assessment"]}',
              'build' => '{"artifacts":["relative/file"],"summary":"what changed"}',
              'critique' => '{"revision":"exact revision","objections":["unresolved correctness issue; empty only if none"]}',
              'verify' => '{"revision":"exact revision","checks":[{"requirements":["R0","R1"],"command":"real test command","stdout":"exact expected nonempty stdout"}]}',
              'integrate' => '{"revision":"exact revision","decision":"accept or repair","repair":"targeted repair for protagonist","summary":"integrated result"}'
            }
            "Return ONLY a JSON object matching #{shapes.fetch(phase)}. Do not replace the objective. " \
              'Protagonist alone may change files. Review roles have no tool access. Verification commands run by the coordinator ' \
              'in a disposable copy of declared artifacts, not the working tree; declare all test dependencies as artifacts. ' \
              'Checks must test the named requirements, not print a success claim. R0 covers the ENTIRE original request. ' \
              'Never accept missing evidence, unresolved objections, or omitted requirements. Integration requests repairs; it does not write.'
          end

          def observe(paths)
            Array(paths).to_h do |relative|
              raise ArgumentError, 'artifact path must be relative' unless relative.is_a?(String) && !relative.start_with?('/')

              path = File.realpath(File.join(@workspace, relative))
              raise ArgumentError, "artifact outside workspace: #{relative}" unless path.start_with?("#{@workspace}/")
              raise ArgumentError, "artifact must be a regular file: #{relative}" unless File.file?(path)
              raise ArgumentError, "artifact symlink is not supported: #{relative}" unless path == File.expand_path(relative, @workspace)

              [relative, Digest::SHA256.file(path).hexdigest]
            end
          end

          def artifact_text
            @artifacts.to_h do |path, sha|
              bytes = File.binread(File.join(@workspace, path))
              raise ArgumentError, "artifact too large for review: #{path} (limit 128 KiB)" if bytes.bytesize > 131_072

              [path, { sha256: sha, text: bytes.encode('UTF-8', invalid: :replace, undef: :replace) }]
            end
          end

          def execute_checks(checks)
            raise ArgumentError, 'verifier must supply 1..32 checks' unless checks.is_a?(Array) && checks.length.between?(1, 32)

            @states['verifier'] = 'checking'
            emit
            observations = checks.map do |check|
              boundary
              ids = Array(check[:requirements]).map(&:to_s)
              raise ArgumentError, 'check must name known requirements' if ids.empty? || (ids - @requirements.keys).any?
              raise ArgumentError, 'check needs a command and nonempty expected stdout' if check[:command].to_s.strip.empty? || check[:stdout].to_s.empty?

              execute_check(check, ids)
            end
            @states['verifier'] = 'done'
            @records << { role: 'verifier', phase: 'verification', revision: @revision, evidence: observations }
            emit
            observations
          end

          def execute_check(check, ids)
            Dir.mktmpdir('pwn-solve-verify') do |copy|
              @artifacts.each_key do |path|
                destination = File.expand_path(path, copy)
                raise ArgumentError, 'invalid artifact copy path' unless destination.start_with?("#{copy}/")

                FileUtils.mkdir_p(File.dirname(destination))
                FileUtils.cp(File.join(@workspace, path), destination)
              end
              copied = @artifacts.to_h { |path, _sha| [path, Digest::SHA256.file(File.join(copy, path)).hexdigest] }
              raise 'candidate changed while copying verification inputs' unless copied == @artifacts

              prior = Thread.current[:pwn_solve_tools]
              Thread.current[:pwn_solve_tools] = ['shell']
              command = "cd #{Shellwords.escape(copy)} && (#{check[:command]})"
              raw = Dispatch.call(tool_call: { id: SecureRandom.hex(8), function: { name: 'shell', arguments: JSON.generate(command: command, timeout: 60) } })
              @opts[:on_tool]&.call('shell', { command: command }, raw)
              response = JSON.parse(raw, symbolize_names: true)
              observed = response[:result].is_a?(Hash) ? response[:result] : {}
              unchanged = @artifacts.all? { |path, sha| File.file?(File.join(copy, path)) && Digest::SHA256.file(File.join(copy, path)).hexdigest == sha }
              { requirements: ids, revision: @revision, command: check[:command], stdout: observed[:stdout],
                stderr: observed[:stderr], exitstatus: observed[:exit], raw: raw,
                passed: response[:success] == true && observed[:exit].is_a?(Integer) && observed[:exit].zero? && observed[:stdout] == check[:stdout] && unchanged && current? }
            ensure
              Thread.current[:pwn_solve_tools] = prior
            end
          end

          def current?
            guidance == @guidance && observe(@artifacts.keys) == @artifacts
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
            @opts[:on_state]&.call({ roles: @states.dup, request: @request, requirements: @requirements.dup,
                                     artifacts: @artifacts.dup, objections: @objections.dup, round: @round, revision: @revision,
                                     routing: (@personas || {}).transform_values { |row| row.slice(:engine, :model) } })
          end

          def result(status, summary)
            @states.transform_values! { |state| %w[waiting done].include?(state) ? state : status }
            emit
            path = File.join(Swarm::SWARM_ROOT, @sid, 'solve.json') if @sid
            report = ["#{status.upcase}: #{summary}", "Original request: #{@request}", "Revision: #{@revision || 'none'}",
                      "Artifacts: #{@artifacts.keys.join(', ')}", "Evidence coverage: #{(@requirements.keys - uncovered).join(', ')}",
                      "Unverified: #{uncovered.join(', ')}", "Open objections: #{@objections.join('; ')}", "Record: #{path}"].join("\n")
            outcome = { ok: status == 'accepted', status: status, request: @request, swarm_id: @sid, revision: @revision,
                        requirements: @requirements, artifacts: @artifacts, objections: @objections, evidence: @evidence,
                        records: @records, uncovered: uncovered, reply: report, record_path: path }
            File.write(path, JSON.pretty_generate(outcome), mode: 'w', perm: 0o600) if path
            outcome
          end
        end

        public_class_method def self.authors
          'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
        end

        public_class_method def self.help
          puts "USAGE:
            # Run a revision-bound team through the public Swarm solve entry point.
            PWN::AI::Agent::Swarm.solve(request: 'required - original objective')
            # Return module authors.
            #{self}.authors
          "
        end
      end
    end
  end
end
