# frozen_string_literal: true

require 'optparse'
require 'yaml'
require 'json'
require 'pwn'

module PWN
  module AI
    # Explicit standalone entrypoint; help and parsing never load a vault.
    module CLI
      public_class_method def self.parse(opts = {})
        result = {}
        parser = OptionParser.new do |options|
          options.banner = 'Usage: pwn-ai [--analyze PATH | --replay ID | --rerun ID | --plan-only | --execute PATH | --resume RUN_ID] [--ai PROMPT]'
          options.on('--analyze PATH', 'Ingest evidence before starting the AI session') { |v| result[:analyze] = v }
          options.on('--replay ID', 'Render saved trace without executing tools') { |v| result[:replay] = v }
          options.on('--rerun ID', 'Re-execute saved tools in a fresh context (side effects possible)') { |v| result[:rerun] = v }
          options.on('--plan-only', 'Emit a YAML task DAG and write the mission ledger without running tools') { result[:plan_only] = true }
          options.on('--execute PATH', 'Run an approved YAML task DAG') { |v| result[:execute] = v }
          options.on('--resume RUN_ID', 'Resume a checkpointed DAG run, skipping completed steps') { |v| result[:resume] = v }
          options.on('--mission ID', 'Bind this plan or run to a durable mission') { |v| result[:mission] = v }
          options.on('--policy ACTION', %w[evaluate promote rollback], 'Offline policy: evaluate, promote, rollback (no AI session)') { |v| result[:policy] = v }
          options.on('--baseline PATH', 'Frozen baseline policy JSON') { |v| result[:baseline] = v }
          options.on('--candidate PATH', 'Frozen candidate policy JSON') { |v| result[:candidate] = v }
          options.on('--reports PATH', 'JSON array from --policy evaluate; replayed before promotion') { |v| result[:reports] = v }
          options.on('--receipt PATH', 'Saved successful promotion JSON for rollback') { |v| result[:receipt] = v }
          options.on('--live-policy PATH', 'Explicit existing policy target; no default') { |v| result[:live_path] = v }
          options.on('--approve-policy-change', 'Operator explicitly approves promotion or rollback') { result[:enabled] = true }
          options.on('--policy-writers-stopped', 'Operator attests ALL policy writers are stopped') { result[:quiescent] = true }
          options.on('--ai PROMPT', 'One-shot request; - reads standard input') { |v| result[:ai] = v }
          options.on('--pwn-env PATH', 'Use the specified encrypted configuration') { |v| result[:pwn_env_path] = v }
          options.on('--pwn-dec PATH', 'Use the specified decryptor') { |v| result[:pwn_dec_path] = v }
          options.on('-h', '--help', 'Show help without loading configuration') { result[:help] = true }
        end
        remaining = parser.parse!(Array(opts[:argv]).dup)
        raise OptionParser::InvalidArgument, "unexpected arguments: #{remaining.join(' ')}" unless remaining.empty?
        raise OptionParser::InvalidArgument, 'choose only one of --analyze, --replay, --rerun, --plan-only, --execute, --resume' if %i[analyze replay rerun plan_only execute resume].count { |key| result.key?(key) } > 1
        raise OptionParser::InvalidArgument, '--ai cannot accompany --replay or --rerun' if result[:ai] && (result[:replay] || result[:rerun])
        raise OptionParser::InvalidArgument, '--plan-only requires --ai' if result[:plan_only] && !result[:ai]

        validate_policy_options(parsed: result)

        result[:help_text] = parser.to_s
        result
      end

      public_class_method def self.run(opts = {})
        parsed = parse(argv: opts[:argv] || ARGV)
        output = opts[:output] || $stdout
        if parsed[:help]
          output.puts(parsed[:help_text])
          return 0
        end

        require 'pwn'
        return run_policy(parsed: parsed, output: output) if parsed[:policy]

        if parsed[:plan_only]
          prompt = parsed[:ai] == '-' ? (opts[:input] || $stdin).read : parsed[:ai]
          raise ArgumentError, '--ai requires a non-empty prompt' if prompt.to_s.strip.empty?

          dag = PWN::AI::Agent::Mission.plan!(request: prompt, id: parsed[:mission])
          output.puts(YAML.dump(JSON.parse(JSON.generate(dag))))
          return 0
        end
        if parsed[:resume] || parsed[:execute]
          PWN::Config.refresh_env(**parsed.slice(:pwn_env_path, :pwn_dec_path))
          begin
            report = if parsed[:resume]
                       PWN::AI::Agent::TaskDAG.resume(run_id: parsed[:resume], operator: true, mission_id: parsed[:mission])
                     else
                       PWN::AI::Agent::TaskDAG.execute(path: parsed[:execute], approved: true, operator: true, mission_id: parsed[:mission])
                     end
          rescue ArgumentError => e
            output.puts(e.message)
            return 1
          end
          bind_mission!(mission_id: parsed[:mission], report: report)
          output.puts(JSON.generate(report))
          return report[:ok] == false ? 1 : 0
        end
        if parsed[:replay] || parsed[:rerun]
          require 'pwn/session_trace'
          if parsed[:replay]
            PWN::SessionTrace.replay(session_id: parsed[:replay], io: output)
          else
            report = PWN::SessionTrace.rerun(session_id: parsed[:rerun], environment: :bubblewrap)
            output.puts(JSON.generate(report))
            return 1 if report[:results].any? { |result| result['exit_status'] != 0 }
          end
          return 0
        end

        PWN::Config.refresh_env(**parsed.slice(:pwn_env_path, :pwn_dec_path))
        session = PWN::Sessions.create(title: 'pwn-ai', source: 'pwn-ai-cli')
        if parsed[:analyze]
          report = PWN::AI::Context.ingest(path: parsed[:analyze], session_id: session[:id], format: 'binary')
          (opts[:error] || $stderr).puts(JSON.generate(report))
        end
        if parsed[:ai]
          prompt = parsed[:ai] == '-' ? (opts[:input] || $stdin).read : parsed[:ai]
          raise ArgumentError, '--ai requires a non-empty prompt' if prompt.strip.empty?

          output.puts(PWN::AI::Agent::Loop.run(request: prompt, session_id: session[:id], enabled_toolsets: PWN::Env.dig(:ai, :agent, :toolsets)))
        else
          PWN::Plugins::REPL.start(ai_session_id: session[:id])
        end
        0
      end

      private_class_method def self.validate_policy_options(opts = {})
        parsed = opts[:parsed]
        fields = %i[baseline candidate reports receipt live_path enabled quiescent]
        unless parsed[:policy]
          raise OptionParser::InvalidArgument, 'policy options require --policy' if fields.any? { |key| parsed.key?(key) }

          return
        end

        allowed = {
          'evaluate' => %i[baseline candidate],
          'promote' => %i[baseline candidate reports live_path enabled quiescent],
          'rollback' => %i[receipt live_path enabled quiescent]
        }.fetch(parsed[:policy])
        unexpected = parsed.keys - allowed - %i[policy help]
        raise OptionParser::InvalidArgument, "options not allowed with --policy #{parsed[:policy]}: #{unexpected.join(', ')}" unless unexpected.empty?

        missing = (allowed - %i[enabled quiescent]) - parsed.keys
        raise OptionParser::InvalidArgument, "missing policy options: #{missing.join(', ')}" unless missing.empty? || parsed[:help]
      end

      private_class_method def self.run_policy(opts = {})
        parsed = opts[:parsed]
        evaluator = PWN::AI::Agent::PolicyEvaluation
        args = parsed.slice(:baseline, :candidate, :live_path, :enabled, :quiescent)
        report = case parsed[:policy]
                 when 'evaluate'
                   [0, 1].map { |seed| evaluator.evaluate(args.merge(seed: seed)) }
                 when 'promote', 'rollback'
                   raise ArgumentError, 'requires --approve-policy-change and --policy-writers-stopped; stop all policy writers first' unless parsed[:enabled] && parsed[:quiescent]

                   key = parsed[:policy] == 'promote' ? :reports : :receipt
                   args[key] = JSON.parse(File.read(parsed.fetch(key)), symbolize_names: true)
                   parsed[:policy] == 'promote' ? evaluator.promote(args) : evaluator.rollback(args)
                 end
        opts[:output].puts(JSON.generate(report))
        report.is_a?(Hash) && (report[:promoted] == false || report[:rolled_back] == false) ? 1 : 0
      rescue StandardError => e
        opts[:output].puts(JSON.generate(error: e.message))
        1
      end

      private_class_method def self.bind_mission!(opts = {})
        report = opts[:report] || {}
        return report unless report[:run_id]

        mid = opts[:mission_id].to_s
        mid = PWN::AI::Agent::Mission.active_id if mid.empty?
        return report if mid.to_s.empty?

        PWN::AI::Agent::Mission.begin!(id: mid, request: 'approved dag', unattended: true) unless PWN::AI::Agent::Mission.current(id: mid)
        root = report[:dir] ? File.dirname(report[:dir].to_s) : nil
        PWN::AI::Agent::Mission.bind_run!(id: mid, run_id: report[:run_id], root: root)
        PWN::AI::Agent::OpenGoal.begin!(request: PWN::AI::Agent::Mission.current(id: mid)[:request], mission_id: mid)
        report
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts parse(argv: ['--help'])[:help_text]
        puts "
          # Parse CLI arguments without loading a vault.
          #{self}.parse(argv: 'optional - argument array; defaults to []')
          # Execute the requested CLI action; replay/rerun never load credentials.
          #{self}.run(
            argv: 'optional - argument array; defaults to ARGV',
            input: 'optional - prompt input IO; defaults to stdin',
            output: 'optional - result IO; defaults to stdout',
            error: 'optional - ingestion diagnostics IO; defaults to stderr'
          )
          # Display author information.
          #{self}.authors
        "
      end
    end
  end
end
