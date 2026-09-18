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
          options.on('--plan-only', 'Emit a YAML task DAG with zero side effects') { result[:plan_only] = true }
          options.on('--execute PATH', 'Run an approved YAML task DAG') { |v| result[:execute] = v }
          options.on('--resume RUN_ID', 'Resume a checkpointed DAG run, skipping completed steps') { |v| result[:resume] = v }
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
        if parsed[:plan_only]
          prompt = parsed[:ai] == '-' ? (opts[:input] || $stdin).read : parsed[:ai]
          raise ArgumentError, '--ai requires a non-empty prompt' if prompt.to_s.strip.empty?

          dag = PWN::AI::Agent::TaskDAG.plan(request: prompt)
          output.puts(YAML.dump(JSON.parse(JSON.generate(dag))))
          return 0
        end
        if parsed[:resume] || parsed[:execute]
          PWN::Config.refresh_env(**parsed.slice(:pwn_env_path, :pwn_dec_path))
          report = if parsed[:resume]
                     PWN::AI::Agent::TaskDAG.resume(run_id: parsed[:resume])
                   else
                     PWN::AI::Agent::TaskDAG.execute(path: parsed[:execute])
                   end
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
