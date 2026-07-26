# frozen_string_literal: true

require 'stringio'
require 'pwn/ai/agent/registry'

# Evaluate Ruby with the full PWN:: namespace loaded. Lifted from the ruby
# branch of the legacy :pwn_ai_hook (repl.rb). This is the agent's bridge
# to every PWN::Plugins / PWN::AI::Agent / PWN::SAST module — the model
# emits Ruby and pwn runs it in TOPLEVEL_BINDING.
PWN::AI::Agent::Registry.register(
  name: 'pwn_eval',
  toolset: 'pwn',
  schema: {
    name: 'pwn_eval',
    description: 'Evaluate Ruby in the live pwn REPL process with the full ' \
                 'PWN:: namespace available (PWN::Plugins::NmapIt, ' \
                 'PWN::Plugins::TransparentBrowser, PWN::Plugins::BurpSuite, ' \
                 'PWN::SAST, PWN::Reports, PWN::AI::Agent::*, etc.). Returns ' \
                 'captured stdout plus the inspected value of the last expression.',
    parameters: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Ruby source to evaluate.' }
      },
      required: %w[code]
    }
  },
  max_chars: 32_000,
  handler: lambda { |args|
    code = args[:code].to_s
    raise ArgumentError, 'code is required' if code.strip.empty?

    old_stdout = $stdout
    buf = StringIO.new
    $stdout = buf
    begin
      # rubocop:disable Security/Eval
      # rubocop:disable Style/DocumentDynamicEvalDefinition
      # INTENTIONAL: this IS the pwn-ai → PWN bridge
      # As YTCracker says, "It ain't a bug, it's a featcha."
      # https://www.youtube.com/watch?v=2nALqqSqdDw
      #
      # File label '(pwn_eval)' (not __FILE__) so SyntaxError / NameError
      # messages cite the *payload* line, not ruby_eval.rb:49 glued to source
      # (e.g. "ruby_eval:49results = probes.map do |R|").
      # Rescue ScriptError (SyntaxError, LoadError, NotImplementedError) as
      # well as StandardError — Dispatch only catches StandardError, so an
      # unrescued SyntaxError previously escaped the tool loop. Returning a
      # structured error lets the model self-heal (fix code and retry).
      proc = eval(
        "proc { #{code}\n}",
        TOPLEVEL_BINDING,
        '(pwn_eval)',
        1
      )
      val = proc.call
      # rubocop:enable Security/Eval
      # rubocop:enable Style/DocumentDynamicEvalDefinition
      { stdout: buf.string, value: val.inspect }
    rescue ScriptError, StandardError => e
      {
        stdout: buf.string,
        error: "#{e.class}: #{e.message}",
        backtrace: Array(e.backtrace).first(5),
        # Hint common payload footguns the model keeps emitting
        hint: (
          if e.is_a?(SyntaxError) && e.message.match?(/formal argument cannot be a constant/)
            'Block parameters must be local variables (lowercase), e.g. |r| not |R|. Also close every do/end.'
          elsif e.is_a?(SyntaxError)
            'Payload failed to parse. Check matching do/end, braces, and that no line-number prefix was glued onto the code.'
          end
        )
      }
    ensure
      $stdout = old_stdout
    end
  }
)
