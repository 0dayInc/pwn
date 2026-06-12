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
      # rubocop:disable Security/Eval -- intentional: this IS the pwn-ai → PWN bridge
      val = eval(code, TOPLEVEL_BINDING, '(pwn_eval)')
      # rubocop:enable Security/Eval
      { stdout: buf.string, value: val.inspect }
    ensure
      $stdout = old_stdout
    end
  }
)
