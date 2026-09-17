# frozen_string_literal: true

require 'stringio'
require 'timeout'
require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/tool_guard'

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
                 'PWN::SAST, PWN::Reports, PWN::AI::Agent::*, etc.). Locals ' \
                 'persist across calls in this process — open a browser once ' \
                 '(browser_obj = TransparentBrowser.open(...); browser = ' \
                 'browser_obj[:browser]), then navigate via that same ' \
                 'browser. Do not open a second browser. Close once with ' \
                 'Close once with TransparentBrowser.close(browser_obj: browser_obj). ' \
                 'Pass timeout as a conservative integer seconds estimate given HOST ' \
                 'LOAD (loadavg, ncpu, mem). Omit for a host-derived default. ' \
                 'Explicit timeout is honored up to 10800s (3 hours) for any payload. On ' \
                 'timeout, keep the same payload and retry with timeout += 180 ' \
                 'until the 3-hour budget is gone; then rewrite (max 10 mutations/task). ' \
                 'Returns captured stdout plus the inspected value of the last expression.',
    parameters: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Ruby source to evaluate.' },
        encoding: { type: 'string', description: 'Set to base64 when data holds the Ruby source.' },
        data: { type: 'string', description: 'Base64 Ruby source when encoding is base64.' },
        placeholder_ok: { type: 'boolean', description: 'Explicitly permit placeholder tokens; Ruby must still parse and execute. Literal strings/heredocs never require this.' },
        timeout: {
          type: 'integer',
          description: 'Conservative seconds this eval should take given HOST LOAD. Omit for a host-derived default. Explicit values honored 1..10800 (3 hours). On timeout keep the same payload and timeout += 180; rewrite only after the 3-hour budget (max 10 mutations/task).'
        }
      },
      required: %w[code]
    }
  },
  max_chars: 32_000,
  handler: lambda { |args|
    args = PWN::AI::Agent::ToolGuard.unwrap_payload(args: args, key: :code)
    args = PWN::AI::Agent::ToolGuard.coerce_args(args: args, required: %w[code])
    if args[:__schema_error]
      return {
        stdout: '',
        error: 'invalid_payload',
        hint: args[:__schema_hint]
      }
    end

    code = args[:code].to_s
    return PWN::AI::Agent::ToolGuard.invalid_payload(hint: 'code must be a nonempty string') unless args[:code].is_a?(String) && !code.empty?

    placeholder = PWN::AI::Agent::ToolGuard.placeholder_match(text: code, language: :ruby, placeholder_ok: args[:placeholder_ok])
    if placeholder
      return PWN::AI::Agent::ToolGuard.invalid_payload(
        **placeholder,
        text: code,
        hint: 'Ruby source contains an elided code stub outside literal data.',
        remedy: 'Replace the matched stub with complete Ruby code. Strings and heredocs may contain ellipses without placeholder_ok. Explicit placeholder_ok: true skips this guard but not Ruby parsing; base64 data is decoded before validation.'
      )
    end

    timeout = PWN::AI::Agent::ToolGuard.deadline_s(timeout: args[:timeout], kind: :eval, payload: code)
    PWN::AI::Agent::ToolGuard.protect_http!
    sandboxed = PWN::Plugins::AISandbox.wrap_ruby(code: code, timeout: timeout)
    return sandboxed unless sandboxed.nil?

    blocked = PWN::Plugins::MethodCatalog.guard_eval(code: code)
    return blocked if blocked

    old_stdout = $stdout
    buf = StringIO.new
    $stdout = buf
    begin
      # rubocop:disable Security/Eval
      # INTENTIONAL: this IS the pwn-ai → PWN bridge
      # As YTCracker says, "It ain't a bug, it's a featcha."
      # https://www.youtube.com/watch?v=2nALqqSqdDw
      #
      # File label '(pwn_eval)' (not __FILE__) so SyntaxError / NameError
      # messages cite the *payload* line, not ruby_eval.rb glued to source.
      # Rescue ScriptError (SyntaxError, LoadError, NotImplementedError) as
      # well as StandardError — Dispatch only catches StandardError, so an
      # unrescued SyntaxError previously escaped the tool loop. Returning a
      # structured error lets the model self-heal (fix code and retry).
      # Evaluate in TOPLEVEL_BINDING so locals (browser_obj, browser)
      # persist across pwn_eval calls. Wrapping in proc { } made each
      # call a fresh scope — the next snippet hit NameError and opened
      # another Chrome.
      val = Timeout.timeout(timeout) do
        eval(
          code,
          TOPLEVEL_BINDING,
          '(pwn_eval)',
          1
        )
      end
      # rubocop:enable Security/Eval
      { stdout: buf.string, value: val.inspect, timeout: timeout }
    rescue Timeout::Error
      PWN::AI::Agent::ToolGuard.timeout_result(
        tool: 'pwn_eval',
        payload: code,
        timeout: timeout,
        stdout: buf.string
      )
    rescue ScriptError, StandardError => e
      {
        stdout: buf.string,
        error: "#{e.class}: #{e.message}",
        backtrace: Array(e.backtrace).first(5),
        hint: (
          if e.is_a?(SyntaxError) && e.message.match?(/formal argument cannot be a constant/)
            'Block parameters must be local variables (lowercase), e.g. |r| not |R|. Also close every do/end.'
          elsif e.is_a?(SyntaxError)
            'Payload failed to parse. Check matching do/end, braces, and that no line-number prefix was glued onto the code.'
          elsif e.is_a?(NameError) && e.message.match?(/undefined local variable or method '(browser|browser_obj)'/)
            'Reuse the existing browser_obj / browser from the prior pwn_eval. Do not call TransparentBrowser.open again.'
          end
        )
      }
    ensure
      $stdout = old_stdout
      PWN::AI::Agent::ToolGuard.protect_http!
    end
  }
)
