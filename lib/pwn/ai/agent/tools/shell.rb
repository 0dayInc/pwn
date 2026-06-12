# frozen_string_literal: true

require 'open3'
require 'timeout'
require 'pwn/ai/agent/registry'

# Run a shell command on the pwn host. Lifted from the bash branch of the
# legacy :pwn_ai_hook (repl.rb).
PWN::AI::Agent::Registry.register(
  name: 'shell',
  toolset: 'terminal',
  schema: {
    name: 'shell',
    description: 'Execute a shell command on the local pwn host and return ' \
                 'stdout/stderr/exit code. Use for OS-level work: nmap, curl, ' \
                 'ls, git, file inspection, anything not in the PWN:: namespace.',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'The exact shell command to run.' },
        timeout: { type: 'integer', description: 'Seconds before the command is killed.', default: 120 }
      },
      required: %w[command]
    }
  },
  max_chars: 24_000,
  handler: lambda { |args|
    cmd     = args[:command].to_s
    timeout = (args[:timeout] || 120).to_i
    raise ArgumentError, 'command is required' if cmd.strip.empty?

    stdout = stderr = ''
    status = nil
    begin
      Timeout.timeout(timeout) do
        stdout, stderr, status = Open3.capture3(cmd)
      end
    rescue Timeout::Error
      return { stdout: stdout, stderr: stderr, exit: nil, error: "timeout after #{timeout}s" }
    end

    { stdout: stdout, stderr: stderr, exit: status&.exitstatus }
  }
)
