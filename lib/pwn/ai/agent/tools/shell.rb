# frozen_string_literal: true

require 'open3'
require 'timeout'
require 'pwn/ai/agent/registry'

# Run a shell command on the pwn host. Lifted from the bash branch of the
# legacy :pwn_ai_hook (repl.rb).
#
# Timeout path must NOT leave Open3's pipe-reader threads racing a closed
# pipe — that surfaces as noisy:
#   #<Thread:0x... open3.rb:664 run> terminated with exception
#   (report_on_exception is true): IOError stream closed in another thread
# Fix: own the popen3 lifecycle, process-group kill on timeout, and silence
# report_on_exception on the reader threads before closing pipes.
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

    stdout = +''
    stderr = +''
    exitstatus = nil
    timed_out = false

    # pgroup: true => child is session/process-group leader; kill(-pid)
    # reaps the whole tree (shell + grandchildren) on timeout.
    Open3.popen3(cmd, pgroup: true) do |stdin, out_io, err_io, wait_thr|
      stdin.close
      pid = wait_thr.pid

      out_reader = Thread.new { out_io.read.to_s }
      err_reader = Thread.new { err_io.read.to_s }
      # Prevent Ruby from dumping IOError to $stderr when we close pipes
      # out from under these readers on the timeout path.
      out_reader.report_on_exception = false
      err_reader.report_on_exception = false

      begin
        Timeout.timeout(timeout) do
          # Wait for the child; readers drain pipes concurrently.
          wait_thr.value
        end
      rescue Timeout::Error
        timed_out = true
        begin
          Process.kill('TERM', -pid)
        rescue Errno::ESRCH, Errno::EPERM
          nil
        end
        # Brief grace, then hard kill the process group.
        sleep 0.2
        begin
          Process.kill('KILL', -pid)
        rescue Errno::ESRCH, Errno::EPERM
          nil
        end
        begin
          wait_thr.value
        rescue StandardError
          nil
        end
      end

      # Ensure pipes are closed so readers unblock even if the child
      # ignored signals or left descendants holding fds.
      begin
        out_io.close unless out_io.closed?
      rescue StandardError
        nil
      end
      begin
        err_io.close unless err_io.closed?
      rescue StandardError
        nil
      end

      # Join readers; swallow the IOError that arrives when the pipe was
      # closed mid-read (timeout path). report_on_exception is already off.
      begin
        stdout = out_reader.value.to_s
      rescue StandardError
        stdout = +''
      end
      begin
        stderr = err_reader.value.to_s
      rescue StandardError
        stderr = +''
      end

      unless timed_out
        status = wait_thr.value
        exitstatus = status&.exitstatus
      end
    end

    return { stdout: stdout, stderr: stderr, exit: nil, error: "timeout after #{timeout}s" } if timed_out

    { stdout: stdout, stderr: stderr, exit: exitstatus }
  }
)
