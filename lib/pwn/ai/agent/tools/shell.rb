# frozen_string_literal: true

require 'open3'
require 'timeout'
require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/tool_guard'

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
                 'ls, git, file inspection, anything not in the PWN:: namespace. ' \
                 'Pass timeout as a conservative integer seconds estimate given ' \
                 'HOST LOAD (loadavg, ncpu, mem). Omit for a host-derived default. ' \
                 'Explicit timeout is honored up to 10800s (3 hours) for any payload. On ' \
                 'timeout, keep the same payload and retry with timeout += 180 ' \
                 'until the 3-hour budget is gone; then rewrite (max 10 mutations/task).',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'The exact shell command to run.' },
        timeout: {
          type: 'integer',
          description: 'Conservative seconds this command should take given HOST LOAD. Omit for a host-derived default. Explicit values honored 1..10800 (3 hours). On timeout keep the same payload and timeout += 180; rewrite only after the 3-hour budget (max 10 mutations/task).'
        }
      },
      required: %w[command]
    }
  },
  max_chars: 24_000,
  handler: lambda { |args|
    # Sanitize model/tool JSON junk that becomes syntax error: \ in sh:
    # 1) UTF-8 replace invalid bytes
    # 2) join line-continuation backslash+newline (mid-cmd) into space
    # 3) strip a bare trailing backslash (+ following ws)
    # Prefer pwn_eval / cat <<'EOF' over nested ruby -e with JSON \ layers.
    # Fix for mistakes 30e55df3a6d6 / 853b3ca24b9e (REGRESSED shell syntax \).
    args = PWN::AI::Agent::ToolGuard.coerce_args(args: args, required: %w[command])
    return PWN::AI::Agent::ToolGuard.invalid_payload(hint: args[:__schema_hint]) if args[:__schema_error]

    cmd = args[:command].to_s
                        .encode('UTF-8', invalid: :replace, undef: :replace, replace: '')
                        .gsub(/\\\r?\n/, ' ')
                        .gsub(/\\+\s*\z/, '')
                        .strip
    timeout = PWN::AI::Agent::ToolGuard.deadline_s(timeout: args[:timeout], kind: :shell, payload: cmd)
    if cmd.empty? || PWN::AI::Agent::ToolGuard.placeholder?(text: cmd)
      return PWN::AI::Agent::ToolGuard.invalid_payload(
        hint: 'command is required (string). Do not send ..., {...}, {…}, or empty. ' \
              'Example: shell(command="uname -r").'
      )
    end

    if PWN::AI::Agent::ToolGuard.bashism?(text: cmd) && !PWN::AI::Agent::ToolGuard.shell_bash?
      return PWN::AI::Agent::ToolGuard.invalid_payload(
        hint: 'Command uses bash-only syntax (PIPESTATUS, $RANDOM, [[ ]], process substitution, ' \
              'source, &>). This handler runs /bin/sh (dash) unless ' \
              'PWN::Env[:ai][:agent][:shell_bash]=true. Rewrite as POSIX or opt in to bash.'
      )
    end

    stdout = +''
    stderr = +''
    exitstatus = nil
    timed_out = false

    # pgroup: true => child is session/process-group leader; kill(-pid)
    # reaps the whole tree (shell + grandchildren) on timeout.
    spawn_cmd = if PWN::AI::Agent::ToolGuard.shell_bash?
                  ['bash', '-lc', cmd]
                else
                  cmd
                end
    Open3.popen3(*Array(spawn_cmd), pgroup: true) do |stdin, out_io, err_io, wait_thr|
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

      # On the timeout path, force-close pipes so readers unblock.
      # On the success path, join readers FIRST so a fast child cannot
      # lose stdout to a close-before-read race (empty stdout, exit 0).
      if timed_out
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
      end

      # Join readers; swallow IOError if pipes were closed mid-read (timeout).
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

      # Close after join on success so fds do not leak.
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

      unless timed_out
        status = wait_thr.value
        exitstatus = status&.exitstatus
      end
    end

    if timed_out
      return PWN::AI::Agent::ToolGuard.timeout_result(
        tool: 'shell',
        payload: cmd,
        stdout: stdout,
        stderr: stderr,
        timeout: timeout
      )
    end

    { stdout: stdout, stderr: stderr, exit: exitstatus, shell: PWN::AI::Agent::ToolGuard.shell_name }
  }
)
