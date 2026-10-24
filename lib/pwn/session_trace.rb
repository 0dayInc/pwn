# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'tmpdir'
require 'open3'
require 'timeout'
require_relative 'sessions'
require_relative 'redaction'

module PWN
  # Recorded, redacted evidence, not a promise of deterministic LLM output.
  module SessionTrace
    EVENTS = %w[request response tool_call tool_result].freeze

    public_class_method def self.append(opts = {})
      event = opts[:event].to_s
      raise ArgumentError, 'Invalid trace event' unless EVENTS.include?(event)

      path = trace_path(session_id: opts[:session_id])
      FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
      row = PWN::Redaction.redact(value: {
                                    version: 1, event: event, data: opts[:data], model: opts[:model], params: opts[:params] || {}
                                  })
      row[:seed] = opts[:seed] if opts.key?(:seed) && !opts[:seed].nil?
      File.open(path, File::RDWR | File::CREAT | File::APPEND | File::NOFOLLOW, 0o600) do |file|
        file.flock(File::LOCK_EX)
        file.rewind
        last = nil
        file.each_line { |line| last = JSON.parse(line) }
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        row[:monotonic_ns] = [now, last ? last.fetch('monotonic_ns') + 1 : 0].max
        row[:sequence] = last ? last.fetch('sequence') + 1 : 1
        file.puts(JSON.generate(PWN::AI::Agent::Result.utf8_value(value: row)))
        file.flush
      end
      row
    end

    # Read-only rendering; never dispatches a recorded call.
    public_class_method def self.replay(opts = {})
      rows = read(session_id: opts[:session_id])
      io = opts[:io] || $stdout
      rows.each { |row| io.puts(JSON.generate(row)) }
      rows
    end

    public_class_method def self.read(opts = {})
      path = trace_path(session_id: opts[:session_id])
      File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
        file.flock(File::LOCK_SH)
        file.each_line.map { |line| PWN::Redaction.redact(value: JSON.parse(line)) }
      end
    end

    # Explicit opt-in; no host dispatch, home mount, network or inherited env.
    # Ruby is the isolated system Ruby, not the original provider/runtime.
    public_class_method def self.rerun(opts = {})
      raise ArgumentError, 'Select an isolated environment: bubblewrap' unless opts[:environment].to_s == 'bubblewrap'

      calls = read(session_id: opts[:session_id]).select { |row| row['event'] == 'tool_call' }.map { |row| row['data'] }
      calls.each do |call|
        raise ArgumentError, 'Unsupported rerun tool' unless call.is_a?(Hash) && %w[shell pwn_eval].include?(call['name'])
        raise ArgumentError, 'Redacted calls require fresh fixture inputs' if JSON.generate(call).include?('[REDACTED:')
        raise ArgumentError, 'Tool arguments required' unless call['arguments'].is_a?(Hash)
      end
      runner = <<~RUBY
        require 'json'
        require 'open3'
        calls = JSON.parse(STDIN.read)
        results = calls.map do |call|
          args = call.fetch('arguments')
          argv = if call['name'] == 'shell'
                   ['/bin/sh', '-c', args.fetch('command')]
                 else
                   ['/usr/bin/ruby', '-e', "result = eval(ARGV.fetch(0)); puts(result) unless result.nil?", args.fetch('code')]
                 end
          out, err, status = Open3.capture3(*argv)
          { id: call['id'], name: call['name'], stdout: out, stderr: err, exit_status: status.exitstatus }
        end
        STDOUT.write(JSON.generate(results))
      RUBY
      argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
              '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/work',
              '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
              '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
              '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
              '--dir', '/work', '--chdir', '/work', '/usr/bin/ruby', '-e', runner]
      out = +''
      status = nil
      timeout = Float(opts.fetch(:timeout, 30))
      raise ArgumentError, 'Invalid rerun deadline' unless timeout.positive? && timeout <= 300

      Open3.popen3(*argv, unsetenv_others: true, pgroup: true) do |stdin, stdout, stderr, wait|
        readers = [Thread.new { stdout.read }, Thread.new { stderr.read }]
        begin
          Timeout.timeout(timeout) do
            stdin.write(JSON.generate(calls))
            stdin.close
            out = readers.first.value
            readers.last.value
            status = wait.value
          end
        rescue Timeout::Error
          Process.kill('KILL', -wait.pid)
          raise 'Isolated rerun deadline exceeded; no host fallback'
        ensure
          readers.each(&:join)
        end
      end
      raise 'Isolated rerun failed; no host fallback' unless status.success?

      { run_id: SecureRandom.hex(12), environment: 'bubblewrap', results: PWN::Redaction.redact(value: JSON.parse(out)) }
    rescue Errno::ENOENT
      raise 'Isolated environment unavailable; no host fallback'
    end

    private_class_method def self.trace_path(opts = {})
      id = opts[:session_id].to_s
      raise ArgumentError, 'Invalid session id' unless id.match?(/\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\z/)

      dir = File.dirname(PWN::Sessions.support_path(kind: :trace, session_id: id))
      raise ArgumentError, 'Symlinked trace directory' if File.symlink?(dir)

      File.join(dir, 'trace.jsonl')
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Persist one redacted event with monotonic ordering.
        #{self}.append(
          session_id: 'required - safe session identifier',
          event: 'required - request, response, tool_call or tool_result',
          data: 'optional - event payload with call IDs',
          model: 'optional - provider model identifier',
          params: 'optional - model invocation parameters',
          seed: 'optional - provider-supported seed'
        )
        # Render recorded evidence without executing tools.
        #{self}.replay(
          session_id: 'required - recorded session identifier',
          io: 'optional - output IO, defaults to stdout'
        )
        # Read recorded evidence with defensive redaction.
        #{self}.read(
          session_id: 'required - recorded session identifier'
        )
        # Rerun shell/Ruby calls in a fresh no-network Bubblewrap namespace.
        #{self}.rerun(
          session_id: 'required - recorded session identifier',
          environment: 'required - explicit bubblewrap opt-in; no host fallback',
          timeout: 'optional - positive deadline seconds, default 30, maximum 300'
        )
        # Print the author information.
        #{self}.authors
      "
    end
  end
end
