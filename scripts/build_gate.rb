# frozen_string_literal: true

# Run only the validation gate, never installation. Keep one bounded, private
# log even when a terminal disconnects or the child exits without a summary.
require 'fileutils'
require 'open3'

abort 'Usage: ruby scripts/build_gate.rb command [args...]' if ARGV.empty?

limit = 1_048_576
path = File.join(Dir.home, '.pwn', 'logs', 'build-gate.log')
FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
File.open(path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |log|
  abort "Build gate already running; log: #{path}" unless log.flock(File::LOCK_EX | File::LOCK_NB)

  log.chmod(0o600)
  log.truncate(0)
  log.sync = true
  $stdout.sync = true
  append = lambda do |bytes|
    if log.size + bytes.bytesize > limit
      log.rewind
      retained = (log.read + bytes).byteslice(-limit, limit)
      log.rewind
      log.truncate(0)
      log.write(retained)
    else
      log.seek(0, IO::SEEK_END)
      log.write(bytes)
    end
  end
  emit = lambda do |bytes|
    append.call(bytes)
    begin
      $stdout.write(bytes)
    rescue Errno::EPIPE, IOError
      # Continue draining the child into the durable log after stream loss.
      nil
    end
  end
  emit.call("Build gate log: #{path} (last #{limit} bytes; replaced on next run)\n")
  emit.call("Gate launcher: uid=#{Process.uid} ruby=#{RUBY_VERSION} cwd=#{Dir.pwd} HOME=#{Dir.home}\n")
  status = nil
  Open3.popen2e(*ARGV) do |input, output, waiter|
    input.close
    loop { emit.call(output.readpartial(16_384)) }
  rescue EOFError
    status = waiter.value
  end
  result = status.signaled? ? "signal=#{Signal.signame(status.termsig)}" : "exit=#{status.exitstatus}"
  emit.call("\nBuild gate #{result}\n")
  unless status.success?
    log.rewind
    tail = log.read.byteslice(-16_384, 16_384) || log.tap(&:rewind).read
    warn "\nBuild gate failed (#{result}). Build gate log: #{path}\n#{tail}"
  end
  exit(status.exitstatus || (128 + status.termsig))
end
