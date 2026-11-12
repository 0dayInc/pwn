# frozen_string_literal: true

# Shared by the real controller-death example and its diagnostic regressions.
class PwnSpecNamespaceControllerFixture
  class StartupError < StandardError; end

  attr_reader :pid, :status

  # Scope adoption to this fixture and restore the runner's previous setting.
  def self.with_reaping
    prctl = PWN::AI::Agent::MissionNamespace.native('prctl', [Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG])
    previous = [0].pack('i')
    PWN::AI::Agent::MissionNamespace.checked(prctl.call(37, Fiddle::Pointer[previous].to_i, 0, 0, 0), 'PR_GET_CHILD_SUBREAPER')
    PWN::AI::Agent::MissionNamespace.checked(prctl.call(36, 1, 0, 0, 0), 'PR_SET_CHILD_SUBREAPER')
    begin
      yield
    ensure
      PWN::AI::Agent::MissionNamespace.checked(prctl.call(36, previous.unpack1('i'), 0, 0, 0), 'restore child subreaper')
    end
  end

  def initialize(descriptor:)
    @reader, @writer = IO.pipe
    @pid = Process.fork do
      @reader.close
      run_controller(descriptor)
    end
    raise ArgumentError, 'controller fork must return a positive child PID' unless @pid.is_a?(Integer) && @pid > 1

    @writer.close
  rescue Exception # rubocop:disable Lint/RescueException -- failed fixture setup must close both pipe ends
    close
    raise
  end

  def wait_ready(path)
    Timeout.timeout(10) do
      loop do
        reap(Process::WNOHANG)
        raise StartupError, exit_evidence unless @pid
        return if File.exist?(path)

        sleep 0.01
      end
    end
  end

  def terminate
    return unless @pid.is_a?(Integer) && @pid > 1

    reap(Process::WNOHANG)
    return unless @pid

    # Capture only this still-owned controller's direct children before KILL.
    begin
      @children = File.read("/proc/#{@pid}/task/#{@pid}/children").split.map { |value| Integer(value, 10) }.select { |pid| pid > 1 }
    rescue Errno::ENOENT
      reap
      return
    end
    begin
      Process.kill('KILL', @pid)
    rescue Errno::ESRCH
      nil
    end
    reap
  end

  def close
    terminate
    @children&.each { |pid| reap_adopted(pid) }
    @children = []
  ensure
    [@reader, @writer].compact.each { |io| io.close unless io.closed? }
  end

  private

  def reap_adopted(pid)
    Timeout.timeout(5) { Process.waitpid(pid) }
  rescue Errno::ECHILD
    nil # The controller already reaped it; never signal a no-longer-owned PID.
  rescue Timeout::Error
    # Cleanup runs after the late-write assertion, never in its observation window.
    if Process.waitpid(pid, Process::WNOHANG).nil?
      Process.kill('KILL', pid)
      Process.waitpid(pid)
    end
    raise
  end

  def run_controller(descriptor)
    exit_status = 0
    begin
      mission = PWN::AI::Agent::MissionNamespace.new(descriptor: descriptor)
      sleep 30
    rescue Exception => e # rubocop:disable Lint/RescueException -- constructor/SystemExit evidence belongs in the parent
      exit_status = e.is_a?(SystemExit) ? e.status : 1
      report_error(e)
    ensure
      begin
        mission&.close
      rescue StandardError => e
        report_error(e) if exit_status.zero?
        exit_status = 1 if exit_status.zero?
      ensure
        @writer.close
        exit! exit_status
      end
    end
  end

  def report_error(error)
    location = error.backtrace_locations&.first
    file = File.basename(location&.path.to_s).gsub(/[^A-Za-z0-9_.-]/, '?')[0, 100]
    klass = error.class.name.to_s.gsub(/[^A-Za-z0-9_:]/, '?')[0, 150]
    # Never serialize messages, source snippets, descriptors or configuration.
    @writer.write(JSON.generate(class: klass, location: "#{file}:#{location&.lineno}"))
  rescue IOError, SystemCallError
    nil
  end

  def exit_evidence
    # A forked descendant can retain the writer: never block waiting for EOF.
    bytes = @reader.read_nonblock(512, exception: false)
    evidence = bytes.is_a?(String) ? JSON.parse(bytes) : {}
    "controller exited before payload readiness: class=#{evidence.fetch('class', 'unavailable')} location=#{evidence.fetch('location', 'unavailable')} exitstatus=#{@status&.exitstatus.inspect} termsig=#{@status&.termsig.inspect}"
  end

  def reap(flags = 0)
    return unless @pid

    _, status = Process.wait2(@pid, flags)
    return unless status

    @status = status
    @pid = nil
  rescue Errno::ECHILD
    @pid = nil
  end
end
