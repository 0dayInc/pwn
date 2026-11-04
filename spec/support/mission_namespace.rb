# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'

# Unit fixtures contain Ruby closures/mocks that cannot cross exec. Bootstrap
# ONLY the test runner into a real user namespace; every mission still creates
# and reaps its own PID namespace. Exec integration fixtures force the production
# descriptor path separately. No test flag disables kernel containment.
# A root runner must map nobody. --map-current-user leaves only uid 0, and
# chown/setuid to an unmapped account then fails with EINVAL.
# Do not ask unshare to map host uids 0-65535. That flag calls newuidmap, which
# refuses the range unless /etc/subuid grants it. Root still has
# CAP_SETUID in the parent namespace and writes the map itself.
module PwnSpecNamespace
  module_function

  def bootstrap!
    return if PWN::AI::Agent::MissionNamespace.prepared?

    if Process.uid.zero?
      bootstrap_root!
    else
      exec('unshare', '--user', '--keep-caps', '--map-current-user', RbConfig.ruby, '-I', $LOAD_PATH.join(File::PATH_SEPARATOR), $PROGRAM_NAME, *ARGV)
    end
  end

  def bootstrap_root!
    dir = nil
    pid = nil
    # setgroups deny is required before gid_map and then makes Process.groups=
    # return EPERM for every process in the suite. Clear supplementary groups
    # while this parent can still call setgroups. The unshare child inherits
    # the empty set, which is the cleared state the smoke drop expects.
    Process.groups = []
    dir = Dir.mktmpdir('pwn-userns-')
    File.chmod(0o1777, dir)
    ready = File.join(dir, 'ready')
    go = File.join(dir, 'go')
    pid = Process.spawn(
      { 'PWN_NS_READY' => ready, 'PWN_NS_GO' => go },
      'unshare', '--user', '--keep-caps', '/bin/sh', '-c',
      'touch "$PWN_NS_READY"; while [ ! -f "$PWN_NS_GO" ]; do sleep 0.05; done; exec "$@"',
      'sh', RbConfig.ruby, '-I', $LOAD_PATH.join(File::PATH_SEPARATOR), $PROGRAM_NAME, *ARGV
    )
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    sleep 0.02 until File.exist?(ready) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    raise 'root user-namespace bootstrap timed out before unshare' unless File.exist?(ready)

    File.write("/proc/#{pid}/setgroups", 'deny')
    File.write("/proc/#{pid}/gid_map", "0 0 65536\n")
    File.write("/proc/#{pid}/uid_map", "0 0 65536\n")
    File.write(go, "go\n")
    Process.wait(pid)
    status = Process.last_status.exitstatus || 1
    pid = nil
    # Kernel#exit raises SystemExit. RSpec rescues that while loading a spec
    # and reports it as a load failure. exit! ends this parent with the child's
    # status and does not raise. Clean the sync dir first; exit! skips ensure.
    FileUtils.rm_rf(dir) if dir
    dir = nil
    exit! status
  rescue StandardError
    if pid
      Process.kill('KILL', pid)
      Process.wait(pid)
    end
    raise
  ensure
    FileUtils.rm_rf(dir) if dir && File.exist?(dir)
  end
end

PwnSpecNamespace.bootstrap!
