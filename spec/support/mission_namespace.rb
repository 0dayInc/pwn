# frozen_string_literal: true

# Unit fixtures contain Ruby closures/mocks that cannot cross exec. Bootstrap
# ONLY the test runner into a real user namespace; every mission still creates
# and reaps its own PID namespace. Exec integration fixtures force the production
# descriptor path separately. No test flag disables kernel containment.
# A root runner must map nobody. --map-current-user leaves only uid 0, and
# chown/setuid to an unmapped account then fails with EINVAL.
unless PWN::AI::Agent::MissionNamespace.prepared?
  args = ['unshare', '--user', '--keep-caps']
  args.push(Process.uid.zero? ? '--map-users=0:0:65536' : '--map-current-user')
  args.push('--map-groups=0:0:65536') if Process.uid.zero?
  exec(*args, RbConfig.ruby, '-I', $LOAD_PATH.join(File::PATH_SEPARATOR), $PROGRAM_NAME, *ARGV)
end
