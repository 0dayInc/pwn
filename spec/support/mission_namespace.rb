# frozen_string_literal: true

# Unit fixtures contain Ruby closures/mocks that cannot cross exec. Bootstrap
# ONLY the test runner into a real user namespace; every mission still creates
# and reaps its own PID namespace. Exec integration fixtures force the production
# descriptor path separately. No test flag disables kernel containment.
unless PWN::AI::Agent::MissionNamespace.prepared?
  exec('unshare', '--user', '--map-current-user', '--keep-caps', RbConfig.ruby,
       '-I', $LOAD_PATH.join(File::PATH_SEPARATOR), $PROGRAM_NAME, *ARGV)
end
