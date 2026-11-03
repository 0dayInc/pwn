# Mission process lifetime and cancellation

## Implemented boundary

The curses ordinary-request path, local slash-command workers, each curses
swarm job, and the non-curses `pwn_ai_run_steerable` entrypoint execute provider,
controller, and tool work
in a mission-owned Linux PID namespace. CTRL+C kills
namespace PID 1 through a pidfd, waits for its supervisor to reap it, joins the
IPC reader, and only then releases the UI's running state. A process group is
not the ownership boundary: setsid, double forks, and nested child namespaces
remain descendants of the mission namespace. Other sessions and unrelated
processes are not signalled.

There is no systemd, cgroup, application compiler, or PGID fallback.
`PWN::AI::Agent::MissionNamespace` is Ruby code using stdlib Fiddle for Linux pidfds and
process-death signals. Its runtime prerequisite is **util-linux `unshare`**
(`pwn setup --profile ai`). Linux user/PID namespaces and pidfds must be enabled;
unsupported kernels or local policy fail closed with setup guidance.

Ruby recreates its timer thread after fork, so creating a user namespace from a
Ruby fork is not supported. For ordinary launches the controller **execs** an
`unshare --user --map-current-user --keep-caps` supervisor. That fresh Ruby
supervisor creates a PID namespace and forks its init. It passes a pidfd back
through a private Unix socket; the init waits for acknowledgement before running
any request. Killing the supervisor also kills its init through PDEATHSIG.
The controller, its cwd, and unrelated embedded PWN REPL modes are unchanged.

Curses/native, legacy, slash, swarm and one-shot CLI requests use named,
serializable descriptors, not serialized Ruby closures. Configuration, loaded
skill metadata and routing context travel as typed JSON over inherited private
sockets, never in argv or plaintext staging files. RequestRuntime's tool-worker
snapshot excludes locks and caller cancellation callbacks; the enclosing owner
provides cancellation. Replies and events remain JSON with generation fencing.
Loaded Ruby skill scripts are required in the worker. Embedders with additional
trusted plugin initializers can explicitly set
`PWN::AI::Agent::MissionNamespace.bootstrap_requires = ['/absolute/plugin/bootstrap.rb']`.
Arbitrary monkey patches, IO objects and Proc values are not serializable.

For applications explicitly launched in a single-identity user namespace,
MissionNamespace can fork its PID supervisor directly. This preserves trusted
in-memory Ruby closures without calling unshare(NEWUSER) from Ruby. The caller
must bootstrap explicitly with `unshare --user --map-current-user --keep-caps`;
there is no automatic re-exec of an embedded application. The unit-test runner
uses this real-kernel mode for in-memory mocks; exec/PTy fixtures explicitly
force the ordinary descriptor path. Both paths create a real per-mission PID
namespace and reject unavailable containment.

Ordinary-request events carry a generation; swarm child messages carry job
IDs, and console swarm callbacks carry an epoch invalidated by CTRL+C.
Provider calls, including ordinary-request title refresh, remain in the child.
Steering uses a separate JSON control pipe. The UI never deserializes Ruby
objects from the child.

## Detached jobs

Detached jobs started by a tool inside a mission inherit that mission's
namespace. They can continue after the individual tool returns, but **not**
after mission completion, cancellation, or namespace-owner death. Normal
mission completion also tears down remaining detached descendants. This is
intentionally different from cross-session durable jobs. A standalone
`AISandbox.protect_call` without an enclosing mission creates its own namespace
and ends that lifetime when the call ends.

Existing files and already-submitted remote operations are not rolled back.
The local process guarantee does not revoke work accepted by an external
service or remote host. Kernel-blocked uninterruptible I/O may delay reaping;
the UI must remain busy rather than claim readiness early.

## Controller-state separation

Tool workers are denied writes to their RequestRuntime artifact/checkpoint
root, including its spill directories and inherited descriptors. The actual
worker-symlink -> parent-spill reproducer now fails at the worker's symlink
with permission denied, and the synthetic source directory remains unchanged.
The audited controller stores (sessions/traces, transcript artifacts,
learning/policy/metrics, skills, logs, vault/configuration and mission state) are
also excluded from worker grants. See the finite writer checklist in
[Runtime-Source-Protection](Runtime-Source-Protection.md). Unspecified tool
writes stay in `~/.pwn/workspaces/runtime`; another path is allowed only when
the original operator request names it. Naming a missing file grants its parent,
including when that parent contains unrelated unreadable directories, so the
named file can be created. Controller state and tool output
workspaces must be disjoint: a parent directory containing protected state
cannot safely receive a broad Landlock write grant.

## Verification and remaining scope

RSpec owns the subprocess fixtures under `spec/support/harness/mission_*.rb`.
`spec/integration/mission_cancel_spec.rb` exercises ordinary console next-request
readiness and generation fencing, blocked-provider descendants, setsid escape,
normal-exit double forks, unrelated-process preservation, mission-lived tool
jobs, swarm cancellation, and fail-closed bootstrap. The namespace-denial
fixture injects EPERM; namespace creation/teardown tests use the real kernel.
`spec/integration/controller_spill_spec.rb` exercises actual RequestRuntime,
Dispatch, sandbox restriction, and parent spill persistence with synthetic paths.

Local slash-command maintenance/model/MCP workers now use the same hard process
ownership. Their completion and UI-state messages are generation-fenced JSON;
CTRL+C reaps the owner before returning ready. Maintenance already committed
before cancellation is not rolled back. Model persistence decrypts and encrypts
in memory; its staging file contains only ciphertext (or is empty). An offline
SIGKILL regression interrupts encryption startup and verifies unchanged original
ciphertext and absence of plaintext in the abandoned stage. Native curses PTY
coverage includes cancellation during a blocked local command and a successful
next mission.

The legacy regex-ReAct fallback now runs its provider/parser/tool loop in the
same MissionProcess owner. Completed history is transferred by JSON; native
containment failures are terminal rather than an excuse to retry uncontained.
Its actual after_read hook and PTY fixture cover detached Ruby/bash descendants,
CTRL+C, no late writes and a successful next request. Workspace policy
clarification does not block these offline gates.

Native PTY regressions drive actual terminal CTRL+C through both the curses
console and `pwn_ai_run_steerable`, assert no late descendant writes, then complete
a second mission. Compiler-free package acceptance builds and installs into a
private scratch GEM_HOME with compiler/make commands replaced by failing shims,
activates that exact specification, checks an empty extensions list and no
mission shared object, then executes a descriptor. Root and nonroot acceptance
must be reported separately; these are offline checks, not provider or hardware
evidence.

Root loses host-wide DAC override when it enters a user namespace. A host-root
mission therefore cannot traverse another user's mode-0700 home merely because
its parent could. Test roots and deployment workspaces must be traversable by
the mapped host identity. Do not chmod the operator's home to make a fixture
pass. Filesystem fixtures beneath a private nonroot HOME must use that identity,
including when their outer test runner is root. The integrated root fixture uses
an isolated mount namespace: only its task-owned scratch layout is bound at a
root-traversable path, with HOME, TMPDIR and inherited stdout/stderr logs opened
inside that layout. Inherited logs opened below the inaccessible real home would
correctly fail the protected-descriptor preflight. Neither the host mount table
nor the operator's directory permissions are changed.
