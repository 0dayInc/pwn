# Runtime source protection

> The mandatory worker boundary protects source and separates the finite
> controller-state inventory below from tool writes. Checkpoint persistence also
> uses pinned fd-relative no-follow directory operations. Process containment
> owns detached tool jobs until mission completion/cancellation; it is not a
> substitute for filesystem protection. Unspecified tool writes use
> `~/.pwn/workspaces/runtime`. A path is writable outside that directory only
> when the original operator request names it. An explicit destination grants
> its parent even when that parent contains unrelated unreadable directories,
> so a new file can be created there. Source checkouts stay read-only
> even if named. See [Mission-Cancellation](Mission-Cancellation.md).

A pwn-ai RequestRuntime dispatch executes its registered handler in an AISandbox
worker. This boundary is mandatory even when the optional `ai_sandbox` profile
is `off`. It covers shell, Ruby evaluation, other registered handlers, nested
Dispatch calls, and fork/exec descendants including durable Jobs supervisors.
Direct library calls made by an operator outside a RequestRuntime are not AI
runtime tool calls and are unchanged. Legacy regex-ReAct Ruby and shell blocks
also use the mandatory worker boundary (inside their enclosing mission); they
no longer evaluate directly in the mission controller. The source-denial
regression drives both languages through the actual Pry after_read hook.

The host protects `/opt/pwn` when present and the real source root containing the
loaded package. Linux Landlock ABI 3 or newer denies content writes, truncation,
creation, removal, and linking under those roots. It resolves symlinks and `..`
in the kernel: scripts are not rewritten. Repo reads remain available. The UI
process does not change cwd. Relative reads use the task directory when it is
outside protected source; otherwise they use `~/.pwn/workspaces/runtime`.
Unnamed new files and temporary files go to that runtime directory. `/tmp`, the
launch directory, and the rest of `~/.pwn` are not default write grants. A path
named by the original operator request is created and granted; naming a file
grants its parent so the file can be created. That parent grant is a directory
rule, so a new file can still be created when the parent contains unrelated
unreadable directories. Do not create the missing destination as a directory.
Protected source is never granted.
Standard null/zero/random devices are available. Other filesystem writes fail
closed. This bounded write set permits hardlink-alias exclusion without scanning
all mounted filesystems or changing checkout permissions.

## Fail-closed requirements and restrictions

- Supported syscall ABIs are Linux x86_64 and aarch64; libseccomp is required.
  Missing enforcement prevents handler execution, rather than falling back to
  regex checks or unsandboxed execution.
- Landlock does not mediate file metadata changes. The worker therefore denies
  chmod/chown, timestamp and extended-attribute mutation system-wide, including
  outside source. Ordinary outside content writes and file creation still work.
  Tools that need those metadata operations require a different supported
  execution environment, not an exception to source protection.
- Mount/namespace manipulation, ptrace/process-memory writes, and io_uring setup
  are denied. Existing descriptors into protected roots are closed in the child.
- Host preflight inventories multiply linked protected file identities and
  excludes matching aliases in every writable tree. Aliases elsewhere receive
  no write grant. Alias inventories are cached against source inode/link-count/
  ctime fingerprints and writable-root identity; source link changes invalidate
  that cache. Unreadable subtrees encountered during alias scanning are excluded.
  This includes generated rdoc assets linked to installed gem assets; no source
  files are chmodded, deleted, or automatically rewritten.
- Protected root ancestors cannot grant inherited write permission without also
  granting it to source. Creating a new sibling directly in such an ancestor is
  consequently denied; use an existing writable outside directory.
- This is a local process/filesystem effect boundary, not isolation of remote
  services or already-running privileged daemons commanded over IPC/network.
  It does not defend against a concurrent external actor replacing policy paths
  or introducing new hardlink aliases after preflight. Do not run untrusted
  external writers against the protected installation.
- Handler-local Ruby variables and in-memory plugin state do not propagate back
  to the UI. Persistent outputs and durable job state do. A handler that requires
  process-local state across calls must not assume the old in-process evaluator.

## Sandboxed swarm control

`agent_spawn` and `agent_ask` handlers still run inside the mandatory worker.
Their Swarm calls use a private socket to request only the controller's typed
`spawn`/`ask` operations. The controller checks request tool permissions, rejects
unknown fields/operations and traversal identifiers, and never invokes a
worker-selected Registry handler, callback, Ruby expression, or filesystem path.
Nested persona tools pass through Dispatch and get their own mandatory workers.

Before launch the controller provisions the fixed swarm directory, persona file,
and continuation lock with no-follow ancestry and regular-file/single-link
checks. Workers cannot write the persona file, swarm subtree, or request
checkpoint tree, nor rename their ancestors. No parent-directory write grant is
added. Child Loop receipts remain controller-observed and are rechecked when
merged into the parent. This preserves sandboxed spawn/ask state creation without
allowing arbitrary controller callbacks.

## Finite parent-writer audit

The worker deny set now includes these controller-owned stores, even before a
store exists. Missing paths still split the ancestor's Landlock grant, preventing
first-write symlink planting. Existing inherited descriptors and hardlink aliases
are covered by the same preflight as source. Store constants are resolved in the
controller, not from model/tool output. Both lexical paths and canonical store
aliases are denied, so a configured symlink cannot expose controller state
through another otherwise writable directory.

| Parent writer | Protected state |
| --- | --- |
| RequestRuntime checkpoints and EngagementMemory | Request-specific artifact root; checkpoint lock/temp/final persistence is also fd-relative/no-follow |
| Sessions and SessionTrace | Sessions root, including support, leases, traces and requests |
| Loop transcript compaction, ArtifactRegistry, swarm bus spills | Default artifacts root and configured ArtifactRegistry root |
| Learning, Policy, Metrics, Reward, Mistakes, ToolGuard | Declared files/directories, learning and metrics subtrees; absent sibling staging paths cannot be planted |
| Memory and MemoryIndex | Memory, archive and index files |
| OpenGoal, Mission and TaskDAG | Goal file, missions and runs roots |
| SkillReview and Curriculum | Ledger, curriculum/finetune roots, default/configured skill directories and loaded skill parents |
| Provider credential persistence and local model configuration | Default vault/decryptor and configured driver paths |
| Session redaction's Vault persistence | Engagements tree, legacy vault file and master-key path |
| Log and Extrospection | Default logs and declared Extrospection stores |
| Typed swarm controller | Swarm subtree, personas and continuation lock |

The regression first reproduced an actual worker redirect of the transcript
spill directory: after the worker returned, Loop created a file in synthetic
protected source. It now receives permission denied, as does the earlier
RequestRuntime spill reproducer. An independent fixture attempts 29 state
mutations across existing directories/files and an absent staging path in both
ordinary and symlinked-store layouts, while also creating a legitimate output in
a disjoint workspace.

Tools that directly mutate these controller stores are deliberately denied;
only spawn/ask currently have the typed broker exception. This is not a promise
that arbitrary in-process stateful plugins retain their old behavior. New parent
writers or custom stores require an inventory update. The guarantee assumes a
trusted initial controller layout and excludes concurrent external filesystem
writers as described above; it is not a general host sandbox.

## Completion evidence and uncertainty

Required artifact names come from the original operator request (including
explicit amendments), not cached model guesses or tool transcripts. Unquoted
prose such as `i.e.` does not create a required file named `i.e`; explicitly
quoted filenames are still honored.

RequestRuntime snapshots required artifacts before dispatch and, on success,
reads their stat, bounded head/tail and SHA-256 from the host. Successful actual
file deltas count even if payload classification called the tool `eval` rather
than `write`. Receipts accumulate across separate calls/iterations and survive
transcript compaction. A failed tool, unchanged stale file, or tool stdout claim
cannot create a receipt. Current bytes/identity must still match at completion.
A combined write/read call does not require a ritual second call.

Unknown side effects remain replay-fenced. A timeout/interruption or failed
mutation is not erased by unrelated successful artifacts. On an attempted final
answer the loop returns a structured `blocked` outcome with action ID and payload
hash, instead of endlessly asking for rewrites. Exact-target operator-approved
reconciliation is still required for genuine uncertainty; the existing HTTP
reconciliation API is unchanged. Kernel/preflight failure before the handler
starts is recorded as `rejected`, not falsely labeled an uncertain mutation.

## Verification and deployment

Offline specs exercise actual kernel workers, symlink/parent traversal denial,
metadata denial, nested Dispatch, a detached Jobs worker, fail-closed unsupported
protection/hardlinks, and the Loop → Dispatch → cumulative host receipt path with
an actual generated PDF and separate text output. Provider messages in that
replay are fixtures, not a live remote-model test.

Source changes do not update an installed gem or a running pwn-ai process.
Deploy the matching source/package files and restart the remote process through
the operator's normal deployment procedure. Inspect the reported root/hardlink
and kernel requirements before claiming that host is operational.
