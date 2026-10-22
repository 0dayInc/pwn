# Capability broker and disposable sandbox

## pwn-capd (P8)

The native Ruby helper speaks one bounded JSON request per Unix connection.
Ruby `Socket` and `pack` implement AF_PACKET send/capture and pcap encoding;
the existing `ffi` gem calls Linux libc `prctl`, `capget` and `capset`.
There is no Python runtime or fallback. Read-only ARP/ND queries retain the
`/usr/sbin/ip` (iproute2) dependency, executed as an argument vector with a
clean environment, bounded output and a five-second deadline.
Linux SO_PEERCRED authenticates the configured caller UID; the client also
checks the daemon UID. The socket is mode 0600. Only explicitly configured
interfaces are accepted. Operations: `status`, `raw_send` (base64 Ethernet
frame), `capture` (bounded in-memory pcap), `arp` / `nd` (typed IP kernel
neighbor-cache queries). There is no command endpoint, arbitrary privileged
output path, firewall mutation, or implicit sudo. ARP/ND currently query cache;
they do not actively solicit neighbors or mutate entries.

Requests are limited to 100,000 bytes including the newline; each connection
has a 35-second total deadline. Ethernet sends accept 14..65,535 decoded bytes.
Captures accept 1..128 packets, at most 30 seconds, and 4,096 bytes per packet.
The helper sets `no_new_privs`, intersects effective/permitted capabilities
with CAP_NET_RAW/CAP_NET_ADMIN, and clears both inheritable words before
handling requests. It never adds a capability. Existing socket paths (including
symlinks) and writable or foreign-owned socket directories are refused.

Unprivileged protocol and native-executable smoke (no raw packets or privilege grants):

```
bundle exec rspec spec/lib/pwn/plugins/capability_broker_spec.rb spec/lib/pwn/plugins/capability_broker/daemon_spec.rb
```

Operator installation (NOT executed by the application): install the reviewed
PWN Ruby package and its dependencies root-owned, including `bin/pwn-capd`,
`lib/pwn/plugins/capability_broker.rb` and
`lib/pwn/plugins/capability_broker/daemon.rb`. Keep the package's `bin/` and
`lib/` layout intact; point the service ExecStart at that package's
`bin/pwn-capd`. A root-managed installed-gem executable may also be exposed
as `/usr/local/libexec/pwn-capd` (mode 0755). The executable, library tree,
Ruby interpreter, gems and all ancestor directories must be administrator
controlled and non-writable by clients. Clear user-controlled `RUBYOPT`,
`RUBYLIB`, `GEM_HOME`, `GEM_PATH` and Bundler environment settings in the
service; use only the reviewed installation's dependency paths.
Do **not** setcap the shared Ruby interpreter
or this script: Linux ignores script file capabilities, and granting a shared
interpreter network privileges exposes every script. Use a dedicated systemd
service with `User=<operator>`,  `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`,
`CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN`, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, `ProtectHome=yes`, `RuntimeDirectory=pwn-capd`,
`RestrictAddressFamilies=AF_UNIX AF_PACKET AF_NETLINK`, and the reviewed helper
as ExecStart. The socket owner and configured peer UID must match that operator.
Enable a preconfigured unit with `sudo systemctl start pwn-capd`.
For an audited one-shot sudo launch use:

```
sudo /usr/local/libexec/pwn-capd --uid "$(id -u)" --interface lo
```

Never authorize unrestricted sudo access to arbitrary helper arguments. Pin
UID, socket and interface in sudoers. Only add engagement interfaces after
operator review. CAP_NET_ADMIN is reserved for future neighbor management;
current operations need CAP_NET_RAW, while neighbor queries are read-only.

Ruby API (the central plugin namespace autoloads CapabilityBroker):

```ruby
require 'pwn/plugins/capability_broker'
PWN::Plugins::CapabilityBroker.request(operation: 'status')
PWN::Plugins::CapabilityBroker.request(operation: 'arp', iface: 'lo', address: '127.0.0.1')
PWN::Plugins::CapabilityBroker.request(operation: 'nd', iface: 'lo', address: '::1')
# Packet.send(pkt:, iface:, socket:) and Packet.capture(path:, count:, timeout:, iface:, socket:)
```

`PWN_CAPD_SOCKET` overrides `/run/pwn-capd/control.sock`. Capture artifacts are
written and read back by the unprivileged client, never by the daemon.
Absent broker returns degraded error and missing local CAP_NET_RAW accurately;
there is no fabricated capture path or privileged Ruby remediation.

## Sandbox (P13)

```ruby
require 'pwn/plugins/sandbox'
PWN::Plugins::Sandbox.run(binary: '/path/safe-fixture', argv: [], stdin: '', timeout: 10, memory_mb: 256)
PWN::Plugins::Sandbox.fuzz(target: '/path/safe-fixture', corpus: '/path/seeds', minutes: 1, seed: 0)
s = PWN::Plugins::Sandbox.snapshot(binary: '/path/safe-fixture')
PWN::Plugins::Sandbox.rollback(snapshot: s[:snapshot], backend: 'bwrap')
```

Docker is default, image `pwn-sandbox:local`; it must be provisioned locally,
with `/usr/bin/ruby`, strace, GDB, and target runtime libraries. The controller
and isolated worker use Ruby stdlib only; no Python interpreter is launched by
the sandbox driver (GDB itself may include Python support). No implicit
pull, installation, daemon startup or host-execution fallback occurs. Use the
included `lib/pwn/plugins/sandbox/Dockerfile` to build explicitly. Network none,
read-only root/artifacts, unprivileged UID, all caps dropped, no-new-privileges,
pid/cpu/memory/swap constraints, disposable bounded tmpfs, forced cleanup.
Instrumentation runs are separate replays with the same input, not observation
of the original execution. Signals, PC, backtrace, raw GDB output are returned;
exploitable classification is `unknown` if the GDB plugin is absent. No invented
classification. Current `-nx` configuration deliberately does not load arbitrary
user GDB startup scripts. Install a reviewed exploitable plugin into the image
and extend its explicit initialization if classification is required.

Explicit `backend: 'bwrap'` works without a Docker daemon where unprivileged
user namespaces are permitted. It exposes only read-only system runtime trees
and target artifact, creates fresh user/network/PID/mount namespaces, and hides
home. It is a **weaker resource tier**: per-process RLIMIT_AS, not an aggregate
cgroup budget or fork-bomb protection. Use Docker/microVM for hostile samples.
No automatic backend fallback. Snapshot/rollback means verified immutable input
copies and fresh disposable environments, **not live process/VM checkpoints**.
Fuzzing is bounded seeded bit-flip stdin mutation, not coverage-guided AFL.

Tools register via `require 'pwn/ai/agent/tools/sandbox'`: `sandbox_run` and
`sandbox_fuzz`; normal Registry discovery finds that file.

Sandbox verification (safe bwrap fixtures require working unprivileged namespaces):
```
bundle exec rspec spec/lib/pwn/plugins/sandbox_spec.rb spec/lib/pwn/plugins/sandbox/driver_spec.rb
```

The tests exercise `/bin/true`, read-only mounts, namespace isolation without
network requests, timeouts, resource limits, SIGSEGV/GDB/strace replay,
byte-exact stdin mutation and snapshot integrity. Docker command/cleanup unit
checks are not evidence of a running Docker backend. The GDB fixture requests
1024 MiB: this host's GDB can exhaust the default 256 MiB address-space budget.
Instrumentation failures retain raw output and an unknown classification.

Fuzz seeds are reproducible within this Ruby implementation, not bit-for-bit
compatible with Python's PRNG sequence. Each iteration retains the execution
and replay budget plus bounded backend startup/cleanup overhead; the minutes
budget stops starting new iterations, rather than preempting cleanup.

Safe real Docker smoke after explicit provisioning:
```
bundle exec ruby -Ilib -rpwn/plugins/sandbox -e 'p PWN::Plugins::Sandbox.run(binary: "/bin/true")'
```
