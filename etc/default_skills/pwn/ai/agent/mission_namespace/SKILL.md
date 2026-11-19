---
name: pwn-ai-agent-mission-namespace
description: Compiler-free Linux mission process ownership.
preserve: true
metadata:
  bundled: true
  module: PWN::AI::Agent::MissionNamespace
  source: pwn/ai/agent/mission_namespace.rb
---

# PWN::AI::Agent::MissionNamespace

Launch typed mission descriptors using util-linux `unshare` when the kernel
allows an unprivileged user namespace. If that call is denied, or the
namespace child closes the supervision socket, the same handshake runs in a
process-group supervisor. No apparmor or sysctl change is required. Pidfds
still cancel the owned child. A setsid descendant can leave a process group;
a PID namespace, when available, is what reaps those.

The controller remains outside namespaces. Each request transfers its private
configuration snapshot in memory, then owns a PID namespace. Cancellation kills
namespace PID 1 and waits for the supervisor to reap it. Arbitrary Ruby closures
are only supported inside an already-owned mission for protected tool workers.
