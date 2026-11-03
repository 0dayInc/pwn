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

Launch typed mission descriptors using util-linux `unshare`, Ruby stdlib
Fiddle pidfds, and private inherited sockets. Install `pwn setup --profile ai`.
Linux user/PID namespaces and pidfds must be enabled. Unsupported hosts fail
closed; there is no process-group or uncontained fallback.

The controller remains outside namespaces. Each request transfers its private
configuration snapshot in memory, then owns a PID namespace. Cancellation kills
namespace PID 1 and waits for the supervisor to reap it. Arbitrary Ruby closures
are only supported inside an already-owned mission for protected tool workers.
