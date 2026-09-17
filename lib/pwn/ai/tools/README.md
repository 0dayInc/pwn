# Agent manifests and scope policy

`Registry.discover` loads trusted `*.yaml` declarations in this directory. Each
entry requires `name`, `description`, JSON Schema `params`, and `risk_level`
(`info`, `low`, `med`, `high`, `crit`). Optional `plugin` and `method` register one
public `PWN::Plugins::<Name>` method; omitted plugin fields annotate an existing
Ruby-registered tool. Plugin methods receive an args Hash (or no args for a
zero-arity method). Do not load model-provided manifests.

Scope is opt-in: no `~/.pwn/scope.yaml` preserves existing behavior. Creating that
file enables policy. Example:

```yaml
allowed_cidrs: [192.0.2.0/24, '2001:db8::/32']
allowed_domains: [example.test, '*.example.test']
allowed_ports: [443, 8000-8100]
risk_gates:
  info: auto
  low: auto
  med: prompt
  high: prompt
  crit: deny
confirmation:
  read_only: auto
  active_scan: auto
  exploit: prompt
  destructive: prompt
```

Missing risk gates deny; unannotated tools use `crit`. `enabled: false` explicitly
disables this optional policy. Invalid/empty policy files fail closed. A wildcard
requires a subdomain and does not match the apex. CIDRs must be wholly contained;
URLs check their host and explicit/default port, without performing DNS/network
lookups. Every declared target and port must match. A denied target is audited to
`~/.pwn/logs/scope-audit.jsonl`; raw code, credentials, and target values are not
written into that audit. Audit write failures remain denials and report
`audit_error`.

By default, target argument names are `target`, `targets`, `host`, `hosts`,
`domain`, `domains`, `cidr`, `cidrs`, `url`, `urls`; ports are `port`, `ports`.
A manifest may customize these top-level fields:

```yaml
target_params:
  hosts: [destination]
  ports: [destination_port]
```

This is a declared-target policy, **not a sandbox or Ruby/shell static analyzer**.
It does not infer network destinations from code/command text, resolve DNS, or
prevent an operator-approved general-purpose tool from making undeclared calls.
Keep those tools at `prompt` or `deny` when stronger engagement controls are
required; no global reduction of `pwn_eval` functionality is imposed.

Trusted callers may pass `scope_policy:`, `scope_path:`, `audit_path:`, and
`approval_callback:` to `Dispatch.call`. Prompt callbacks receive
`{name:, risk_level:, args:}` and must return literal `true`; absent/raising
callbacks fail closed. Out-of-scope calls never reach the callback. Approval
flags in tool arguments have no authority.

## Task timeout ledger integration

Pass one mutable `budget_ledger: {}` to every Dispatch call for a user task; use
a fresh Hash for a new task. Without one, Dispatch uses a thread-local fallback
(`Thread.current[:pwn_dispatch_budget]`) that the embedding caller must reset.
Do not derive ledgers, scope policy, or approval callbacks from tool arguments.

For timeout-capable tools the canonical hash excludes `timeout`. A timeout makes
that tool's next retry use the identical payload and last timeout +180, clipped
to the remaining 10800-second cumulative payload budget. An exhausted payload
can be rewritten ten times per task. Different successful operations are not
mutations. `budget_key:` is an optional trusted approach identifier (default tool
name). Other tools remain available when an approach exhausts its budget.

Results include `budget` telemetry. `retry_required` blocks premature mutation;
`budget_exhausted` requests a deterministic pivot, not global task abortion.
The loop must pass the tool result back to the model and continue other work.
Timeout-capable registered handlers are responsible for enforcing the deadline
passed in args; shell and pwn_eval enforce it in their execution lifecycles.
