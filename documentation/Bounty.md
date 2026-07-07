# `PWN::Bounty` — Bug-Bounty Lifecycle Tooling

| Module | Purpose |
|---|---|
| `PWN::Bounty::LifecycleAuthzReplay` | Record an authenticated browser session, then replay every request under a *different* principal to surface horizontal/vertical authz bugs |

Pairs naturally with:

- [`PWN::WWW::HackerOne`](WWW.md) / `BugCrowd` / `Synack` — programme navigation
- `PWN::Plugins::HackerOne` — submissions API
- [`PWN::Plugins::BurpSuite`](BurpSuite.md) — capture the session to replay

```ruby
PWN::Bounty::LifecycleAuthzReplay.start(
  har_path: 'admin_session.har',
  replay_as: { cookie: 'session=LOW_PRIV_TOKEN' },
  proxy: 'http://127.0.0.1:8080'
)
```

[← Home](Home.md) · [WWW](WWW.md)
