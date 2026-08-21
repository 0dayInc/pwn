---
name: pwn-ai-agent-extrospection-osintsocial
description: Drive PWN::AI::Agent::Extrospection::OSINTSocial from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Extrospection::OSINTSocial
  source: pwn/ai/agent/extrospection/osint/social.rb
---

# PWN::AI::Agent::Extrospection::OSINTSocial

Social-network / developer-identity OSINT feeds for PWN::AI::Agent::Extrospection.osint. All methods here reopen the Extrospection singleton so osint_dispatch can route to them exactly like the in-file feeds. Everything is best-effort: unreachable endpoints degrade to {error:} rather than raising. Feeds provided: :keybase :gravatar :mastodon :bluesky :hackernews :stackexchange :npm :pypi :rubygems :crates :dockerhub :codeberg :sourcehut :chesscom :lichess :steam :telegram :social_sweep New kind :social routes to the profile-fetch feeds; :username still returns the legacy 3-platform hash for back-compat but now also includes a truncated :social_sweep hit list.

## When to use

Call `PWN::AI::Agent::Extrospection::OSINTSocial` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/extrospection/osint/social.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Extrospection::OSINTSocial.help
PWN::AI::Agent::Extrospection::OSINTSocial.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/agent/extrospection/osint/social.rb`

## Verification

`PWN::AI::Agent::Extrospection::OSINTSocial.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
