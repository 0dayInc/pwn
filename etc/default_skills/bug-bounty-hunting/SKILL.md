---
name: bug-bounty-hunting
description: Work a bug-bounty program end to end with PWN WWW, Burp, and reports.
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - CWE-284
    - CWE-639
    - https://owasp.org/www-project-web-security-testing-guide/
---

# Bug Bounty Hunting

Use when the ask is a program (HackerOne, Bugcrowd, Synack, or a private
target list): read scope, test in-scope assets, write a report. A listing
of `documentation/` or a green rspec run is not a program tested.

## When to use

- "test this bounty program"
- "authz replay / IDOR / broken access control"
- submit or draft a HackerOne-style report

## Methodologies

- OWASP WSTG + OWASP Top 10 / API Top 10 for the hunt classes
- Bugcrowd VRT / HackerOne severity for ranking (program table wins)
- PTES Intelligence Gathering + Vulnerability Analysis, then a short report
- CWE-284 / CWE-639 / CWE-918 / CWE-79 as the usual bounty labels

## Tooling

- Programs: `PWN::WWW::HackerOne`, `PWN::WWW::BugCrowd`, `PWN::WWW::Synack`
  and `PWN::Plugins::HackerOne` for the API.
- Session + scan: `PWN::Plugins::BurpSuite` (preferred), ZAP as fallback.
- Browser: `PWN::Plugins::TransparentBrowser` through the proxy
  (`devtools: true` when the ask needs DOM/network).
- Authz: `PWN::Bounty::LifecycleAuthzReplay` on a captured HAR with a
  second principal.
- Crawl / API: `PWN::Plugins::Spider`, `PWN::Plugins::OpenAPI`.
- Report: `PWN::Reports::*`, then the program API if asked to submit.

## Procedure

1. Pull the program page. Write down asset types, wildcards, exclusions,
   and payout table. That note is evidence, not the finish.
2. Enumerate in-scope hosts and apps (`NmapIt` only against those assets,
   TransparentBrowser + Burp for web).
3. Map auth: register / login two roles. Save cookies or tokens.
4. Hunt the usual bounty classes: IDOR, authz, OAuth mix-ups, SSRF, stored
   XSS, cache deception, business logic. Prefer Burp active scan on the
   mapped site map, then manual replay.
5. Authz pass: `LifecycleAuthzReplay.start(har_path:, replay_as:, proxy:)`.
6. For each finding: minimal request/response pair, impact, CWE, fix hint.
7. If asked to file: `PWN::Plugins::HackerOne` (or the program's form) with
   that evidence. Close the browser when done.

## Pitfalls

- Do not stop after `sessions_list` or "I will test next time".
- Out-of-scope assets are a skip, not a lecture. Stay on the program list.
- `memory_remember` of an SOP is not a submitted report.

## Verification

Scope note exists, at least one live browse/scan/replay ran against an
in-scope asset, and findings (or a justified empty result) are written
to a file the operator can open.
