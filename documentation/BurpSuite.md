# Burp Suite Integration

**Preferred** web application proxy and scanner in PWN.

## Why Burp Over ZAP

Burp Suite Professional offers richer scanning, more comprehensive plugin ecosystem, and better active/passive scanning capabilities for modern web apps. Use `PWN::Plugins::BurpSuite` by default.

## Key Methods (incomplete list - inspect in REPL)

- `PWN::Plugins::BurpSuite.start(...)`
- `PWN::Plugins::BurpSuite.stop`
- `PWN::Plugins::BurpSuite.get_sitemap(...)`
- `PWN::Plugins::BurpSuite.send_request(...)`
- Live spidering and scanning orchestration
- Integration with TransparentBrowser for proxied browsing

## Typical Usage via Agent

> "Start BurpSuite, configure TransparentBrowser to proxy through it, spider target, run active scan, report findings."

See `lib/pwn/plugins/burp_suite.rb` for full API and source.

Also see [Plugins](Plugins.md) and [pwn-ai Agent](pwn-ai-Agent.md).

[[Diagrams]]
