# `PWN::Plugins::TransparentBrowser`

Watir + Selenium wrapper that gives you a real Chrome/Firefox — headless or
visible — with proxy support, DevTools protocol access, and cookie/console
capture. It's the traffic source for [BurpSuite](BurpSuite.md), the engine
under every [`PWN::WWW`](WWW.md) driver, and the agent's go-to for anything
JS-heavy.

## Open

```ruby
b = PWN::Plugins::TransparentBrowser.open(
  browser_type: :headless,           # :chrome | :firefox | :headless | :rest
  proxy:        'http://127.0.0.1:8080',
  with_devtools: true
)
b[:browser].goto 'https://target'
b[:browser].text_field(name: 'q').set 'pwn'
```

## Useful bits

```ruby
b[:browser].cookies.to_a
b[:browser].execute_script('return document.title')
b[:devtools].send_cmd('Network.enable')
PWN::Plugins::TransparentBrowser.dump_links(browser_obj: b)
PWN::Plugins::TransparentBrowser.close(browser_obj: b)
```

## `:rest` mode

`browser_type: :rest` returns a `RestClient`-backed object with the same proxy
plumbing — for APIs where a full browser is overkill.

## Agent integration — Extrospection's eyes

`PWN::AI::Agent::Extrospection` drives this plugin (`:headless`, `:rest`
fallback) as its **web sense organ** — the counterpart to `probe_rf`'s ears:

| Agent tool | Uses TransparentBrowser to… |
|---|---|
| `extro_snapshot(sections: %i[web])` → `probe_web` | Fingerprint config-declared `web_anchors`: status · title · meta[generator] · SHA-256 of *rendered* DOM text · TLS cert fp/notAfter · optional screenshot |
| `extro_watch(url:, selector:)` | Passive change-detection on a target page — re-hash the rendered DOM and diff vs the prior `:web` observation |
| `extro_verify(claim:, kind:)` | **Proactive self fact-check** — render NVD/CVE.org, rubygems/PyPI, a cited URL, or DuckDuckGo HTML and return `:confirmed` / `:refuted` / `:unknown`. `:refuted` → `Mistakes.record(tool:'assumption', …)` |
| `revalidate_memory` (cron) | Garbage-collect stale `PWN::Memory` `:fact` entries by re-`verify()`ing every one containing a CVE / version / URL |

All four honour `proxy:` (Burp / `tor`) so attribution stays controlled, reuse
**one** browser handle across anchors, and `close` in an `ensure`. See
[Extrospection](Extrospection.md) for the full loop.


[← Home](Home.md) · [BurpSuite](BurpSuite.md) · [WWW](WWW.md) · [Extrospection](Extrospection.md)
