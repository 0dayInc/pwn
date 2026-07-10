# `PWN::WWW` - Site-Specific Browser Automations

21 modules, each a scripted [`TransparentBrowser`](Transparent-Browser.md)
session against a real site: log in, navigate, scrape, submit.
Source: `lib/pwn/www/*.rb`.

## Modules

| Category | Modules |
|---|---|
| **Bug bounty** | `HackerOne` · `BugCrowd` · `Synack` · `AppCobaltIO` |
| **Search / OSINT** | `Google` · `Bing` · `DuckDuckGo` · `Torch` · `WaybackMachine` · `Pastebin` · `Checkip` |
| **Social** | `Twitter` · `Facebook` · `LinkedIn` · `Youtube` · `Pandora` |
| **Finance / Work** | `CoinbasePro` · `Paypal` · `TradingView` · `Uber` · `Upwork` |

## Pattern

```ruby
b = PWN::WWW::HackerOne.open(browser_type: :headless,
                             proxy: 'http://127.0.0.1:8080')
PWN::WWW::HackerOne.login(browser_obj: b, username: '...', mfa: '...')
# ... scripted navigation ...
PWN::WWW::HackerOne.logout(browser_obj: b)
PWN::Plugins::TransparentBrowser.close(browser_obj: b)
```

Because traffic goes through TransparentBrowser, you can point `proxy:` at
[BurpSuite](BurpSuite.md) and passively capture every request the automation
makes.

[← Home](Home.md) · [Transparent-Browser](Transparent-Browser.md) ·
[Bounty](Bounty.md)
