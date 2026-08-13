# `PWN::WWW` - Site-Specific Browser Automations

22 modules, each a scripted [`TransparentBrowser`](Transparent-Browser.md)
session against a real site: log in, navigate, scrape, submit.
Source: `lib/pwn/www/*.rb`.

## Modules

| Category | Modules |
|---|---|
| **Bug bounty** | `HackerOne` · `BugCrowd` · `Synack` · `AppCobaltIO` |
| **Code hosts** | `GitHub` |
| **Search / OSINT** | `Google` · `Bing` · `DuckDuckGo` · `Torch` · `WaybackMachine` · `Pastebin` · `Checkip` |
| **Social** | `Twitter` · `Facebook` · `LinkedIn` · `Youtube` · `Pandora` |
| **Finance / Work** | `CoinbasePro` · `Paypal` · `TradingView` · `Uber` · `Upwork` |

## Pattern

```ruby
b = PWN::WWW::GitHub.open(browser_type: :headless,
                         proxy: 'http://127.0.0.1:8080')
PWN::WWW::GitHub.login(
  browser_obj: b,
  username: '...',
  password: '...',
  mfa: '123456'
)
# scripted navigation
PWN::WWW::GitHub.logout(browser_obj: b)
PWN::Plugins::TransparentBrowser.close(browser_obj: b)
```

`login` takes `username`, `password`, and an MFA token (`mfa:` or
`mfa_token:`). Pass the token string to stay non-interactive, or set
`mfa: true` to prompt. The browser stays on the post-auth GitHub session
when the method returns.

Because traffic goes through TransparentBrowser, you can point `proxy:` at
[BurpSuite](BurpSuite.md) and passively capture every request the automation
makes.

[← Home](Home.md) · [Transparent-Browser](Transparent-Browser.md) ·
[Bounty](Bounty.md)
