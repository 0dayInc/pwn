# Transparent Browser

`PWN::Plugins::TransparentBrowser` — powerful browser automation (headless + visible) built on top of Selenium / Watir / Ferrum / similar.

## Primary Uses

- Web spidering / crawling
- JavaScript-heavy application interaction
- Automated form submission, auth flows
- Screenshotting, DOM inspection
- Proxied browsing (pairs excellently with BurpSuite)

## Example Calls

```ruby
browser = PWN::Plugins::TransparentBrowser.open_browser(
  browser_type: :chrome,
  proxy: 'http://127.0.0.1:8080'   # Burp
)
browser.goto 'https://target.example.com'
# ... interact ...
browser.close
```

Agent-friendly.

## See Also

- [Burp Suite](BurpSuite.md)
- [Plugins](Plugins.md)

[[Diagrams]]
