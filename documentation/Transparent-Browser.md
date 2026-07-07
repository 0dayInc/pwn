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

[← Home](Home.md) · [BurpSuite](BurpSuite.md) · [WWW](WWW.md)
