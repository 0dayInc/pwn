# `PWN::Plugins::BurpSuite` ⭐

The **preferred** web proxy / scanner in PWN (see
[Burp vs ZAP](Diagrams.md#burp--vs-zap-selection)). Wraps Burp Suite
Professional's headless mode + REST API.

![Web application testing](diagrams/web-application-testing.svg)

## Configure

```yaml
# ~/.pwn/config.yml
burp:
  jar: /opt/burpsuite_pro/burpsuite_pro.jar
  api_key: <REST-API-KEY>
  bind_ip: 127.0.0.1
  proxy_port: 8080
  api_port: 1337
```

## Core methods

```ruby
burp = PWN::Plugins::BurpSuite.start(headless: true)

# drive traffic through it
b = PWN::Plugins::TransparentBrowser.open(
      browser_type: :headless, proxy: 'http://127.0.0.1:8080')
b[:browser].goto 'https://target'

# scan
PWN::Plugins::BurpSuite.active_scan(burp_obj: burp,
                                    target_url: 'https://target')
issues = PWN::Plugins::BurpSuite.get_scan_issues(burp_obj: burp)

PWN::Plugins::BurpSuite.stop(burp_obj: burp)
```

## CLI drivers

- `pwn_burp_suite_pro_active_scan -t URL -o out/`
- `pwn_burp_suite_pro_active_rest_api_scan` — pure REST, no JVM spawn

## Why preferred over ZAP

Richer scanner, larger BApp ecosystem, more reliable REST surface. `Zaproxy`
remains as an OSS fallback and is API-compatible enough that swapping is a
one-line change.

[← Home](Home.md) · [Transparent-Browser](Transparent-Browser.md) ·
[Plugins](Plugins.md)
