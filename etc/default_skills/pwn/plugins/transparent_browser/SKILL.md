---
name: pwn-plugins-transparentbrowser
description: Drive PWN::Plugins::TransparentBrowser from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::TransparentBrowser
  source: pwn/plugins/transparent_browser.rb
---

# PWN::Plugins::TransparentBrowser

This plugin rocks. Chrome, Firefox, headless, REST Client, all from the comfort of one plugin. Proxy support (e.g. Burp Suite Professional) is completely available for all browsers except for limited functionality within IE (IE has interesting protections in place to prevent this). This plugin also supports taking screenshots :)

## When to use

Call `PWN::Plugins::TransparentBrowser` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/transparent_browser.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::TransparentBrowser.help
PWN::Plugins::TransparentBrowser.open(opts)
```

## Public methods

- `open`
- `dump_links`
- `find_elements_by_text`
- `type_as_human`
- `console`
- `view_dom_mutations`
- `hide_dom_mutations`
- `update_about_config`
- `list_tabs`
- `jmp_tab`
- `new_tab`
- `close_tab`
- `dom`
- `get_page_state`
- `devtools_websocket_messages`
- `debugger`
- `get_targets`
- `breakpoint_locations`
- `step`
- `toggle_devtools`
- `jmp_devtools_panel`
- `close`
- `evidence`
- `authors`
- `help`
- `evidence!`

## Source

`pwn/plugins/transparent_browser.rb`

## Verification

`PWN::Plugins::TransparentBrowser.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
