---
name: pwn-plugins-android
description: Drive PWN::Plugins::Android from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Android
  source: pwn/plugins/android.rb
---

# PWN::Plugins::Android

PWN module used to interact w/ Android Devices

## When to use

Call `PWN::Plugins::Android` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/android.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Android.help
PWN::Plugins::Android.adb_net_connect(opts)
```

## Public methods

- `adb_net_connect`
- `adb_sh`
- `adb_push`
- `adb_pull`
- `take_screenshot`
- `screen_record`
- `list_installed_apps`
- `dumpsys`
- `open_app`
- `find_hidden_codes`
- `swipe`
- `input`
- `input_special`
- `close_app`
- `invoke_event_listener`
- `adb_net_disconnect`
- `apk_pipeline`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/android.rb`

## Verification

`PWN::Plugins::Android.respond_to?(:adb_net_connect)` after the
module is loaded. Read the source for parameter names.
