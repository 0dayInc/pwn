---
name: pwn-banner
description: Drive PWN::Banner from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner
  source: pwn/banner.rb
---

# PWN::Banner

Static banners and pure, PWN-branded retro ASCII loops: falling_blocks, snake, and pong. mini_frame returns fresh rows on a borderless canvas; use equal width and height (5..16) for complete square artwork. Dimensions clamp to 0..16, with smaller panes degrading to a wordmark. The caller samples mini_names once per session and advances the explicit frame index every MINI_FRAME_SECONDS (0.1), wrapping at MINI_FRAME_COUNT (60). These are decorative animations, not interactive games or telemetry. Static Banner modules autoload only when needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::Banner` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner.help
PWN::Banner.mini_frame(opts)
```

## Public methods

- `mini_frame`
- `mini_names`
- `get`
- `welcome`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/banner.rb`

## Verification

`PWN::Banner.respond_to?(:mini_frame)` after the
module is loaded. Read the source for parameter names.
