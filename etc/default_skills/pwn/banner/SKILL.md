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

Static banners and pure, PWN-branded retro ASCII/color loops: falling_blocks, snake, pong, and asteroids. mini_frame returns fresh rows on a borderless canvas; use equal width and height (5..16) for complete square artwork. Dimensions clamp to 0..16 (colored blocks: 0..64). Set branding: false for an unbranded pane with the wordmark row reclaimed for play; tiny panes then stay blank. The caller samples mini_names once per session and advances the explicit frame index every mini_frame_seconds(name:) (0.05 for Pong/Asteroids, 0.1 otherwise). mini_cells replays 1800 seeded gameplay frames (MINI_FRAME_COUNT); mini_frame retains its legacy 60-frame ASCII loop. These are decorative game simulations, not interactive games or telemetry. mini_cells uses local Random.new with seed 73 by default; callers may keep a different integer seed per session. Six immutable replays are cached. Tetrominoes stack and clear; snake pursues food and grows; Pong rallies include imperfect paddle tracking, misses and score pips between serves. Blocks use horizontal half-cells with independent foreground/background colors, filling the pane below PWN (up to 64 cells). Other games retain quadrant pixels; snake stays centered with food/head color priority. White line-clear flashes and game-over/reset wipes are intentional. Pong uses half-cell motion and one-cell-high paddles without speeding up play. Asteroids uses five-pixel cyan arrowheads on a half-cell grid, sparse small white rocks, yellow shots and red thrust; wrapped collisions split real rocks. Static Banner modules autoload only when needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

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
- `mini_frame_seconds`
- `mini_cells`
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
