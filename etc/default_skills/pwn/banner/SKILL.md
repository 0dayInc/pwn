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

Static banners and pure, PWN-branded retro ASCII/color loops: falling_blocks, snake, pacman, asteroids, galaga and frogger. mini_frame returns fresh rows on a borderless canvas; use equal width and height (5..16) for complete square artwork. Dimensions clamp to 0..16 (colored blocks/Pac-Man/Galaga/Frogger: 0..64). Set branding: false for an unbranded pane with the wordmark row reclaimed for play; tiny panes then stay blank. The caller samples mini_names once per session and advances the explicit frame index every mini_frame_seconds(name:) (0.05 for Asteroids/Galaga, 0.1 otherwise). mini_cells replays 1800 seeded gameplay frames (MINI_FRAME_COUNT); mini_frame retains its legacy 60-frame ASCII loop. Inactive panes use seeded demos; MiniGame supplies caller-owned playable state. mini_cells uses local Random.new with seed 73 by default; callers may keep a different integer seed per session. Six immutable replays are cached. Tetrominoes stack and clear; snake pursues food and grows; Pac-Man eats pellets in connected mazes with chasing ghosts, energizers, recovery and new levels. Blocks use horizontal half-cells with independent foreground/background colors, filling the pane below PWN (up to 64 cells). Other games retain quadrant pixels; decorative snake stays centered with food/head color priority. White line-clear flashes and game-over/reset wipes are intentional. Pac-Man and ghosts occupy one cell each so even eight-cell panes retain internal walls and corridors. Directional mouths and compact ghost glyphs trade eye detail for maze geometry; spanning-tree mazes vary each round. Galaga has formations, dives, hostile fire, explosions and advancing waves; arrows move and Space fires. Frogger arrows hop through moving traffic and onto carrying logs to fill goals, recover from deaths and advance levels. Both start on input, run automatic demos when inactive and retain the UI owner. Legacy name: :pong remains accepted by direct APIs but is not selectable. Asteroids uses filled cyan ships on a 2x4 Braille raster, sparse small white rocks, yellow shots and red thrust; wrapped collisions split real rocks. Static Banner modules autoload only when needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

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
