# `PWN::Banner` - Startup Art

15 ANSI banners; one is picked at random every time the REPL starts. Purely
cosmetic, entirely necessary.

`Anon · Bubble · Cheshire · CodeCave · DontPanic · ForkBomb · FSociety ·
JmpEsp · Matrix · Ninja · OffTheAir · Pirate · Radare2 · Radare2AI ·
WhiteRabbit`

```ruby
puts PWN::Banner::Matrix.get
welcome-banner          # REPL command: redraw a random one
```

Add your own: drop a module in `lib/pwn/banner/` implementing `self.get`.

## pwn-ai startup pane

The curses console starts with a white miniature derived directly from
`PWN::Banner::WhiteRabbit.get`, without its dedication or wordmark. The full
banner remains unchanged. The rabbit is centered and aspect-contained in the
current pane: small panes use area-filtered 3×6 character strokes packed into
ordinary 2×4 Braille text dots; when the original ASCII fits, it is displayed
verbatim, centered without enlargement. This assumes typical 1:2 terminal cells.
Small panes lose punctuation detail, and Braille dot spacing depends on the font;
physically tiny panes cannot retain a recognizable rabbit. No image protocol,
image file, graphics probe or runtime image library is used.

No games or replays are computed until the animation pane first receives focus
via Ctrl+T/Ctrl+X. That enables games for the console lifetime. Ctrl+G cycles
games while focused; leaving the pane keeps the existing automatic animation,
not the startup rabbit. Resizing, modal input priority and the mission draft
retain their existing behavior. Monochrome terminals keep the same geometry.

[← Home](Home.md)
