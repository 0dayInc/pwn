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

[← Home](Home.md)
