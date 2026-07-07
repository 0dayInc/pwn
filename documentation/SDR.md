# `PWN::SDR` — Software-Defined Radio & RF

![SDR flow](diagrams/sdr-radio-flow.svg)

## Modules  (`lib/pwn/sdr/*.rb`)

| Module | Purpose |
|---|---|
| **`GQRX`** | Remote-control a running GQRX instance over TCP: tune, set demod, squelch, record, `get_spectrum_snapshot` (pure-Ruby FFT), scan ranges |
| `FlipperZero` | Serial control of Flipper (sub-GHz, NFC, IR, iButton) |
| `RFIDler` | 125 kHz RFID reader/emulator |
| `SonMicroRFID` | SM130 13.56 MHz reader |
| `FrequencyAllocation` | ITU/FCC band-plan lookup — "what lives at 433.92 MHz?" |
| `Decoder::*` | Demodulator/protocol helpers |

## CLI

```bash
pwn_gqrx_scanner --start 430e6 --stop 440e6 --step 12.5e3 --mode fast
pwn_gqrx_scanner --start 118e6 --stop 137e6 --mode iterative --squelch -60
```

See skill `pwn_gqrx_scanner_fast_vs_iterative_scanning` for the trade-off.

## REPL example

```ruby
g = PWN::SDR::GQRX.connect(host: '127.0.0.1', port: 7356)
PWN::SDR::GQRX.set_freq(gqrx_sock: g, freq: 433_920_000)
PWN::SDR::GQRX.set_demod(gqrx_sock: g, demod: 'AM')
snap = PWN::SDR::GQRX.get_spectrum_snapshot(gqrx_sock: g)
PWN::SDR::FrequencyAllocation.lookup(freq: 433_920_000)
# => { band: 'ISM 433', typical: ['garage doors', 'weather stations', …] }
```

Record signal intel with `extro_observe(source: 'gqrx', category: 'recon', …)`.

**See also:** [Hardware](Hardware.md) · [Extrospection](Extrospection.md)

[← Home](Home.md)
