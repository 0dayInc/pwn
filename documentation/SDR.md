# `PWN::SDR` — Software-Defined Radio & RF

![SDR flow](diagrams/sdr-radio-flow.svg)

## Modules  (`lib/pwn/sdr/*.rb`)

| Module | Purpose |
|---|---|
| **`GQRX`** | Remote-control a running GQRX instance over TCP: tune, set demod, squelch, record, `get_spectrum_snapshot` (pure-Ruby FFT — median noise floor, DC/LO-leakage null, band-edge guard), `fast_scan_range` |
| `FlipperZero` | Serial control of Flipper (sub-GHz, NFC, IR, iButton) |
| `RFIDler` | 125 kHz RFID reader/emulator |
| `SonMicroRFID` | SM130 13.56 MHz reader |
| `FrequencyAllocation` | ITU/FCC band-plan lookup — "what lives at 433.92 MHz?" |
| **`Decoder::*`** | 20 protocol demodulators/decoders — `ADSB APT Bluetooth DECT FLEX GPS GSM Iridium LoRa LTE Morse P25 Pager POCSAG RDS RFID RTL433 RTTY WiFi ZigBee` |

## CLI

```bash
# FFT sweep — SNR-gated peak detection (no false-positive flood)
pwn_gqrx_scanner --start 430e6 --stop 440e6 --fft-scan \
                 --avg 8 --min-snr-db 10 --capture-secs 0.10

# Classic iterative S-meter scan
pwn_gqrx_scanner --start 118e6 --stop 137e6 --step 12.5e3 \
                 --strength-lock -60 --audio-gain-db 6
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

## RF ↔ Extrospection

The AI agent is RF-aware. `extro_snapshot(sections: [:rf])` runs `probe_rf`
(RTL-SDR / HackRF / SoapySDR / Flipper / GQRX-socket inventory) and RF signal
intel is recorded with a first-class `:rf` observation category:

```ruby
extro_observe(source: 'gqrx', category: :rf, target: '433.920MHz',
              data: 'peak -34.2 dBFS bw=200k FSK — likely garage remote')
```

`extro_correlate` then cross-references `:rf` observations against missing
`RF_BINS` / unplugged hardware so the agent can tell "no signal" from "no
dongle".

**See also:** [Hardware](Hardware.md) · [Extrospection](Extrospection.md)

[← Home](Home.md)
