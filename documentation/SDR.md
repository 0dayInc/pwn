# `PWN::SDR` — Software-Defined Radio & RF

![SDR flow](diagrams/sdr-radio-flow.svg)

## Modules  (`lib/pwn/sdr/*.rb`)

| Module | Purpose |
|---|---|
| **`GQRX`** | Remote-control a running GQRX instance over TCP: tune, set demod, squelch, record, `get_spectrum_snapshot` (pure-Ruby FFT — median noise floor, DC/LO-leakage null, band-edge guard), `fast_scan_range` (band-plan radio settings + panoramic FFT + **post-FFT edge/peak refine** for exact channel centres; schema-parity with `scan_range`) |
| `FlipperZero` | Serial control of Flipper (sub-GHz, NFC, IR, iButton) |
| `RFIDler` | 125 kHz RFID reader/emulator |
| `SonMicroRFID` | SM130 13.56 MHz reader |
| `FrequencyAllocation` | ITU/FCC band-plan lookup — "what lives at 433.92 MHz?" |
| **`Decoder::*`** | 20 protocol demodulators/decoders — `ADSB APT Bluetooth DECT FLEX GPS GSM Iridium LoRa LTE Morse P25 Pager POCSAG RDS RFID RTL433 RTTY WiFi ZigBee` |

## CLI

```bash
# FFT sweep — SNR-gated peak detection, then edge/peak refine for exact centres
pwn_gqrx_scanner --scan-ranges 430.000.000-440.000.000 --fft-scan \
                 --avg 8 --min-snr-db 10 --capture-secs 0.10
# Skip refine (pure panoramic): add --no-refine

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


## Native DSP acceleration (`PWN::FFI`)

`PWN::SDR::Decoder::DSP` transparently accelerates hot paths when the host
has the matching shared libraries:

| DSP method | Backend | Library |
|---|---|---|
| `unpack_s16le` | `PWN::FFI::Volk` | libvolk |
| `resample` | `PWN::FFI::Liquid` | libliquid |
| `dc_block(m:)` | `PWN::FFI::Liquid` | libliquid |
| `rms_dbfs` (≥64) | `PWN::FFI::Volk` | libvolk |

```ruby
PWN::FFI.backends
# => {FFTW: true, HackRF: true, Liquid: true, RTLSdr: true, SoapySDR: true, Volk: true}

# Force pure-Ruby (e.g. for tests / A/B)
PWN::SDR::Decoder::DSP.native = false
```

Front-end inventory & raw I/Q capture:

```ruby
PWN::FFI::SoapySDR.list_devices
# => [{driver: "hackrf", label: "HackRF Pro #0 …", serial: "…"}, …]

PWN::FFI::RTLSdr.list_devices
dev = PWN::FFI::HackRF.open
PWN::FFI::HackRF.configure(device: dev, freq_hz: 433_920_000, rate_hz: 10e6)
PWN::FFI::HackRF.close(device: dev)
```

See [FFI](FFI.md) for the full binding surface and design rules.

## RF ↔ Extrospection

The AI agent is RF-aware. Two layers:

| Layer | Call | Role |
|---|---|---|
| **Passive inventory** | `extro_snapshot(sections: [:rf])` → `probe_rf` | RTL-SDR / HackRF / SoapySDR / Flipper / GQRX-socket presence |
| **Active sense organ** | **`extro_rf_tune(freq: "101.1")`** | Connect to a *running* GQRX remote-control socket, tune, demod, measure strength, sample RDS → `now_playing` / `station` |

```ruby
# record a recon finding
extro_observe(source: 'gqrx', category: :rf, target: '433.920MHz',
              data: 'peak -34.2 dBFS bw=200k FSK — likely garage remote')

# ask the radio a question (RDS on FM broadcast)
extro_rf_tune(freq: '101.1')
# → { ok:true, freq:"101.1 MHz", strength_dbfs:-2.8, station:"X96",
#     now_playing:"Mr. Brightside by The Killers", rds:{pi,ps_name,radiotext}, … }
# → observe(category: :rf, ttl: 300)   # songs are ephemeral
```

RDS sampling is `PWN::SDR::Decoder::RDS.sample` (non-interactive Hash). The
TTY spinner (`Decoder::RDS.decode`) stays the human path used by
`GQRX.init_freq(decoder: :rds)`. Agents and cron use `extro_rf_tune` /
`.sample(interactive: false)`.

`extro_correlate` then cross-references `:rf` observations against missing
`RF_BINS` / unplugged hardware so the agent can tell "no signal" from "no
dongle" / "GQRX remote control is down".

**See also:** [Hardware](Hardware.md) · [Extrospection](Extrospection.md)

[← Home](Home.md)
