# `PWN::FFI` - Native Calls for DSP & RF Front-Ends

Thin `ffi`-gem bindings to **already-installed** system shared objects. Nothing
is compiled at `gem install` time, nothing shells out. If a `.so` is missing the
module still loads and `.available?` returns `false` so callers fall back to
pure Ruby.

```ruby
PWN::FFI.backends
# => {AdalmPluto: true, FFTW: true, HackRF: true, Liquid: true,
#     RTLSdr: true, SoapySDR: true, Volk: true}

PWN::FFI.available?(mod: :Volk)  # => true/false
```

## Install the shared objects

```bash
pwn setup --profile sdr   # rtl-sdr, hackrf, libiio/libad9361, SoapySDR,
                          # libvolk, libliquid, libfftw3, libsndfile, libusb
```

`pwn setup` (the [doctor](Installation.md)) reports each `PWN::FFI` backend
as `ok` / `MISSING` and knows the correct package name on `apt` / `dnf` /
`pacman` / `brew` / `port`.

## Modules (`lib/pwn/ffi/*.rb`)

| Module | Shared object | Role |
|---|---|---|
| **`Volk`** | `libvolk` | SIMD kernels: s16 to f32 convert, accumulate, \|z\|^2, scale, dot-product. Backs `Decoder::DSP.unpack_s16le` / `rms_dbfs`. |
| **`Liquid`** | `libliquid` | liquid-dsp: `freqdem` (FM demod), `msresamp_rrrf` (arbitrary resample), Kaiser FIR, DC blocker. Backs `Decoder::DSP.resample` / `dc_block`. |
| **`FFTW`** | `libfftw3f` | Single-precision FFTW3: real & complex 1-D FFTs, magnitude / power-dB helpers for spectrum work. |
| **`RTLSdr`** | `librtlsdr` | Device list, open/tune/gain, blocking `read_sync` of raw cu8 I/Q. |
| **`HackRF`** | `libhackrf` | Open/tune/rate/gains + **callback RX streaming** (`start_rx`/`read_sync`/`stop_rx`/`capture`) of raw cs8 I/Q. |
| **`AdalmPluto`** | `libiio` (+ `libad9361`) | ADALM-Pluto (ad9361-phy). `open`/`configure`/`start_rx`/`read_sync`/`stop_rx`/`capture` of cs16 I/Q; USB or `ip:192.168.2.1`. |
| **`SoapySDR`** | `libSoapySDR` | Enumerate every Soapy-backed front-end (RTL-SDR, HackRF, Airspy, Pluto, LimeSDR, UHD, ...) **and** stream cs16 I/Q from any of them (`open`/`configure`/`start_rx`/`read_sync`/`stop_rx`/`close`). |
| `Stdio` | `libc` | Classic `puts` / `printf` / `scanf` for shellcode / format-string research. |

## Design rules

1. **Thin & optional.** Attach a minimal surface; prefer high-level Ruby wrappers
   (`Liquid.freq_demod`, `Volk.unpack_s16le`) over raw C pointers in call sites.
2. **No install-time compile.** Use the system package (`libvolk-dev`,
   `libliquid-dev`, `libfftw3-dev`, `libhackrf-dev`, `libiio-dev`, ...). Install
   them all with **`pwn setup --profile sdr`** (see [Installation](Installation.md)).
   On hosts without them every `.available?` is `false` and pure-Ruby paths
   keep working.
3. **Namespace hygiene.** `PubFFI = ::FFI` (defined once in `lib/pwn/ffi.rb`)
   avoids the `PWN::FFI` vs `::FFI` collision when modules `extend PubFFI::Library`.
4. **Uniform front-end contract.** Every hardware binding exposes the same
   verbs: `available?`, `open`, `configure`, `start_rx`, `read_sync`, `stop_rx`,
   `close`, plus a one-shot `capture` where practical. `Decoder::Base.run_iq`
   only depends on that contract, not on any specific radio.
5. **Fallbacks in DSP.** `PWN::SDR::Decoder::DSP` probes `PWN::FFI.available?`
   and rescues into pure Ruby. Toggle globally with
   `PWN::SDR::Decoder::DSP.native = false`.

## REPL examples

```ruby
# SIMD-unpack GQRX audio
raw = udp_chunk  # s16le bytes
samples = PWN::FFI::Volk.unpack_s16le(data: raw)

# FM demod of complex baseband
audio = PWN::FFI::Liquid.freq_demod(iq: interleaved_iq, kf: 0.5)

# Real FFT power spectrum
db = PWN::FFI::FFTW.rfft_power_db(samples: audio, n: 4096)

# RF front-end inventory
PWN::FFI::SoapySDR.list_devices
PWN::FFI::HackRF.info
PWN::FFI::RTLSdr.list_devices
PWN::FFI::AdalmPluto.list_uris

# Stream raw I/Q from ANY Soapy-backed device
h = PWN::FFI::SoapySDR.open(args: 'driver=rtlsdr')
PWN::FFI::SoapySDR.configure(handle: h, freq_hz: 929_612_500, rate_hz: 2_048_000)
PWN::FFI::SoapySDR.start_rx(handle: h)
data = PWN::FFI::SoapySDR.read_sync(handle: h)   # cs16le interleaved I/Q
PWN::FFI::SoapySDR.close(handle: h)

# One-shot HackRF capture
iq = PWN::FFI::HackRF.capture(freq_hz: 1_090_000_000, rate_hz: 2_000_000, samples: 262_144)
```

## True-air decode: how this drives `PWN::SDR::Decoder::*`

Every decoder module now has a **true over-the-air I/Q path** via
`PWN::SDR::Decoder::Base.run_iq`, which:

1. Calls `Base.resolve_iq_source(source: :auto)` to pick the first working
   front-end in order `:file` -> `:rtlsdr` -> `:adalm_pluto` -> `:hackrf` ->
   `:soapy` (or a forced `:source`).
2. Streams raw I/Q via the uniform `read_sync` contract above.
3. Unpacks (`cu8`/`cs8`/`cs16`) and either hands complex samples to
   `demod#feed_iq(iq, rate:)` or FM-demodulates first and calls
   `demod#feed(audio)` for narrowband protocols.
4. Emits the same JSONL-logged Hash frames every decoder already produces.
5. Falls back to `Base.run_detector` (energy characterizer) when no hardware
   or capture file is present, so the operator still gets structured output.

| Decoder | Air path | I/Q entry point |
|---|---|---|
| ADSB, Bluetooth, DECT, GPS, GSM, Iridium, LoRa, LTE, P25, RFID, RTL433, WiFi, ZigBee | `run_iq` (wideband) | `#feed_iq(iq, rate:)` |
| APT, FLEX, Morse, Pager, POCSAG, RTTY | `run_iq(fm_demod: true)` or `run_native` (GQRX 48 kHz UDP) | `#feed(audio)` |
| RDS | GQRX built-in RDS decoder (`RDS.sample`) | n/a |

No decoder shells out; Ruby remains the orchestrator.

**See also:** [SDR](SDR.md) - [Hardware](Hardware.md)

[<- Home](Home.md)
