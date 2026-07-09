# `PWN::FFI` — Native Calls for DSP & RF

Thin `ffi`-gem bindings to **already-installed** system shared objects. Nothing
is compiled at `gem install` time, nothing shells out. If a `.so` is missing the
module still loads and `.available?` returns `false` so callers fall back to
pure Ruby.

```ruby
PWN::FFI.backends
# => {FFTW: true, HackRF: true, Liquid: true, RTLSdr: true, SoapySDR: true, Volk: true}

PWN::FFI.available?(mod: :Volk)  # => true/false
```

## Modules (`lib/pwn/ffi/*.rb`)

| Module | Shared object | Role |
|---|---|---|
| **`Volk`** | `libvolk` | SIMD kernels: s16→f32 convert, accumulate, \|z\|², scale, dot-product. Backs `Decoder::DSP.unpack_s16le` / `rms_dbfs`. |
| **`Liquid`** | `libliquid` | liquid-dsp: `freqdem` (FM demod), `msresamp_rrrf` (arbitrary resample), Kaiser FIR, DC blocker. Backs `Decoder::DSP.resample` / `dc_block`. |
| **`FFTW`** | `libfftw3f` | Single-precision FFTW3: real & complex 1-D FFTs, magnitude / power-dB helpers for spectrum work. |
| **`HackRF`** | `libhackrf` | Control plane (init/open/tune/rate/gains) + device info for Extrospection `probe_rf` and wideband I/Q capture. |
| **`RTLSdr`** | `librtlsdr` | Device list, tune, gain, blocking `read_sync` of raw u8 I/Q. |
| **`SoapySDR`** | `libSoapySDR` | Enumerate every Soapy-backed front-end (RTL-SDR, HackRF, Airspy, Pluto, UHD, …); API/ABI/lib version. |
| `Stdio` | `libc` | Classic `puts` / `printf` / `scanf` for shellcode / format-string research. |

## Design rules

1. **Thin & optional.** Attach a minimal surface; prefer high-level Ruby wrappers
   (`Liquid.freq_demod`, `Volk.unpack_s16le`) over raw C pointers in call sites.
2. **No install-time compile.** Use the system package (`libvolk-dev`,
   `libliquid-dev`, `libfftw3-dev`, `libhackrf-dev`, …). On hosts without them
   every `.available?` is `false` and pure-Ruby paths keep working.
3. **Namespace hygiene.** `PubFFI = ::FFI` (defined once in `lib/pwn/ffi.rb`)
   avoids the `PWN::FFI` ↔ `::FFI` collision when modules `extend PubFFI::Library`.
4. **Fallbacks in DSP.** `PWN::SDR::Decoder::DSP` probes `PWN::FFI.available?`
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

# RF inventory
PWN::FFI::SoapySDR.list_devices
PWN::FFI::HackRF.info
PWN::FFI::RTLSdr.list_devices
```

## How this accelerates `PWN::SDR::Decoder::*`

Audio-rate protocols (POCSAG, FLEX, Morse, RTTY, APT, …) stay on the GQRX
48 kHz UDP tap and now automatically pick up VOLK/liquid for unpack + resample
hot loops.

Wideband protocols (ADS-B, GSM, LTE, LoRa, WiFi, …) still characterise bursts
from the audio tap via `Base.run_detector`, but can graduate to true
demodulation by:

1. Opening a front-end via `PWN::FFI::RTLSdr` / `HackRF` / `SoapySDR`
2. Reading raw I/Q
3. Running native DSP (`Liquid.freq_demod`, `FFTW.rfft`, VOLK magnitude)
4. Emitting the same Hash frames decoders already JSONL-log

No decoder shells out; Ruby remains the orchestrator.

**See also:** [SDR](SDR.md) · [Hardware](Hardware.md)

[← Home](Home.md)
