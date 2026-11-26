# Contributing

## Repo layout

```text
lib/pwn/                # all namespaces
lib/pwn/setup.rb        # PWN::Setup - doctor/provisioner data tables
lib/pwn/migrate.rb      # PWN::Migrate - ~/.pwn state doctor / auto-migrator
lib/pwn/plugins/        # 107 top-level plugin autoloads
lib/pwn/ai/agent/       # agent core
lib/pwn/ai/agent/tools/ # LLM tool registrations
bin/                    # 56 executables: 53 pwn_* drivers + pwn / pwn-ai / pwn-capd (incl. pwn_setup)
spec/                   # RSpec (incl. conventions_spec)
documentation/          # this wiki + diagrams
```

## Conventions (enforced by `spec/conventions_spec.rb`)

1. Every public module method is `public_class_method def self.name(opts = {})`.
2. Every arg-accepting `def self.*` uses **exactly** `(opts = {})` - no
   positional args, no keyword args.
3. Every module has `self.help` returning a usage string.
4. `# frozen_string_literal: true` at the top of every `.rb`.

## Quality gates

```bash
bundle exec rake  # RSpec, RuboCop, then RDoc; await the actual exit status
```

(`rvmsudo rake` on multi-user RVM installs.)

### Optional native decoder integration tests

The default `bundle exec rake` does not require `proxmark3` or `rtl_433`.
Ruby EM4100/Acurite decoding, native input validation, missing-executable errors,
and cancellation-before-spawn tests always run. Only real native file replays
are excluded with RSpec metadata (`proxmark3_integration`, `rtl433_integration`),
not marked pending or silently passed inside examples.

After installing the optional clients, explicitly enable their fixture tests:

```bash
PWN_TEST_PROXMARK3=1 bundle exec rspec spec/lib/pwn/sdr/decoder/rfid_spec.rb
PWN_TEST_RTL433=1 bundle exec rspec spec/lib/pwn/sdr/decoder/rtl433_spec.rb
# Enable both in the full gate:
PWN_TEST_PROXMARK3=1 PWN_TEST_RTL433=1 bundle exec rake
```

These tests use committed offline amplitude/IQ captures, not RF hardware.
Opt-in runs fail if their client is unavailable or cannot decode the reference;
installed versions can differ in supported protocols and output. Fixture provenance
and tested versions are recorded in `spec/fixtures/sdr/rfid/README.md` and
`spec/fixtures/sdr/rtl433/README.md`. Neither client is installed by the test suite.

At runtime, `RFID.decode(mode: :fdxb_pm3, ...)` and
`RTL433.decode(mode: :native, ...)` raise an actionable `IOError` when their
executable is missing, suggesting installation or an explicit `executable:` path.
An already-true `stop:` callback raises cancellation before spawning either client.
Invalid inputs still raise `ArgumentError`; native decoding never silently falls
back to another decoder or a detector.

### Optional Liquid and radare2 integration tests

Native Liquid DSP examples and the real radare2 JSON replay are also explicit
opt-ins, even when the backends happen to be installed. The default gate excludes
`liquid_integration` and `radare2_integration` metadata rather than marking tests
pending. Liquid interface checks, missing-library errors, pure-Ruby DSP fallback,
radare2 argument validation, and binutils fallback coverage still run by default.
The binary fallback tests require the existing binutils tools and `/bin/true`.

```bash
PWN_TEST_LIQUID=1 bundle exec rspec spec/lib/pwn/ffi/liquid_spec.rb
PWN_TEST_RADARE2=1 bundle exec rspec spec/lib/pwn/plugins/binary_analysis_spec.rb
# Enable both in the full gate:
PWN_TEST_LIQUID=1 PWN_TEST_RADARE2=1 bundle exec rake
```

Liquid opt-in requires the liquid-dsp shared library (`libliquid`) visible to the
dynamic loader. Radare2 opt-in requires `r2` and a C compiler named `cc` on PATH.
The radare2 example compiles a small unstripped C fixture in a temporary directory,
checks real JSON disassembly for its known `main` symbol, and removes the fixture
afterward. It does not assume the host's stripped `/bin/true` has a discoverable
`main`. Opt-in runs fail with installation guidance when a prerequisite is absent;
they never skip or accept a degraded backend as native success. The tests install
nothing and require no radio hardware or network access.

### Optional FFTW, Volk, and SDR shared-library tests

The default gate also excludes real FFTW/Volk computations and radio-library
integration checks, regardless of what is installed. Missing-library behavior,
mocked device inventory and stream lifecycle tests, and Ruby DSP fallbacks run
without these shared libraries and produce no pending examples.

| Environment opt-in | RSpec metadata | Loader prerequisite / coverage |
| --- | --- | --- |
| `PWN_TEST_FFTW=1` | `fftw_integration` | `libfftw3f`; native impulse FFT |
| `PWN_TEST_VOLK=1` | `volk_integration` | `libvolk`; native conversion, accumulation, DSP dispatch |
| `PWN_TEST_RTL_SDR=1` | `rtl_sdr_integration` | `librtlsdr`; binding resolution only, no USB scan |
| `PWN_TEST_ADALM_PLUTO=1` | `adalm_pluto_integration` | Compatible `libiio`; library version only |
| `PWN_TEST_SOAPY_SDR=1` | `soapy_sdr_integration` | `libSoapySDR`; library/API version only |
| `PWN_TEST_HACK_RF=1` | `hack_rf_integration` | `libhackrf`; library version only |

For example:

```bash
PWN_TEST_FFTW=1 bundle exec rspec spec/lib/pwn/ffi/fftw_spec.rb
PWN_TEST_VOLK=1 bundle exec rspec spec/lib/pwn/ffi/volk_spec.rb spec/lib/pwn/sdr/decoder/dsp_spec.rb
PWN_TEST_ADALM_PLUTO=1 bundle exec rspec spec/lib/pwn/ffi/adalm_pluto_spec.rb
PWN_TEST_LIQUID=1 bundle exec rspec spec/lib/pwn/ffi/liquid_spec.rb spec/lib/pwn/sdr/decoder/dsp_spec.rb
```

Each opt-in fails with installation guidance if its library cannot load. Native
DSP integration tests assert real backend dispatch, not just a matching fallback.
None of these library opt-ins opens, tunes, receives from, or transmits through a
radio. Pluto URI discovery is mocked, including scan cleanup.

Actual RTL-SDR USB enumeration has a separate `rtl_sdr_hardware` tag, enabled
only by `PWN_TEST_RTL_SDR_HARDWARE=1`. It requires a connected RTL-SDR and USB
permissions, and fails on an empty inventory. Do not enable it in unattended
upgrade gates; library opt-ins do not enable hardware tests. It performs inventory
only, not tuning or reception. The test suite installs no dependencies.

## Adding a plugin

1. `lib/pwn/plugins/my_thing.rb` following the conventions above.
2. Autoload entry in `lib/pwn/plugins.rb`.
3. `spec/lib/pwn/plugins/my_thing_spec.rb`.
4. Optional `bin/pwn_my_thing` driver (see [Drivers](Drivers.md)).
5. Optional agent tool in `lib/pwn/ai/agent/tools/` (see
   [Agent Tool Registry](Agent-Tool-Registry.md)).
6. **If it needs a native gem or external binary**, add **one row** to
   `PWN::Setup::NATIVE_GEMS` or `PWN::Setup::TOOLCHAIN` in
   `lib/pwn/setup.rb` (with `apt:`/`dnf:`/`pacman:`/`brew:`/`port:` package
   names + the `plugins:` it unlocks) and, if it belongs in a capability
   set, reference it from `PWN::Setup::PROFILES`. That single edit makes
   `pwn setup` install it on every OS and every install path (gem, git,
   Docker, Packer, Vagrant, CI). **Do not** add a new bash provisioner.
7. **If it persists a new file under `~/.pwn/`**, add **one entry** to
   `PWN::Migrate::STATE_FILES` in `lib/pwn/migrate.rb` (owner, kind,
   `:fix` strategy, shallow verifier). If the change breaks *existing*
   files, bump `PWN::Migrate::SCHEMA_VERSION` and append an idempotent
   lambda to `PWN::Migrate::MIGRATIONS`. `pwn setup --migrate --fix`
   then heals every user's `~/.pwn` on upgrade.
8. Update [Plugins.md](Plugins.md) and, if it changes a data flow, the
   relevant `.dot` in `documentation/diagrams/dot/` → `./build.sh`.

## Commit / release

`./git_commit.sh` bumps `PWN::VERSION`, regenerates
`third_party/pwn_rdoc.jsonl`, runs the gates, and pushes.

[← Home](Home.md)

## Documentation after code changes

When you change code under `/opt/pwn`:

1. Clear RuboCop on the paths you touched (`bundle exec rubocop -a <paths>`).
2. Run the test suite (`bundle exec rake`) and fix failures.
3. Only then refresh user docs: `README.md`, `documentation/*`, and
   `documentation/diagrams/dot/*.dot` (rebuild with `documentation/diagrams/build.sh`).
4. Keep user-facing markdown in plain US English (ASCII hyphens, no marketing
   filler, no internal agent backlog codes).

Do not commit doc refreshes while lint or tests are still red.

### Optional combo.nation MCP integration tests

The default `bundle exec rake` does not launch `/opt/combo.nation/combo.nation`.
Protocol, menu-ID, and hardware-gate coverage uses an in-process fake MCP server.
The real stdio binary is excluded with `combo_nation_mcp` metadata unless:

```bash
PWN_TEST_COMBO_NATION_MCP=1 bundle exec rspec spec/lib/pwn/ai/mcp/combo_nation_spec.rb
```

That opt-in never passes `--mcp-allow-hardware` and never opens devices. It fails
if the executable is missing rather than skipping pending.

