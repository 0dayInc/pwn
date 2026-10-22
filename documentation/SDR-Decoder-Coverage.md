# SDR decoder coverage and acceptance matrix

**Verdict: the “full protocol decode in all modules” requirement is not complete.**
A valid frame in one mode is useful implementation, not full coverage of the named protocol family.

Historical protocol audit snapshot: **2026-09-09T20:20:02.204954+00:00**.
The current documentation review reconfirmed 24 registry aliases / 21 modules
and the GQRX forwarding correction below. Other mode-level acceptance rows retain
their historical evidence boundaries; no live RF or new conformance run is implied.
Temporary audit files cited below are not shipped evidence and may expire.

Original audit context: This is a working-tree audit, not a release or a claim about HEAD. Other workers were changing decoders during review; the exact reviewed bytes are identified by SHA-256 in `/tmp/pwn-decoder-completion-matrix.json`, with retained text in `/tmp/pwn-decoder-audit-snapshot.json`. Later edits require delta review. The audit itself changes documentation only; it does not stage, commit, alter decoder code, or endorse unrelated pre-existing staged files.

## Inventory and evidence contract

Runtime enumeration of `PWN::SDR::Decoder::REGISTRY` yields **24 keys, 21 unique protocol modules**, plus shared **Base and DSP**. All **50 decoder/namespace source and spec files** were read, including `base_iq_spec.rb`, `dsp_native_spec.rb`, namespace registry and namespace spec. The machine ledger deduplicates file paths and records module-to-source/spec/aliases, acceptance IDs, supported and missing layers, rates, security/native boundaries and reviewed hashes. Ancillary fixture/build/integration material is recorded separately; merely hashing a binary fixture does not mean it was decoded.

Evidence labels in this document:

- **Implemented/partial:** path exists in the reviewed code, with the exact mode boundary below. This is not a passing conformance assertion.
- **Spec evidence:** the named spec actually asserts the described behavior; a reviewed spec is not an execution result.
- **Independent bits:** expected bytes/fields originate outside the receiver. Synthetic modulation remains synthetic even if the bits are independent.
- **Independent generated IQ:** another transmitter implementation generated the waveform. This demonstrates interoperability for that waveform, not over-air sensitivity.
- **Received IQ / synchronized symbols:** distinguish raw RF samples from already synchronized/channelized samples; the latter cannot validate missing acquisition/tracking.
- **Open:** an implementation, standard clause, field family, unsupported mode, missing oracle or measurement remains outstanding. An explicit rejection is good failure behavior, not fulfillment.

### Meaning of full and finite scope

The requirement is read as receive-side **RF input → acquisition/tracking → demodulation → framing/FEC/integrity → all advertised mode fields → plaintext payload/reassembly where available**, with truthful encrypted/no-key behavior, incremental delivery and measured throughput at the declared input rate. Detectors stay under `.detect` and cannot satisfy any payload row.

Each module below has finite acceptance IDs. They include the implemented mode set **and** missing adjacent modes/layers; they do not silently redefine “all modules” as “one example per module.” Family expansion rows are still OPEN until implemented or explicitly removed by the user. Optional modes in a radio standard are not necessarily mandatory for a conforming individual device, but remain **product-scope decisions** under an unqualified broad decoder name. Freeze standard edition, profile, direction, channel width/rate, security mode and all legal combinations in a checked-in manifest before calling a family complete. The proposed target combinations below are audit acceptance targets, not claims that every standard makes each mode mandatory.

An unqualified “every protocol ever called WiFi/RFID/ISM” has no finite historical/version boundary. This matrix therefore exposes that scope issue instead of silently excluding it: baseline modes and named expansion families are explicit; a pinned per-standard/per-device manifest is a required closure artifact. Proprietary or unavailable specifications are research blockers, not permission to invent field meanings.

### Universal acceptance gates (apply to every module/mode)

| ID | Required observable result | Current assessment |
|---|---|---|
| ALL-1 | Explicit capture source/format/rate; independent fixture provenance, hash and expected fields; exact public `.decode` path | Mixed. Several paths accept only bits, synchronized symbols, MPX or amplitude traces; these are not interchangeable with raw IQ. |
| ALL-2 | Acquisition, timing/carrier tracking, complete frame and all required FEC/CRC/parity checks; correct absent-integrity states | Many partial PHYs. A checksum-valid header or selected-bit CRC must not certify an entire payload. |
| ALL-3 | All declared field variants, lengths, reserved values, per-layer validity and bounded fragmented-message assembly | Broad semantic gaps remain in cellular, WiFi, ZigBee, Bluetooth, paging and RFID. |
| ALL-4 | Plaintext interpreted only when clear or authenticated with caller-supplied keys; cipher/unknown states retained without guessed keys | Partly implemented. ZigBee supports supplied-key NWK/APS CCM; most encrypted families remain opaque. Lack of keys does not excuse missing clear PHY/header decoding. |
| ALL-5 | First frame/artifact visible before source EOF; arbitrary bytes/chunks identical to bulk; no invented EOF padding; cleanup/errors/cancel under blocked reads and callbacks | Shared runner has direct lifecycle evidence. Custom GPS/RTL433/RFID subprocess paths require separate guarantees; FDX-B replay emits after child completion. |
| ALL-6 | Finite negative matrix: bad sync/FEC/CRC/MIC, noise, partial samples/frame, invalid rate, loss and timeout; never decoded-success fallback | Broad regression coverage but not per-mode conformance. Bounded-distance FEC cannot reject every error beyond its correction radius. |
| ALL-7 | Pinned backend/version/license and real missing-backend failure; native path actually exercised when required | Optional paths are not uniformly exercised by the default suite. Pure Ruby and native acceleration are different claims. |
| ALL-8 | End-to-end replay sustaining configured samples/s, measured latency/memory/loss and callback budget on named hardware; separate live RF test | No all-module rate qualification. Kernel benchmarks alone do not close this gate. |

## Shared infrastructure matrix

Local evidence: `lib/pwn/sdr/decoder.rb`, `base.rb`, `dsp.rb`; `spec/lib/pwn/sdr/decoder_spec.rb`, `base_spec.rb`, `base_iq_spec.rb`, `dsp_spec.rb`, `dsp_native_spec.rb`; `lib/pwn/sdr/gqrx.rb` and `spec/lib/pwn/sdr/gqrx_spec.rb`.

| ID | Reviewed support | Acceptance / remaining gap |
|---|---|---|
| REGISTRY-1 | 24 aliases map to 21 modules; Base/DSP are autoloaded utilities, not extra protocols | Resolve every key, assert the target and `.decode`/`.detect` contract. `gprs → GSM` must not imply GPRS decoding; `ism/keyfob → RTL433` must not imply all devices or rolling-code plaintext. |
| BASE-1 | `run_native` s16le audio; `run_iq` cu8/cs8/cs16; explicit file/IO or RTL-SDR/HackRF/Pluto/Soapy selection | IQ format is `iq_format`, not the native RTL433 backend's `format`. Generic Base does not accept cf32, although GPS and RTL433 custom backends do. Verify integer scalar carry, actual descriptor rate and source ownership for every backend. |
| BASE-2 | Bounded producer/consumer queue; ordered JSONL/output flush then callback; EOF draining, single clean-EOF flush, worker error propagation | Reader error/cancel is not clean EOF. Prove incomplete sample failure, no flush on capture loss and no thread/FD leakage; existing focused specs cover these paths but not every protocol demodulator. |
| BASE-3 | Overrun/dropped-byte source status checked, discontinuity raises; unknown counts stay nil | Queue backpressure is not hardware-loss telemetry. Validate adapters on actual devices; UDP audio sequence/loss remains unmeasured. Do not report unknown loss as zero. |
| DSP-1 | Ruby fallback and optional DSPNative packed unpack/magnitude/FM, radix-2 FFT; FFTW/VOLK/Liquid helpers elsewhere | Numeric precision/scale, N versus N-1 FM samples, prior IQ and byte remainder must match across backends/chunks. Generic resampling/timing helpers do not establish continuous protocol tracking. |
| DSP-2 | Native kernel benchmark artifacts in `ext/pwn_dsp/` | Record selected backend and benchmark entire decode pipeline at each row's rate. Existing README explicitly says kernel-only rates omit acquisition/channelizer/protocol/queueing. |
| GQRX-1 | `init_freq` resolves registry and forwards common streaming controls; RDS `.sample` avoided when streaming requested | Current `init_freq` strips only GQRX-owned controls and forwards remaining decoder context, including mode/backend/format and callbacks; resolved `freq_obj` stays authoritative. Any explicit decoder context prevents the legacy RDS `.sample` shortcut. `gqrx_spec.rb` covers forwarding. This fixes the historical allowlist defect, not all decoder conformance. |
| NATIVE-1 | Optional native DSP/SCH and required native LTE bridge; custom native GPS/RDS/RTL433/RFID processes | Namespace comment “100% ruby-native / no external binary” is stale. State accurately: first-party Ruby coordination plus named C/C++ libraries/processes; external fixture generators are not runtime dependencies. If “native” means exclusively Ruby, these backends need an explicit requirement decision. |

### RF and performance requirements

Rates below are complex input samples/second unless labeled audio, symbols or chips. They are not RF center frequencies or occupied bandwidth. A 48 kHz GQRX audio stream cannot replace multi-Msps WiFi, BLE, LTE or ZigBee IQ, and cannot carry the 57 kHz RDS subcarrier. Higher rates require channelization/resampling, not relabeling metadata.

`ext/pwn_gsm/README.md` records a measured native SCH scanner plus DSP replay exceeding its 1.083333 Msps fixture workload; it explicitly limits that result to SCH replay. `ext/pwn_lte/benchmark-results.json` measures an acquired PBCH workload, not a full LTE bearer. `ext/pwn_dsp/benchmark-results.json` measures kernels, not decoders. These are repository artifacts reviewed, **not benchmarks rerun by this audit**. WiFi's 11/22/44 Msps Ruby reference path especially needs native end-to-end qualification before any realtime claim. TEMPEST upsampling cannot recreate missing RF bandwidth.

## Per-module acceptance matrix

Every row remains partial overall. Source and spec links are exact repository files; acceptance items are obligations, not completed checkboxes. External references identify the protocol baseline; local implementation findings come from the linked source, not from those standards.

### ADSB

Aliases: `adsb`. Local evidence: [lib/pwn/sdr/decoder/adsb.rb](../lib/pwn/sdr/decoder/adsb.rb), [spec/lib/pwn/sdr/decoder/adsb_spec.rb](../spec/lib/pwn/sdr/decoder/adsb_spec.rb). Protocol baseline/reference[11]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | 1090 MHz; 1 Mbit/s PPM, exactly 2 Msps IQ. 978 MHz UAT explicitly rejected. |
| Implemented modes/layers | DF17/18 112-bit CRC24 extended squitters; TC1-4 callsign, TC5-8 surface movement/track and caller-reference local CPR, TC9-18 barometric altitude including Gillham, TC19 velocity, TC20-22 GNSS height, paired airborne CPR with capture-time expiry. |
| Missing mandatory completion work | TC28/29/31 emergency/target/operational status and integrity semantics; DF18 control-field/address-source distinctions; other Mode-S short/long DFs and AP/DP parity interpretation; UAT PHY/FEC/fields. |
| Plaintext / encrypted / no keys | Public broadcast fields, no encryption keys involved. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | adsb_spec.rb: published Mode-S and pyModeS payload vectors; PPM IQ is synthetic, surface parity regenerated explicitly. base_iq_spec.rb also checks identity. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| ADSB-1 | Verify every supported TC family with independently expected fields, unavailable/reserved values and CRC failures; exhaust all 4096 altitude words against an independent implementation. | OPEN / partial evidence above |
| ADSB-2 | Reject mismatched aircraft/altitude-family CPR pairs and pairs older than 10 s; test both hemispheres/poles/longitude wrap and surface reference ambiguity. | OPEN / partial evidence above |
| ADSB-3 | Implement TC28/29/31 and DF18 CF semantics, then separately Mode-S DF0/4/5/11/16/20/21 and UAT basic/long messages and uplink products; record standards version per family. | OPEN / partial evidence above |

### APT

Aliases: `apt`. Local evidence: [lib/pwn/sdr/decoder/apt.rb](../lib/pwn/sdr/decoder/apt.rb), [spec/lib/pwn/sdr/decoder/apt_spec.rb](../spec/lib/pwn/sdr/decoder/apt_spec.rb). Protocol baseline/reference[26]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | 137 MHz APT; 2400 Hz AM subcarrier in FM, 4160 words/s; default 48 kHz audio/IQ. |
| Implemented modes/layers | Initial Sync-A search, full 2080-word lines, 2 lines/s, bounded rolling atomic PGM and callbacks. |
| Missing mandatory completion work | Continuous Sync-A/Sync-B lock, clock drift/drop recovery, separation of both 909-pixel channels, telemetry wedges/calibration/channel identification; no independent received-image equivalence proof. |
| Plaintext / encrypted / no keys | No protocol encryption in the reviewed mode; application bytes are not automatically plaintext. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | apt_spec.rb: synthetic AM audio and FM IQ pipe, correct 2080 width and silence rejection; no RF capture. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| APT-1 | Replay independently received APT and compare both image channels and line positions, not only PGM existence. | OPEN / partial evidence above |
| APT-2 | Decode both synchronization sequences, telemetry wedges and channel/calibration fields; preserve calibrated amplitude independently of per-line display contrast. | OPEN / partial evidence above |
| APT-3 | Test acquisition at every line offset, drift, a lost line, noise false-sync and EOF without zero-padding. | OPEN / partial evidence above |

### Bluetooth

Aliases: `bluetooth`. Local evidence: [lib/pwn/sdr/decoder/bluetooth.rb](../lib/pwn/sdr/decoder/bluetooth.rb), [spec/lib/pwn/sdr/decoder/bluetooth_spec.rb](../spec/lib/pwn/sdr/decoder/bluetooth_spec.rb). Protocol baseline/reference[2]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | LE1M 1 Msym/s, default 4 Msps; caller-selected channel 0..39; no hopping receiver. |
| Implemented modes/layers | CRC24/dewhitening; legacy advertising PDU types 0..6, optional extended/AUX header parse; connected LL data/control frames with supplied AA/CRCInit/encryption state. |
| Missing mandatory completion work | LE2M/LE Coded; BR/EDR; connection acquisition and hopping, AUX chain/periodic scheduling, L2CAP/ATT/GATT/LL control semantic decoding and reassembly; MIC/decryption. |
| Plaintext / encrypted / no keys | Connected mode requires explicit encrypted true/false; encrypted bytes become ciphertext_hex, not application plaintext; no MIC verification. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | bluetooth_spec.rb: SIG CRC/advertising vectors and synthetic IQ streaming; connected/extended additions mostly feed_bits. Extended SIG vector has explicitly corrected CRC, not verbatim interoperability. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| BLUETOOTH-1 | Exercise all legacy advertising types and legal lengths through IQ; extended field masks, truncated ExtHdrLen, primary/secondary channel whitening and AUX chain ordering. | OPEN / partial evidence above |
| BLUETOOTH-2 | Recover connection context from CONNECT_IND/AUX_CONNECT_REQ, follow channel selection/maps and decode LL control plus fragmented L2CAP/ATT, with missing-hop handling. | OPEN / partial evidence above |
| BLUETOOTH-3 | Add LE2M, LE Coded S=2/S=8, and independent BR/EDR access/header/payload/FEC/CRC cases; these are distinct family requirements, not covered by LE1M. | OPEN / partial evidence above |

### DECT

Aliases: `dect`. Local evidence: [lib/pwn/sdr/decoder/dect.rb](../lib/pwn/sdr/decoder/dect.rb), [spec/lib/pwn/sdr/decoder/dect_spec.rb](../spec/lib/pwn/sdr/decoder/dect_spec.rb). Protocol baseline/reference[12]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | 1.152 Mbit/s GFSK; default 2.304 Msps; tests also 4.608 Msps; caller carrier/connection context. |
| Implemented modes/layers | P00 A-field R-CRC and Nt RFPI; P32 X-CRC, optional B descrambling with supplied frame number; unprotected, 4x(64+16) multisubfield and 304+16 singlesubfield B formats. |
| Missing mandatory completion work | Automatic frame/multiframe/connection tracking; other packet sizes P08/P80 and higher-order formats; encoded protection/FEC; E/U demux, MAC tail semantics, DLC/NWK reassembly, speech codecs. |
| Plaintext / encrypted / no keys | Descrambling is not decryption. Without explicit clear state, B data stays ciphertext/unknown. X-CRC checks only selected 80 scrambled bits, not all B data. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | dect_spec.rb: ETSI-derived register/scrambling and synthetic GFSK; P32 B-CRC rejection before pipe EOF. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| DECT-1 | Cover FP/PP sync and spectral inversion without falsely asserting role; all A-tail discriminators and R-CRC failures. | OPEN / partial evidence above |
| DECT-2 | P32 each frame-number seed 0..15 and each implemented B format, corrupt selected and unselected X-CRC bits and every protected subfield; assert exact integrity scope. | OPEN / partial evidence above |
| DECT-3 | Implement packet-family matrix, bearer establishment/tracking, DLC and NWK messages and clear speech; independently test encryption unknown, clear and cipher states. | OPEN / partial evidence above |

### Flex

Aliases: `flex`. Local evidence: [lib/pwn/sdr/decoder/flex.rb](../lib/pwn/sdr/decoder/flex.rb), [spec/lib/pwn/sdr/decoder/flex_spec.rb](../spec/lib/pwn/sdr/decoder/flex_spec.rb). Protocol baseline/reference[8]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | 1600/3200/6400 bps FLEX, 2-/4-FSK mode table; 48 kHz discriminator audio or default 240 kHz FM IQ. |
| Implemented modes/layers | Sync/FIW, 88-word phase deinterleave, BCH plus parity, short addresses/vector walking; plain alpha fragment checksum, whole-message signature and bounded ordered modulo-three assembly; numeric/binary extraction. |
| Missing mandatory completion work | Long addresses, enhanced symbolic/secure layouts, numeric/binary message integrity; robust fragment expiry and all phase/mode combinations need independent coverage. |
| Plaintext / encrypted / no keys | No protocol encryption in the reviewed mode; application bytes are not automatically plaintext. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | flex_spec.rb: TI-derived alpha fragments, control bytes, bad checksum/signature, ordering and discriminator streaming. Numeric/binary validity is not established by BCH. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| FLEX-1 | One independent IQ/discriminator vector for every Sync-1 mode/phase combination, FIW/BIW/vector/address boundary and BCH correction radius. | OPEN / partial evidence above |
| FLEX-2 | Implement long addresses and each advertised message vector type with its own checksum/layout; never decode secure data using plain alpha layout. | OPEN / partial evidence above |
| FLEX-3 | Test alpha first/continuation/final, modulo-three wrap, missing/duplicate/out-of-order fragments, controls and fill, signature corruption and bounded expiry across frame/cycle wrap. | OPEN / partial evidence above |

### GPS

Aliases: `gps`. Local evidence: [lib/pwn/sdr/decoder/gps.rb](../lib/pwn/sdr/decoder/gps.rb), [spec/lib/pwn/sdr/decoder/gps_spec.rb](../spec/lib/pwn/sdr/decoder/gps_spec.rb). Protocol baseline/reference[3]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | L1 C/A 1.023 Mcps and 50 bit/s LNAV. Native IQ tracker configuration accepts 2..25 Msps cs8/cs16/cf32, internally 2 Msps; bit mode has no RF input. |
| Implemented modes/layers | Public mode:iq invokes native GNSS-SDR file acquisition/tracking/telemetry; Ruby restores monitor inversion and verifies all ten LNAV word parities. Also mode:lnav_bits; TLM/HOW/TOW/subframe/week fields only, not full navigation/PVT payload semantics. |
| Missing mandatory completion work | Full subframe1 clock/health, subframe2/3 ephemeris and issue-of-data assembly, subframe4/5 page/almanac/UTC/iono semantics, validated PVT output; L2C/L5/L1C and other GNSS are not implied. |
| Plaintext / encrypted / no keys | Civil LNAV is public. No P(Y)/M-code key recovery or restricted-signal plaintext claim. |
| Native requirement | LNAV parser Ruby; optional native gnss-sdr process for IQ tracking, not Python runtime. FFTW accelerates separate acquisition detector. |
| Existing evidence boundary | gps_spec.rb: synthetic fixed parity words and bounded monitor protobuf; real IQ test gated by PWN_GPS_IQ_FIXTURE. Audit must not count an absent optional fixture as a pass. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| GPS-1 | Public IQ decode must invoke actual acquisition/DLL/PLL/bit sync, recover known LNAV before receiver EOF, and reject parity-bad/noise data; direct decode_monitor is not IQ evidence. | OPEN / partial evidence above |
| GPS-2 | Independently verify every LNAV page/subframe field, signed scaling, week rollover, IODE/IODC consistency and expiry; retain unavailable parameters as unavailable. | OPEN / partial evidence above |
| GPS-3 | Expose verified PVT only with sufficient satellites/valid ephemerides and uncertainty; separately enumerate L2C/L5/L1C modes if broad GPS naming is retained. | OPEN / partial evidence above |

### GSM

Aliases: `gprs`, `gsm`. Local evidence: [lib/pwn/sdr/decoder/gsm.rb](../lib/pwn/sdr/decoder/gsm.rb), [spec/lib/pwn/sdr/decoder/gsm_spec.rb](../spec/lib/pwn/sdr/decoder/gsm_spec.rb). Protocol baseline/reference[1]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | GSM channelized 270.833 ksym/s GMSK; SCH default 1,083,333 samples/s, >=4 samples/symbol. |
| Implemented modes/layers | SCH IQ training search, convolutional Viterbi, CRC10/tails, BSIC/frame fields; explicit sch_bits. FCCH observation only via detect. |
| Missing mandatory completion work | Normal-burst equalization, timeslot/multiframe scheduling, BCCH/CCCH/SDCCH/SACCH/FACCH, LAPDm/RR/MM/CC/SMS and traffic; gprs alias has no GPRS RLC/MAC/LLC/SNDCP or EGPRS decoding. |
| Plaintext / encrypted / no keys | Parse cipher-mode state and preserve ciphertext without supplied keys. Channel CRC never establishes decrypted subscriber content. |
| Native requirement | Ruby decoder; optional bundled C SCH scanner and DSP. ext/pwn_gsm/benchmark-results.json is end-to-end offline SCH replay, not general GSM. |
| Existing evidence boundary | gsm_spec.rb and fixtures/sdr/gsm: independent libosmocore codeword plus GNU Radio modulation; generated not received RF. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| GSM-1 | Independent SCH IQ across CFO/timing/noise/truncation with no success on FCCH alone. | OPEN / partial evidence above |
| GSM-2 | Implement normal burst recovery, xCCH deinterleave/FIRE/FEC, BCCH System Information and CCCH paging/immediate assignment with independent IQ traces. | OPEN / partial evidence above |
| GSM-3 | Implement GPRS CS1..4, EGPRS MCS1..9 as separately declared modes, RLC block assembly/LLC/SNDCP; traffic FR/HR/EFR/AMR and clear signalling require their own vectors. | OPEN / partial evidence above |

### Iridium

Aliases: `iridium`. Local evidence: [lib/pwn/sdr/decoder/iridium.rb](../lib/pwn/sdr/decoder/iridium.rb), [spec/lib/pwn/sdr/decoder/iridium_spec.rb](../spec/lib/pwn/sdr/decoder/iridium_spec.rb). Protocol baseline/reference[25]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | Only pre-channelized, carrier/timing-synchronized complex IRA symbols at exactly 25,000 samples/s. Detector default 2 Msps does not decode. |
| Implemented modes/layers | IRA access word, differential Gray symbols, deinterleave/BCH(31,21)+parity correction, sat/beam/XYZ/page fields through ira_symbols_iq; direct decode_ring_alert bits. |
| Missing mandatory completion work | Raw channel/wideband burst acquisition, timing/CFO/phase tracking; IMS/MSG/MS3/IBC/ITL/IAQ/LCW/VOC/IDA/IIP/ISY families, their FEC/CRC and message/data reassembly. |
| Plaintext / encrypted / no keys | Broadcast satellite/beam location is not subscriber location. Ciphertext and unknown message formats must stay opaque. |
| Native requirement | Current IRA Ruby path. gr-iridium/toolkit reference is not itself an integrated general native backend. |
| Existing evidence boundary | iridium_spec.rb: received symbol-row fixture hashes, BCH error enumeration; upstream preprocessing already supplied synchronization. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| IRIDIUM-1 | Replay synchronized received IRA symbol fixtures and nonempty paging lists up to terminator/limit; corruption and truncation must not produce success. | OPEN / partial evidence above |
| IRIDIUM-2 | Add continuous raw IQ channelizer/burst synchronizer and prove same payload without pre-synchronized symbols. | OPEN / partial evidence above |
| IRIDIUM-3 | Implement each documented frame family with matching integrity and reassembly; preserve unknown IU3/INP/vendor semantics explicitly rather than claim a complete proprietary standard. | OPEN / partial evidence above |

### LTE

Aliases: `lte`. Local evidence: [lib/pwn/sdr/decoder/lte.rb](../lib/pwn/sdr/decoder/lte.rb), [spec/lib/pwn/sdr/decoder/lte_spec.rb](../spec/lib/pwn/sdr/decoder/lte_spec.rb). Protocol baseline/reference[15]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | Central six PRBs at exactly 1.92 Msps, FDD normal CP, two transmit ports, explicit offline file/IO. |
| Implemented modes/layers | pbch_iq acquires PSS/SSS PCI/timing/fractional CFO; pbch_sf0_iq consumes known PCI/aligned SF0; native channel estimation/equalization/FEC/CRC16 -> 24-bit MIB. |
| Missing mandatory completion work | Other ports/CP/TDD, tracking and 40-ms combining; control channels/DCI, SIB/RRC, PDSCH/PUSCH/PUCCH/PRACH, HARQ, MAC/RLC/PDCP/NAS and traffic. |
| Plaintext / encrypted / no keys | MIB/SIB are public; traffic cipher context and keys are separate, no keys means opaque PDCP ciphertext. |
| Native requirement | Required bundled bridge linked to srsRAN_4G native PHY and dependencies; missing backend raises LoadError. AGPL redistribution obligations; not 100% pure Ruby. |
| Existing evidence boundary | lte_spec.rb: pinned srsRAN upstream IQ, PCI150/MIB681c00, acquired offsets/CFO and pipe; optional native cases require local backend. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| LTE-1 | Independent PBCH cases for PCI groups, SFN phases, bandwidth/PHICH values, offset/CFO, CRC failure and overlapping search windows; assert no success from PSS alone. | OPEN / partial evidence above |
| LTE-2 | Add 1/2/4-port, normal/extended CP and FDD/TDD PBCH cases, persistent tracking and soft combining. | OPEN / partial evidence above |
| LTE-3 | Implement broadcast SIB1/SI via PDCCH/PDSCH and RRC ASN.1 first; then per-direction channel/FEC/rate-matching/HARQ and plaintext bearer layers across 1.4/3/5/10/15/20 MHz modes. | OPEN / partial evidence above |

### LoRa

Aliases: `lora`. Local evidence: [lib/pwn/sdr/decoder/lora.rb](../lib/pwn/sdr/decoder/lora.rb), [spec/lib/pwn/sdr/decoder/lora_spec.rb](../spec/lib/pwn/sdr/decoder/lora_spec.rb). Protocol baseline/reference[21]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | CSS SF7..12, BW125/250/500 kHz, rate >= BW; rational resampling; CR4/5..4/8. |
| Implemented modes/layers | Preamble/SFD, integer-bin CFO, explicit or configured implicit header, header checksum, Hamming/interleave/whitening, optional payload CRC, LDRO and IQ inversion; raw payload bytes. |
| Missing mandatory completion work | Fractional CFO/clock drift tracking, sensitivity/multipath/collision qualification; SF5/6 and device-specific bandwidths; LoRaWAN MAC/session/MIC/application layers. |
| Plaintext / encrypted / no keys | Raw LoRa payload may be LoRaWAN ciphertext. CRC-off has crc_valid nil; implicit headers have header_valid nil; never treat either as integrity success. |
| Native requirement | Ruby PHY plus optional DSP FFT and VOLK resampling; gr-lora_sdr is fixture generation only, not runtime. |
| Existing evidence boundary | lora_spec.rb and vectors.json/modes.json: pinned gr-lora_sdr synthetic interoperability IQ, transformed/quantized public runner; modes represented are not all combinations. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| LORA-1 | Cross product SF7..12 x CR1..4 x BW125/250/500 x explicit/implicit x CRC on/off x normal/inverted x legal LDRO choices; independent expected payload and absent-integrity flags. | OPEN / partial evidence above |
| LORA-2 | Payload lengths 0/1/2, code-block boundaries and 255, sync words 0x12/0x34, fractional/noninteger sample rates, CFO/drift and arbitrary byte chunks; incompatible options fail before opening RF. | OPEN / partial evidence above |
| LORA-3 | Add fractional synchronization and clock tracking; separately implement LoRaWAN 1.0.x/1.1 join/data/MAC command fields and key-dependent MIC/decryption or retain an explicit unfinished family row. | OPEN / partial evidence above |

### Morse

Aliases: `morse`. Local evidence: [lib/pwn/sdr/decoder/morse.rb](../lib/pwn/sdr/decoder/morse.rb), [spec/lib/pwn/sdr/decoder/morse_spec.rb](../spec/lib/pwn/sdr/decoder/morse_spec.rb). Protocol baseline/reference[4]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | CW/USB sidetone audio default 48 kHz. Raw IQ path currently FM-discriminates rather than CW envelope/SSB demodulation. |
| Implemented modes/layers | Adaptive audio envelope/run timing, DSP Morse table, character/word gaps, text/callsign hint, EOF flush. |
| Missing mandatory completion work | Correct raw CW IQ frontend, all International Morse symbols/prosign handling and timing range qualification; no independent RF text evidence. |
| Plaintext / encrypted / no keys | No protocol encryption in the reviewed mode; application bytes are not automatically plaintext. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | morse_spec.rb: synthetic SOS/audio/flush, not complete alphabet or raw CW RF validation. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| MORSE-1 | Compare every International Morse symbol/prosign to reference table, preserve word boundaries and explicitly represent unknown symbols. | OPEN / partial evidence above |
| MORSE-2 | Independent CW IQ and audio at declared 5/10/20/40 WPM and pitch/gain/CFO variations, dash-first messages and Farnsworth spacing; define measured timing limits. | OPEN / partial evidence above |
| MORSE-3 | Distinguish real CW envelope/USB demodulation from FM audio fixtures; test leading/trailing silence, glitches and EOF final character. | OPEN / partial evidence above |

### P25

Aliases: `p25`. Local evidence: [lib/pwn/sdr/decoder/p25.rb](../lib/pwn/sdr/decoder/p25.rb), [spec/lib/pwn/sdr/decoder/p25_spec.rb](../spec/lib/pwn/sdr/decoder/p25_spec.rb). Protocol baseline/reference[14]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | Phase1 C4FM 4800 symbols/s; default 960 kHz IQ, lower test rates; Phase2/CQPSK rejected. |
| Implemented modes/layers | Frame sync/status removal, NID BCH, DUID7 TSDU up to three TSBKs, trellis/interleave and CRC16; opcode/MFID and group voice grant fields. Mode:pdu/:all additionally parses unconfirmed rate-1/2 DUID12 format0x15 blocks, header CRC16/packet CRC32, SAP/LLID/padding and opaque/clear data. |
| Missing mandatory completion work | Other TSBK opcodes, MBT/confirmed PDU and other PDU formats, HDU/LDU1/LDU2/TDU/TDULC, link control and voice FEC/vocoder; CQPSK, Phase2 and trunking channel follow. |
| Plaintext / encrypted / no keys | Protected TSBK bytes remain ciphertext; no key guessing or false clear speech. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | p25_spec.rb: independent op25 three-block bits plus synthetic C4FM; NID-only detector is explicitly decoded false. New updu.bin test is independent op25 dibits, not an unconfirmed-PDU RF reception proof. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| P25-1 | Exercise one/two/three TSBKs and status-symbol positions, bad middle block, last-block absence and protected flag; independent op25 data and actual C4FM IQ. | OPEN / partial evidence above |
| P25-2 | Decode every standard/MFID-qualified TSBK opcode with reserved/unknown handling; implement MBT/PDU and all Phase1 DUID families with CRC/FEC and reassembly. | OPEN / partial evidence above |
| P25-3 | Add CQPSK and Phase2 TDMA with channel grants/identifier maps; decode clear IMBE/AMBE only after valid voice framing and distinguish encrypted voice. | OPEN / partial evidence above |

### POCSAG

Aliases: `pocsag`. Local evidence: [lib/pwn/sdr/decoder/pocsag.rb](../lib/pwn/sdr/decoder/pocsag.rb), [spec/lib/pwn/sdr/decoder/pocsag_spec.rb](../spec/lib/pwn/sdr/decoder/pocsag_spec.rb). Protocol baseline/reference[19]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | 512/1200/2400 bit/s NRZ FSK; default 240 kHz IQ or 48 kHz discriminator audio. |
| Implemented modes/layers | Preamble/sync/batch words, BCH(31,21)+parity bounded correction, address/function, numeric/alpha and message termination; legacy bit API. |
| Missing mandatory completion work | Independent all-rate/all-function IQ evidence and robust acquisition/polarity/timing qualification; payload alphabet/function selection is not proven by codeword correction alone. |
| Plaintext / encrypted / no keys | No protocol encryption in the reviewed mode; application bytes are not automatically plaintext. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | pocsag_spec.rb: fixed ITU idle/sync words and exhaustive bounded errors, terminated split bits; pure correction tests do not establish all RF modes. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| POCSAG-1 | All three rates x both spectral polarities x address frame positions0..7 x function0..3; numeric alphabet, alpha bit packing, tone-only and multi-batch messages. | OPEN / partial evidence above |
| POCSAG-2 | Every single/double flip on independent valid words including parity, selected uncorrectable triples, sync errors, missing batch and truncation; never promise rejection of every beyond-radius error. | OPEN / partial evidence above |
| POCSAG-3 | Independent RF/discriminator expected capcodes and messages, bounded long messages and callback before EOF through public entry. | OPEN / partial evidence above |

### Pager

Aliases: `pager`. Local evidence: [lib/pwn/sdr/decoder/pager.rb](../lib/pwn/sdr/decoder/pager.rb), [spec/lib/pwn/sdr/decoder/pager_spec.rb](../spec/lib/pwn/sdr/decoder/pager_spec.rb). Protocol baseline/reference[8][19]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | Composite POCSAG+FLEX, same audio/IQ rates as delegates. |
| Implemented modes/layers | Feeds POCSAG and FLEX concurrently and propagates stream/flush outputs. |
| Missing mandatory completion work | Inherits every delegate gap; no additional paging standard inferred from broad pager name; coexistence/arbitration false-positive qualification. |
| Plaintext / encrypted / no keys | No protocol encryption in the reviewed mode; application bytes are not automatically plaintext. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | pager_spec.rb: delegate flush and plumbing, not independent mixed-mode RF coverage. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| PAGER-1 | One mixed POCSAG/FLEX capture with alternating rates/phase modes and exact expected ordered messages. | OPEN / partial evidence above |
| PAGER-2 | Verify no duplicate message/detector output and no speculative success from one losing demodulator. | OPEN / partial evidence above |
| PAGER-3 | Close all POCSAG and FLEX rows independently; declare additional paging standards separately rather than counting this wrapper as another implementation. | OPEN / partial evidence above |

### RDS

Aliases: `rds`. Local evidence: [lib/pwn/sdr/decoder/rds.rb](../lib/pwn/sdr/decoder/rds.rb), [spec/lib/pwn/sdr/decoder/rds_spec.rb](../spec/lib/pwn/sdr/decoder/rds_spec.rb). Protocol baseline/reference[23]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | FM broadcast MPX with 57 kHz subcarrier; redsea raw s16le source accepts128..384 kHz (default192k); default API polls GQRX. |
| Implemented modes/layers | Default GQRX station-string observations/sample. backend:redsea native MPX -> raw complete four-block groups, PI/group and preserved backend fields; rejects partial raw groups. |
| Missing mandatory completion work | Raw SDR IQ-to-MPX in this backend, own group field schema/coverage inventory, all RDS/RBDS groups/ODAs/RDS2 variants; default polling is not independently validated frame decoding. |
| Plaintext / encrypted / no keys | Public RDS groups; a proprietary/encrypted ODA payload is not automatically decoded by intact block CRC. |
| Native requirement | GQRX external application for default metadata; optional native C++ redsea process and liquid-dsp for actual MPX decoding. |
| Existing evidence boundary | rds_spec.rb mostly GQRX sample/help; ext/pwn_rds/verify.rb and stream_verify.rb exercise independent MPX group14A outside default specs. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| RDS-1 | Prove received MPX -> intact four-block group before EOF and bad-block rejection; do not use cached GQRX station strings as raw protocol evidence. | OPEN / partial evidence above |
| RDS-2 | Enumerate group0..15 A/B, PS/RT A-B resets, AF, CT, EON, PTYN, paging/TMC and assigned ODA payloads for pinned RDS/RBDS edition and backend revision. | OPEN / partial evidence above |
| RDS-3 | Implement or explicitly keep open raw IQ MPX generation and RDS2 additional streams; validate each supported group and unknown application ID without invented semantics. | OPEN / partial evidence above |

### RFID

Aliases: `rfid`. Local evidence: [lib/pwn/sdr/decoder/rfid.rb](../lib/pwn/sdr/decoder/rfid.rb), [spec/lib/pwn/sdr/decoder/rfid_spec.rb](../spec/lib/pwn/sdr/decoder/rfid_spec.rb). Protocol baseline/reference[9]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | EM4100 ASK Manchester125kHz carrier, RF/64,/32,/16; >=4 samples/half-bit, default250k IQ. FDX-B mode takes .pm3 amplitudes, not RF-rate IQ. |
| Implemented modes/layers | EM4100 header/row+column parity/stop, 40-bit identity; fdxb_pm3 external offline CRC16-validated country/national ID and animal/data flags. |
| Missing mandatory completion work | EM4100 PSK/biphase; FDX-B SDR IQ frontend and extension semantics; HF ISO14443 A/B, ISO15693, UHF EPC Gen2 and their anti-collision/data/security layers. |
| Plaintext / encrypted / no keys | No tag key recovery; encrypted authentication/application exchanges stay opaque. Plain UID extraction is not access to protected memory. |
| Native requirement | EM4100 Ruby; fdxb_pm3 requires installed native proxmark3 and emits after child completion, not Base streaming. |
| Existing evidence boundary | rfid_spec.rb: published EM4100 bits with synthetic IQ; pinned proxmark3 ATA5577 FDX-B amplitude traces. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| RFID-1 | Independent EM4100 vectors for all clock divisors, row/column/stop failures and repeated tags under ASK IQ. | OPEN / partial evidence above |
| RFID-2 | FDX-B received amplitude and IQ cases with full extension fields, incomplete trace and CRC errors; require output before EOF for any streaming claim. | OPEN / partial evidence above |
| RFID-3 | Separate LF/HF/UHF matrices: ISO14443A/B both directions, ISO15693 rates/subcarriers, EPC Gen2 PIE and FM0/Miller; inventory command/response CRC and bounded transaction assembly. | OPEN / partial evidence above |

### RTL433

Aliases: `ism`, `keyfob`, `rtl433`. Local evidence: [lib/pwn/sdr/decoder/rtl433.rb](../lib/pwn/sdr/decoder/rtl433.rb), [spec/lib/pwn/sdr/decoder/rtl433_spec.rb](../spec/lib/pwn/sdr/decoder/rtl433_spec.rb). Protocol baseline/reference[10]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | OOK/FSK ISM aliases rtl433/ism/keyfob; Acurite default250k IQ (>=20k). Native file replay declares any positive rate and cu8/cs16/cf32. |
| Implemented modes/layers | Ruby Acurite609TXC PPM timing/checksum/ID/status/battery/signed temperature/humidity. native mode uses installed rtl_433 enabled catalogue, optional explicit protocol IDs, normalized JSON. |
| Missing mandatory completion work | No version-pinned exhaustive per-device catalogue acceptance, disabled-by-default modes not automatically covered; native live IO/hardware streaming absent; keyfob rolling-code semantics not generally decoded. |
| Plaintext / encrypted / no keys | Weak checksum is not authentication. Keyfob alias does not imply rolling-code decryption or plaintext recovery. |
| Native requirement | Acurite Ruby; catalogue replay requires native rtl_433 executable, no runtime Python. |
| Existing evidence boundary | rtl433_spec.rb: upstream Acurite RF expected six packets; native Acurite/WH31/Toyota fixtures and ID selection. Other installed devices remain unverified. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| RTL433-1 | Record installed rtl_433 version and full -R help inventory including disabled decoders and every alias/device variant; one acceptance row per device/protocol ID with exact rate and integrity scheme. | OPEN / partial evidence above |
| RTL433-2 | Independent OOK/FSK captures per device with exact native fields, CRC/checksum-negative examples and truncation; three representative devices never prove catalogue completeness. | OPEN / partial evidence above |
| RTL433-3 | Native replay must separate missing mic from verified integrity, preserve device_protocol, handle large JSON/child failure/cancellation, and add real streaming if live full decoding is claimed. | OPEN / partial evidence above |

### RTTY

Aliases: `rtty`. Local evidence: [lib/pwn/sdr/decoder/rtty.rb](../lib/pwn/sdr/decoder/rtty.rb), [spec/lib/pwn/sdr/decoder/rtty_spec.rb](../spec/lib/pwn/sdr/decoder/rtty_spec.rb). Protocol baseline/reference[20]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | ITA2/Baudot, default45.45baud with2125/2295Hz audio tones,1 start+5LSB data+1.5 stop; default48k audio/IQ. |
| Implemented modes/layers | Goertzel mark/space, asynchronous framing, LTRS/FIGS state, text lines/EOF flush. Demod constructor accepts baud/tones but public decode only passes rate. |
| Missing mandatory completion work | Public baud/mark/space forwarding, fractional-clock acquisition and supported alternate speeds/shifts; true FSK/SSB IQ frontend rather than generic FM-to-AFSK assumption. |
| Plaintext / encrypted / no keys | No protocol encryption in the reviewed mode; application bytes are not automatically plaintext. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | rtty_spec.rb: synthetic tones at custom demod rates, stop interval and long-buffer/flush; not public alternate-mode coverage. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| RTTY-1 | Every ITA2 letters/figures code including shifts/CR/LF and full1.5 stop, back-to-back words and framing errors. | OPEN / partial evidence above |
| RTTY-2 | Wire public baud/mark/space/reverse/stop configuration; qualify45.45/50/75/100baud and170/425/850Hz shifts as separate declared modes, with both polarities. | OPEN / partial evidence above |
| RTTY-3 | Independent FSK IQ plus audio equivalence, fractional start offsets/clock drift, noise, truncation and before-EOF lines; do not equate synthetic AFSK tests with general HF RTTY. | OPEN / partial evidence above |

### Tempest

Aliases: `tempest`. Local evidence: [lib/pwn/sdr/decoder/tempest.rb](../lib/pwn/sdr/decoder/tempest.rb), [spec/lib/pwn/sdr/decoder/tempest_spec.rb](../spec/lib/pwn/sdr/decoder/tempest_spec.rb). Protocol baseline/reference[18]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | Known VGA640x480/SVGA800x600/XGA1024x768/HD1280x720 timing plus overrides; default2.048Msps IQ is not full pixel bandwidth. |
| Implemented modes/layers | Magnitude -> sample-and-hold raster with assumed origin and timing; bounded atomic grayscale PGM, streaming frame callbacks. |
| Missing mandatory completion work | Automatic line/frame origin and timing acquisition, drift lock, RF image recognition, calibrated resolution/bandwidth; preset pixel_clock is not used by resolve_timing (totals*refresh used). |
| Plaintext / encrypted / no keys | Raster reconstruction has no protocol CRC/authentication and must not assert screen identity from energy. |
| Native requirement | Ruby magnitude/raster plus optional DSP; no native image-recovery backend integrated. |
| Existing evidence boundary | tempest_spec.rb: synthetic tiny raster/timing and pipe lifecycle; no independent display RF capture. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| TEMPEST-1 | Known independent display test pattern/capture for every preset; compare visible active crop, blanking origin and recovered spatial resolution, not just file dimensions. | OPEN / partial evidence above |
| TEMPEST-2 | Detect horizontal/vertical rates and frame origin, track clock drift and reject noise as unidentified raster; explicitly mark manual preview as candidate, not verified screen content. | OPEN / partial evidence above |
| TEMPEST-3 | Reconcile exact pixel clocks vs rounded60Hz timings; test fractional rate, partial raster, bounds and sustained frame updates with no invented detail from upsampling. | OPEN / partial evidence above |

### WiFi

Aliases: `wifi`. Local evidence: [lib/pwn/sdr/decoder/wifi.rb](../lib/pwn/sdr/decoder/wifi.rb), [spec/lib/pwn/sdr/decoder/wifi_spec.rb](../spec/lib/pwn/sdr/decoder/wifi_spec.rb). Protocol baseline/reference[13]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | 802.11b long-preamble1Mbps DBPSK/Barker; centered IQ exactly11/22/44Msps. |
| Implemented modes/layers | PLCP/scrambler/CRC16 and MAC FCS32; legacy control10..15, management/data WDS/QoS headers, beacon/probe IEs, clear LLC/SNAP, bounded ordered plaintext fragments. |
| Missing mandatory completion work | 2Mbps DQPSK,5.5/11Mbps CCK,short preamble, OFDM/HT/VHT/HE/EHT; CFO/equalizer/drift/resampling; full MAC subtype bodies, aggregation/BlockAck and upper-layer semantics. |
| Plaintext / encrypted / no keys | Protected bit preserves opaque MAC payload; no supplied-key decryption/MIC path. FCS-valid protected data is not plaintext. |
| Native requirement | Ruby protocol path; shared optional DSP acceleration. |
| Existing evidence boundary | wifi_spec.rb: IEEE draft PLCP CRC vector, synthetic standards-derived IQ and plaintext fragmentation; not received-air interoperability proof. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| WIFI-1 | Independent1Mbps received IQ with PLCP/FCS failures, every header address form, IE truncation, retry and fragment ordering/expiry; inspect emitted MSDU not only MPDU. | OPEN / partial evidence above |
| WIFI-2 | Implement2Mbps/CCK long+short PLCP, then OFDM6..54Mbps and HT/VHT/HE/EHT versioned channel-width/MCS/guard-interval matrices; keep unsupported rows open. | OPEN / partial evidence above |
| WIFI-3 | Decode management/control subtype bodies, A-MSDU/A-MPDU/BlockAck and clear LLC/network packets; protected payload never enters plaintext reassembly without authenticated decryption. | OPEN / partial evidence above |

### ZigBee

Aliases: `zigbee`. Local evidence: [lib/pwn/sdr/decoder/zigbee.rb](../lib/pwn/sdr/decoder/zigbee.rb), [spec/lib/pwn/sdr/decoder/zigbee_spec.rb](../spec/lib/pwn/sdr/decoder/zigbee_spec.rb). Protocol baseline/reference[16][24]

| Dimension | Assessment |
|---|---|
| Status | **PARTIAL — full requirement OPEN** |
| RF/rates/input | 2.4GHz802.15.4 O-QPSK2Mchip/s250kbps; default4Msps,8Msps regression; centered normal-polarity IQ. |
| Implemented modes/layers | SHR/PHR/DSSS MAC versions0/1 FCS, addresses/aux security; nested ZigBee PRO NWKv2 routes/header and APS headers; supplied-key AES-CCM levels5/6/7 for NWK/APS. |
| Missing mandatory completion work | MACv2/sub-GHz PHY, MAC CCM, complete NWK/APS commands, key derivation/transport/replay policy, APS fragmentation, ZDP/ZCL semantic fields, inter-PAN. |
| Plaintext / encrypted / no keys | Authentication is per layer. MAC FCS != NWK/APS MIC. Missing keys leaves payload_hex nil/ciphertext, supported correct keys release authenticated plaintext. |
| Native requirement | Ruby PHY/parser; OpenSSL native AES-CCM for supplied-key authentication/decryption. |
| Existing evidence boundary | zigbee_spec.rb: standards chip tables/synthetic O-QPSK, RFC3610 CCM and independently generated NWK/APS cipher fixtures; nested auth failure preserves only valid MAC. |

| Acceptance ID | Finite required test/implementation result | State |
|---|---|---|
| ZIGBEE-1 | Independent IQ MAC beacon/data/ACK/command and all legal address/PAN-compression cases; malformed versions/PHR/lengths/FCS fail. | OPEN / partial evidence above |
| ZIGBEE-2 | NWK routes/security and APS unicast/broadcast/group/ACK/commands, all CCM levels and key sequences; no-key retains ciphertext, wrong-key/MIC does not release plaintext. | OPEN / partial evidence above |
| ZIGBEE-3 | Implement APS reassembly, ZDP discovery/binding and versioned ZCL cluster/command/attribute types, MAC security and newer PHY/frame versions as separate matrices. | OPEN / partial evidence above |

## Prioritized independently implementable work

Priority orders risk and integration value; it is not a claim that later rows are optional. Assign disjoint protocol ownership, with a separate shared Base/GQRX owner.

| Priority / owner boundary | Concrete next deliverable | Acceptance gate / dependency |
|---|---|---|
| P0 Shared API owner | Forward protocol mode/backend/format and context options through GQRX; expose machine-readable capability records | GQRX-1, REGISTRY-1. Test all aliases programmatically; do not silently route a GPS/LTE IQ mode to defaults. |
| P0 Integrity/schema owner with protocol reviews | Uniform layer/capability/source/backend/integrity/encryption states; update stale pure-Ruby/default help claims | ALL-2/4. Preserve valid MAC/PHY output when upper-layer authentication fails, but never label it decoded application plaintext. |
| P0 Measurement owner | Versioned per-mode standards/backend manifest, fixture oracles and loss/rate qualification | ALL-1/7/8. Freeze repository snapshot before full gates; a moving tree cannot be certified by one test run. |
| P1 GSM owner | Normal-burst equalizer + xCCH/FIRE/FEC + BCCH/CCCH/LAPDm/RR; then GPRS alias | GSM-2/3. Independent SCH already exists; implement traffic independently from scanner speedups. |
| P1 LTE owner | PBCH variants/tracking/combining, then PDCCH/PDSCH SI-RNTI → SIB/RRC | LTE-2/3. Native bridge scope stays explicit; no MIB-only “LTE complete” claim. |
| P1 GPS owner | Native IQ fixture execution and complete LNAV fields/ephemeris/clock/page assembly | GPS-1/2; PVT separate. The newly integrated process path must be tested with actual IQ, not only monitor words. |
| P1 Iridium owner | Raw burst acquisition/timing/CFO then non-IRA frame families and reassembly | IRIDIUM-2/3. Pre-synchronized symbol captures only close an IRA downstream boundary. |
| P1 WiFi owner | Native rate-qualified DSSS frontend, DQPSK/CCK, OFDM; MAC semantic/reassembly owner can work independently | WIFI-1/2/3. Keep PHY packet delivery contract stable. |
| P1 Bluetooth owner | Connection/hop/AUX tracking and L2CAP/ATT; separate LE2M/coded and BR/EDR frontends | BLUETOOTH-1/2/3. Supplied-AA single-channel frames are not tracked connections. |
| P1 P25 owner | Finish PDU family/TSBK semantics and voice/link-control; independent CQPSK/Phase2 owner | P25-1/2/3. New unconfirmed PDU has header/packet checks, not all PDU modes. |
| P1 DECT owner | Bearer/multiframe state + DLC/NWK + remaining B protection/packet families | DECT-1/2/3. Caller frame_number/format is not automatic connection decoding. |
| P1 ZigBee upper-layer owner | APS fragments, ZDP/ZCL commands/attributes, replay/key-context policies | ZIGBEE-2/3. MAC CCM and alternate PHYs can be separate tasks; supplied-key NWK CCM already exists. |
| P1 Catalogue/RFID owner | Pinned rtl_433 all-device inventory; separate LF/HF/UHF RFID manifests/frontends | RTL433-1 and RFID-2/3. Installed catalogue/external client availability does not prove every advertised mode. |
| P2 Paging owner | FLEX long-address/message variants + independent all-rate POCSAG/Pager IQ cases | FLEX-1/2/3, POCSAG-1/2/3, PAGER-1/2/3. Preserve message-level integrity. |
| P2 Broadcast owner | Complete RDS group/ODA schema and IQ→MPX; APT Sync-B/telemetry/drift/calibration | RDS-1/2/3, APT-1/2/3. Group14A/PGM output alone are insufficient. |
| P2 Narrowband owner | Correct raw CW/FSK frontend and public RTTY mode parameters, all alphabet/timing fixtures | MORSE-1/2/3, RTTY-1/2/3. Existing synthetic audio and generic FM IQ are different input classes. |
| P2 LoRa owner | Fractional CFO/clock drift and full legal parameter grid; separate LoRaWAN semantics | LORA-1/2/3. Expanded SF/header/CRC modes are present, not all combinations independently demonstrated. |
| P2 Image owner | TEMPEST timing/origin acquisition and independent display-pattern evidence | TEMPEST-1/2/3. Fix exact pixel-clock handling; never certify arbitrary magnitude rasters as actual screens. |
| P2 ADSB owner | Missing TC/status/DF18 semantics; separate Mode-S AP/DP and UAT frontend | ADSB-1/2/3. Existing CPR/altitude expansion is not all surveillance messages. |

## Verification performed and remaining evidence

- Runtime registry enumeration completed using direct namespace loading: 24 aliases, 21 unique values. No radio selected.
- Executed `bundle exec rspec spec/lib/pwn/sdr/decoder_spec.rb spec/lib/pwn/sdr/decoder/base_spec.rb spec/lib/pwn/sdr/decoder/dsp_spec.rb` in `/opt/pwn`: **44 examples, 0 failures**. This verifies only that focused run; it is not a protocol-completeness metric.
- An earlier process launched from the research interpreter had a different gem environment and failed Bundler dependency materialization. The actual terminal environment ran the focused specs successfully. No package installation or lockfile changes were made by this audit.
- All module/spec inventory and acceptance-ID coverage are checked programmatically against `REGISTRY.values.uniq`; source/spec hashes identify what was read. No fabricated decoded frames or measurements are used.
- No full `rake`, complete optional-native matrix, sensitivity test or live RF test was run by this documentation audit. Concurrent implementation was active; run full gates after integration settles. Current normal rake/spec does not regenerate tracked module skills; `rake module_skills` is explicit. Neither this limitation nor a future green suite resolves the OPEN acceptance rows.
- Citation retrieval used direct HTTP and PDF text extraction because the configured web extractor was search-only. NOAA's old APT host failed DNS; the NOAA KLM guide was retrieved instead. Semtech's product page timed out; LoRa mode/synchronization context uses the retrieved independent implementation reference, not an unread manufacturer datasheet. The RDS commercial catalogue page was insufficient for clause-level claims; use the actual redsea reference and a pinned licensed standard for final conformance.

### Required completion artifacts

For every acceptance ID, attach a pinned standard clause/profile, supported-mode list, public entry-point command, source/fixture hash, independent expected decoded fields, negative/ciphertext outcomes, actual execution result, and end-to-end rate/latency evidence. Preserve unsupported variants and unavailable sources as OPEN. A finite catalogue row needs every pinned device ID, including disabled-by-default entries; a finite standard row needs every declared message/PHY combination, not an illustrative subset.

The historical matrix covers its enumerated registry and reviewed files, **not a declaration of exhaustive protocol conformance**. It intentionally does not claim completion from a test count.

## Sources

[1] https://www.etsi.org/deliver/etsi_ts/145000_145099/145002/19.00.00_60/ts_145002v190000p.pdf
[2] https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/physical-layer-specification.html
[3] https://www.gps.gov/sites/default/files/2025-07/IS-GPS-200N.pdf
[4] https://www.itu.int/rec/R-REC-M.1677
[8] https://www.ti.com/lit/an/spra193/spra193.pdf
[9] https://www.priority1design.com.au/em4100_protocol.html
[10] https://raw.githubusercontent.com/merbanan/rtl_433/master/README.md
[11] https://mode-s.org/1090mhz/content/ads-b/1-basics.html
[12] https://www.etsi.org/deliver/etsi_EN/300100_300199/30017503/02.08.01_60/en_30017503v020801p.pdf
[13] https://www.ieee802.org/11/Documents/DocumentArchives/1999_docs/90845b_p80211b-draft3.1.pdf
[14] https://raw.githubusercontent.com/boatbod/op25/master/op25/gr-op25_repeater/lib/p25p1_fdma.cc
[15] https://www.etsi.org/deliver/etsi_ts/136200_136299/136211/17.02.00_60/ts_136211v170200p.pdf
[16] https://www.ieee802.org/15/pub/TG4.html
[18] https://github.com/martinmarinov/TempestSDR
[19] https://www.itu.int/rec/R-REC-M.584
[20] https://www.itu.int/rec/T-REC-S.1
[21] https://raw.githubusercontent.com/tapparelj/gr-lora_sdr/master/README.md
[23] https://raw.githubusercontent.com/windytan/redsea/master/README.md
[24] https://raw.githubusercontent.com/secdev/scapy/master/scapy/layers/zigbee.py
[25] https://raw.githubusercontent.com/muccc/iridium-toolkit/master/FORMAT.md
[26] https://www.ncei.noaa.gov/pub/data/cdo/documentation/podguides/N-15%20thru%20N-19/pdf/2.1%20Section%204.0%20Real%20Time%20Data%20Systems%20for%20Local%20Users%20.pdf
