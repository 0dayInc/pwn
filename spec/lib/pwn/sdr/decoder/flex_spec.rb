# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::Flex do
  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::Flex
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::Flex
    expect(help_response).to respond_to :help
  end

  # Regression: A_TABLE was mis-assigned so 929–932 MHz US FLEX (0xDEA0) never
  # locked and reported the wrong mode (see mistakes sig 827de20227fa).
  it 'maps every Sync-1 A-word to the correct symbol-rate/levels' do
    t = PWN::SDR::Decoder::Flex::A_TABLE
    expect(t[0x870C]).to eq([1600, 2])
    expect(t[0xB068]).to eq([1600, 4])
    expect(t[0x7B18]).to eq([3200, 2])
    expect(t[0xDEA0]).to eq([3200, 4])
    expect(t[0x4C7C]).to eq([3200, 4])
  end

  it 'detects Sync-1 in a 64-bit shift register at either polarity' do
    # A(0xDEA0) | MARKER(0xA6C6AAAA) | ~A(0x215F) — canonical 3200/4 Sync-1
    buf = (0xDEA0 << 48) | (0xA6C6AAAA << 16) | 0x215F
    code, pol = PWN::SDR::Decoder::Flex.sync_check(buf: buf)
    expect(code).to eq(0xDEA0)
    expect(pol).to eq(0)
    code, pol = PWN::SDR::Decoder::Flex.sync_check(buf: ~buf & 0xFFFFFFFFFFFFFFFF)
    expect(code).to eq(0xDEA0)
    expect(pol).to eq(1)
  end

  # Regression: FLEX BCH bit-ordering is reversed vs POCSAG. FIW 0xF27C46AE
  # (cycle 10 / frame 70, live 929.625 MHz capture) must have zero syndrome.
  it 'computes BCH(31,21) syndrome with FLEX on-air bit ordering' do
    fiw = 0xF27C46AE
    expect(PWN::SDR::Decoder::Flex.bch_syn(word: fiw)).to eq(0)
    fixed, nerr = PWN::SDR::Decoder::Flex.bch_fix(word: fiw)
    expect(fixed).to eq(fiw)
    expect(nerr).to eq(0)
    # single-bit correction
    fixed, nerr = PWN::SDR::Decoder::Flex.bch_fix(word: fiw ^ (1 << 5))
    expect(fixed).to eq(fiw)
    expect(nerr).to eq(1)
  end

  # Regression: Demod#try_lock hardcoded a single A-word so it never locked on
  # anything but 1600/2. Synthesise the exact Sync-1 + FIW discriminator wave
  # for 3200/4 and require the demod to lock and decode cycle/frame.
  it 'locks on a synthesised 3200/4 Sync-1 and recovers cycle/frame from FIW' do
    rate = 48_000
    spb  = rate / 1600
    hi   = 0.9
    # bit convention (verified live): read_2fsk bit = (sample > 0)
    fiw = 0xF27C46AE
    fiw_bits = Array.new(32) { |i| (fiw >> i) & 1 } # LSB first on air
    # Sync-1 uses (sym < 2) → 1, i.e. NEGATIVE sample → bit=1
    sync_bits = 'DEA0A6C6AAAA215F'.chars.flat_map do |h|
      n = h.to_i(16)
      [3, 2, 1, 0].map { |i| (n >> i) & 1 }
    end
    lead   = Array.new(160) { |i| i.even? ? 1 : 0 } # dotting so PLL locks
    stream = lead + sync_bits + Array.new(16) { |i| i.even? ? 1 : 0 } + fiw_bits
    # sync-bit=1 → negative; FIW bit=1 → positive. Same wire, opposite conv:
    # a sample level v gives sync_bit=(v<0)?1:0 AND fiw_bit=(v>0)?1:0. So one
    # physical waveform carries both — encode via sync convention throughout,
    # FIW bits therefore need to be inverted before mapping to samples.
    fiw_phys = fiw_bits.map { |b| 1 - b }
    stream = lead + sync_bits + Array.new(16, 0) + fiw_phys
    samples = stream.flat_map { |b| Array.new(spb, b == 1 ? -hi : hi) }
    d = PWN::SDR::Decoder::Flex::Demod.new(rate: rate)
    d.feed(samples) { |_m| nil }
    expect(d.instance_variable_get(:@mode)).to eq([3200, 4])
    expect(d.instance_variable_get(:@cycle)).to eq(10)
    expect(d.instance_variable_get(:@frame)).to eq(70)
  end
end
