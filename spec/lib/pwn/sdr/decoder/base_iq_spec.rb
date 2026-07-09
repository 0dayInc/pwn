# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::Base do
  it 'responds to run_iq / resolve_iq_source' do
    expect(PWN::SDR::Decoder::Base).to respond_to(:run_iq)
    expect(PWN::SDR::Decoder::Base).to respond_to(:resolve_iq_source)
    expect(PWN::SDR::Decoder::Base).to respond_to(:unpack_iq)
    expect(PWN::SDR::Decoder::Base).to respond_to(:close_iq_source)
  end

  it 'resolves a cu8 capture file as an I/Q source' do
    path = '/tmp/pwn_iq_test.cu8'
    File.binwrite(path, ([127, 127] * 1024).pack('C*'))
    src = PWN::SDR::Decoder::Base.resolve_iq_source(
      freq_obj: { freq: 433_920_000 },
      source: :file,
      file: path,
      sample_rate: 250_000
    )
    expect(src).to be_a(Hash)
    expect(src[:kind]).to eq(:file)
    expect(src[:format]).to eq(:cu8)
    chunk = PWN::SDR::Decoder::Base.read_iq_chunk(source: src, bytes: 512)
    expect(chunk.bytesize).to eq(512)
    iq = PWN::SDR::Decoder::Base.unpack_iq(source: src, data: chunk)
    expect(iq.length).to eq(512) # interleaved I/Q floats
    PWN::SDR::Decoder::Base.close_iq_source(source: src)
  ensure
    FileUtils.rm_f(path)
  end
end

describe PWN::SDR::Decoder::DSP do
  it 'unpacks cu8 / cs16 and computes mag_sq / fm_demod_iq' do
    cu8 = [127, 127, 200, 50].pack('C*')
    expect(PWN::SDR::Decoder::DSP.unpack_cu8(data: cu8).length).to eq(4)
    cs16 = [1000, -1000].pack('s<*')
    expect(PWN::SDR::Decoder::DSP.unpack_cs16le(data: cs16).length).to eq(2)
    iq = [0.5, 0.0, 0.0, 0.5, -0.5, 0.0]
    m2 = PWN::SDR::Decoder::DSP.mag_sq(iq: iq)
    expect(m2.length).to eq(3)
    # Liquid freqdem returns n samples; pure-Ruby path returns n-1
    fm = PWN::SDR::Decoder::DSP.fm_demod_iq(iq: iq)
    expect(fm.length).to be_between(2, 3)
  end
end

describe PWN::SDR::Decoder::ADSB do
  it 'decodes Mode-S DF17 identity fields from a bit vector' do
    bits = Array.new(112, 0)
    # DF = 17 (10001)
    [1, 0, 0, 0, 1].each_with_index { |b, i| bits[i] = b }
    # ICAO = 0xABC123 → 24 bits starting at bit 8
    icao = 0xABC123
    24.times { |i| bits[8 + i] = (icao >> (23 - i)) & 1 }
    # TC = 4 (identity) at bits 32..36
    [0, 0, 1, 0, 0].each_with_index { |b, i| bits[32 + i] = b }
    h = PWN::SDR::Decoder::ADSB.decode_modes(bits: bits)
    expect(h[:df]).to eq(17)
    expect(h[:icao24]).to eq('ABC123')
    expect(h[:type_code]).to eq(4)
  end
end
