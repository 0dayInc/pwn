# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'

describe PWN::SDR::Decoder::Base do
  it 'responds to run_iq / resolve_iq_source' do
    expect(PWN::SDR::Decoder::Base).to respond_to(:run_iq)
    expect(PWN::SDR::Decoder::Base).to respond_to(:resolve_iq_source)
    expect(PWN::SDR::Decoder::Base).to respond_to(:unpack_iq)
    expect(PWN::SDR::Decoder::Base).to respond_to(:close_iq_source)
  end

  it 'resolves a cu8 capture file as an I/Q source' do
    Tempfile.create(['pwn-iq-', '.cu8']) do |file|
      file.binmode
      file.write(([127, 127] * 1024).pack('C*'))
      file.flush
      src = PWN::SDR::Decoder::Base.resolve_iq_source(
        freq_obj: { freq: 433_920_000 },
        source: :file,
        file: file.path,
        sample_rate: 250_000
      )
      expect(src).to be_a(Hash)
      expect(src[:kind]).to eq(:file)
      expect(src[:format]).to eq(:cu8)
      chunk = PWN::SDR::Decoder::Base.read_iq_chunk(source: src, bytes: 512)
      expect(chunk.bytesize).to eq(512)
      iq = PWN::SDR::Decoder::Base.unpack_iq(source: src, data: chunk)
      expect(iq.length).to eq(512) # interleaved I/Q floats
    ensure
      PWN::SDR::Decoder::Base.close_iq_source(source: src)
    end
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
    # Published identification example: https://mode-s.org/1090mhz/content/ads-b/2-identification.html
    bits = '8D4840D6202CC371C32CE0576098'.chars.flat_map { |c| c.to_i(16).to_s(2).rjust(4, '0').chars.map(&:to_i) }
    h = PWN::SDR::Decoder::ADSB.decode_modes(bits: bits)
    expect(h).to include(df: 17, icao24: '4840D6', type_code: 4, callsign: 'KLM1023')
  end
end
