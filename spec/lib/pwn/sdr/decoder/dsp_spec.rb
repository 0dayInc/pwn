# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::Decoder::DSP do
  it 'should display information for authors' do
    expect(PWN::SDR::Decoder::DSP).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::SDR::Decoder::DSP).to respond_to :help
  end

  it 'should expose a native toggle' do
    expect(PWN::SDR::Decoder::DSP).to respond_to :native
    expect(PWN::SDR::Decoder::DSP).to respond_to :native=
  end

  it 'should unpack s16le to unit-range floats (ruby path)' do
    was = PWN::SDR::Decoder::DSP.native
    PWN::SDR::Decoder::DSP.native = false
    raw = [0, 16_384, -16_384, 32_767].pack('s<*')
    out = PWN::SDR::Decoder::DSP.unpack_s16le(data: raw)
    expect(out[0]).to be_within(1e-6).of(0.0)
    expect(out[1]).to be_within(1e-3).of(0.5)
    expect(out[2]).to be_within(1e-3).of(-0.5)
    expect(out[3]).to be_within(1e-3).of(1.0)
  ensure
    PWN::SDR::Decoder::DSP.native = was
  end

  it 'should unpack s16le via Volk when available' do
    skip 'libvolk not installed' unless PWN::FFI.available?(mod: :Volk)

    was = PWN::SDR::Decoder::DSP.native
    PWN::SDR::Decoder::DSP.native = true
    raw = [0, 16_384, -16_384, 32_767].pack('s<*')
    out = PWN::SDR::Decoder::DSP.unpack_s16le(data: raw)
    expect(out[1]).to be_within(1e-3).of(0.5)
  ensure
    PWN::SDR::Decoder::DSP.native = was
  end

  it 'should resample pure-ruby and liquid paths to comparable length' do
    samples = Array.new(200) { |i| Math.sin(2 * Math::PI * i / 40.0) }

    was = PWN::SDR::Decoder::DSP.native
    PWN::SDR::Decoder::DSP.native = false
    ruby_out = PWN::SDR::Decoder::DSP.resample(samples: samples, src_rate: 48_000, dst_rate: 24_000)
    expect(ruby_out.length).to eq(100)

    if PWN::FFI.available?(mod: :Liquid)
      PWN::SDR::Decoder::DSP.native = true
      liq_out = PWN::SDR::Decoder::DSP.resample(samples: samples, src_rate: 48_000, dst_rate: 24_000)
      # multi-stage resampler length can differ by a few samples due to delay
      expect(liq_out.length).to be_between(90, 120)
    end
  ensure
    PWN::SDR::Decoder::DSP.native = was
  end
end
