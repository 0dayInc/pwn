# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::Liquid do
  it 'should display information for authors' do
    expect(PWN::FFI::Liquid).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::Liquid).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::Liquid).to respond_to :available?
  end

  it 'should resample at half rate when libliquid is present' do
    skip 'libliquid not installed' unless PWN::FFI::Liquid.available?

    samples = Array.new(64) { |i| Math.sin(2 * Math::PI * i / 16.0) }
    out = PWN::FFI::Liquid.resample(samples: samples, rate: 0.5)
    expect(out.length).to be_between(24, 40)
  end

  it 'should FM-demod a complex tone when libliquid is present' do
    skip 'libliquid not installed' unless PWN::FFI::Liquid.available?

    iq = []
    phase = 0.0
    dphi = 2 * Math::PI * 0.05
    64.times do
      iq << Math.cos(phase)
      iq << Math.sin(phase)
      phase += dphi
    end
    audio = PWN::FFI::Liquid.freq_demod(iq: iq, kf: 0.5)
    expect(audio.length).to eq(64)
    # after settle, demod of constant dphi ≈ 0.1 (2*dphi when kf=0.5 → dphi/kf)
    expect(audio[10]).to be_within(0.05).of(0.1)
  end
end
