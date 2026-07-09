# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::FFTW do
  it 'should display information for authors' do
    expect(PWN::FFI::FFTW).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::FFTW).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::FFTW).to respond_to :available?
  end

  it 'should compute an rfft impulse response when libfftw3f is present' do
    skip 'libfftw3f not installed' unless PWN::FFI::FFTW.available?

    spec = PWN::FFI::FFTW.rfft(samples: [1.0, 0, 0, 0, 0, 0, 0, 0])
    expect(spec.length).to eq(5) # n/2+1
    expect(spec[0][0]).to be_within(1e-5).of(1.0)
    expect(spec[0][1]).to be_within(1e-5).of(0.0)
  end
end
