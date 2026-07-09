# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::Volk do
  it 'should display information for authors' do
    expect(PWN::FFI::Volk).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::Volk).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::Volk).to respond_to :available?
  end

  it 'should unpack s16le to unit-range floats when libvolk is present' do
    skip 'libvolk not installed' unless PWN::FFI::Volk.available?

    raw = [0, 16_384, -16_384, 32_767].pack('s<*')
    out = PWN::FFI::Volk.unpack_s16le(data: raw)
    expect(out.length).to eq(4)
    expect(out[0]).to be_within(1e-5).of(0.0)
    expect(out[1]).to be_within(1e-3).of(0.5)
    expect(out[2]).to be_within(1e-3).of(-0.5)
    expect(out[3]).to be_within(1e-3).of(1.0)
  end

  it 'should accumulate floats when libvolk is present' do
    skip 'libvolk not installed' unless PWN::FFI::Volk.available?

    sum = PWN::FFI::Volk.accumulate(samples: [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])
    expect(sum).to be_within(1e-4).of(36.0)
  end
end
