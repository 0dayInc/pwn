# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::FFTW do
  it 'handles a missing shared library without native calls' do
    allow(described_class).to receive(:available?).and_return(false)
    expect { described_class.rfft(samples: [1.0]) }.to raise_error(RuntimeError, /libfftw3f not available/)
  end

  { rfft: :fftwf_plan_dft_r2c_1d, cfft: :fftwf_plan_dft_1d }.each do |method, planner|
    %i[allocation planning execution].each do |failure|
      it "releases #{method} native allocations on #{failure} failure" do
        allow(described_class).to receive(:available?).and_return(true)
        input = FFI::MemoryPointer.new(:float, 4)
        output = FFI::MemoryPointer.new(:float, 4)
        plan = FFI::MemoryPointer.new(:char)
        allow(described_class).to receive(:fftwf_malloc).and_return(input, failure == :allocation ? FFI::Pointer::NULL : output)
        allow(described_class).to receive(planner).and_return(failure == :planning ? FFI::Pointer::NULL : plan)
        allow(described_class).to receive(:fftwf_execute).and_raise(IOError, 'execution failed')
        expect(described_class).to receive(:fftwf_free).with(input).once
        expect(described_class).to receive(:fftwf_free).with(output).once unless failure == :allocation
        expect(described_class).to receive(:fftwf_destroy_plan).with(plan).once if failure == :execution
        expect { described_class.public_send(method, samples: [1.0, 0.0], iq: [1.0, 0.0]) }
          .to raise_error(StandardError, /failed/)
      end
    end
  end

  it 'should display information for authors' do
    expect(PWN::FFI::FFTW).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::FFTW).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::FFTW).to respond_to :available?
  end

  it 'should compute an rfft impulse response', :fftw_integration do
    expect(described_class.available?).to be(true), 'Install libfftw3f and make it visible to the dynamic loader (PWN_TEST_FFTW=1).'

    spec = PWN::FFI::FFTW.rfft(samples: [1.0, 0, 0, 0, 0, 0, 0, 0])
    expect(spec.length).to eq(5) # n/2+1
    expect(spec[0][0]).to be_within(1e-5).of(1.0)
    expect(spec[0][1]).to be_within(1e-5).of(0.0)
  end
end
