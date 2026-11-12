# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::SoapySDR do
  it 'handles a missing shared library without native calls' do
    allow(described_class).to receive(:available?).and_return(false)
    expect(described_class.info).to include(available: false)
    expect { described_class.make(args: 'driver=mock') }.to raise_error(RuntimeError, /libSoapySDR not available/)
  end

  %i[setSampleRate setFrequency setGainMode setGain setBandwidth].each do |operation|
    it "rejects failed #{operation} without publishing requested configuration as applied" do
      operations = %i[setSampleRate setFrequency setGainMode setGain setBandwidth]
      operations.each { |name| allow(described_class).to receive(:"SoapySDRDevice_#{name}").and_return(0) }
      allow(described_class).to receive(:"SoapySDRDevice_#{operation}").and_return(-2)
      handle = { device: :device, channel: 0, rate_hz: 12_000, freq_hz: 100_000_000 }
      expect do
        described_class.configure(handle: handle, rate_hz: 24_000, freq_hz: 101_000_000, gain_db: 12, bw_hz: 20_000)
      end.to raise_error(RuntimeError, /#{operation}.*-2/)
      expect(handle).to include(rate_hz: 12_000, freq_hz: 100_000_000)
    end
  end

  it 'reports close failure and retains the stream for cleanup retry' do
    handle = { device: :device, stream: :stream }
    allow(described_class).to receive(:SoapySDRDevice_deactivateStream).and_return(0)
    allow(described_class).to receive(:SoapySDRDevice_closeStream).and_return(-2)
    expect { described_class.stop_rx(handle: handle) }.to raise_error(/closeStream.*-2/)
    expect(handle[:stream]).to eq(:stream)
  end

  it 'closes a newly created stream when activation fails' do
    stream = FFI::MemoryPointer.new(:char)
    allow(described_class).to receive(:SoapySDRDevice_setupStream).and_return(stream)
    allow(described_class).to receive(:SoapySDRDevice_activateStream).and_return(-2)
    allow(described_class).to receive(:SoapySDRDevice_lastError).and_return('failed')
    expect(described_class).to receive(:SoapySDRDevice_closeStream).with(:device, stream)
    expect { described_class.start_rx(handle: { device: :device, channel: 0 }) }.to raise_error(/activateStream/)
  end

  it 'raises on overflow rather than disguising lost IQ as timeout' do
    allow(described_class).to receive(:SoapySDRDevice_readStream).and_return(-4)
    handle = { stream: :mock }
    expect { described_class.read_sync(handle: handle) }.to raise_error(/overrun.*-4/i)
    expect(handle[:overruns]).to eq(1)
  end

  it 'should display information for authors' do
    expect(PWN::FFI::SoapySDR).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(PWN::FFI::SoapySDR).to respond_to :help
  end

  it 'should respond to available?' do
    expect(PWN::FFI::SoapySDR).to respond_to :available?
  end

  it 'should report API info', :soapy_sdr_integration do
    expect(described_class.available?).to be(true), 'Install libSoapySDR and make it visible to the dynamic loader (PWN_TEST_SOAPY_SDR=1).'

    info = PWN::FFI::SoapySDR.info
    expect(info[:available]).to eq(true)
    expect(info[:api]).to match(/\d+\.\d+/)
  end
end
