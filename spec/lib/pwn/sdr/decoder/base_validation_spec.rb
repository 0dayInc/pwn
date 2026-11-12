# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

RSpec.describe PWN::SDR::Decoder::Base do
  def silent_demod
    Object.new.tap do |demod|
      demod.define_singleton_method(:feed_iq) { |_samples, rate:| rate }
    end
  end

  [0, -1].each do |rate|
    it "rejects configured sample rate #{rate} before resolving a source" do
      allow(described_class).to receive(:resolve_iq_source).and_return(kind: :io, io: StringIO.new(''))
      expect do
        described_class.run_iq(freq_obj: {}, sample_rate: rate, demod: silent_demod,
                               interactive: false, output: StringIO.new, log_file: false)
      end.to raise_error(ArgumentError, /sample_rate.*positive/)
      expect(described_class).not_to have_received(:resolve_iq_source)
    end
  end

  [0, -1, Float::NAN, Float::INFINITY].each do |rate|
    it "rejects descriptor rate #{rate} even for empty captures before flushing" do
      input = StringIO.new('')
      demod = silent_demod
      expect(demod).not_to receive(:flush)
      expect do
        described_class.run_iq(freq_obj: {}, source: { kind: :io, io: input, rate_hz: rate }, demod: demod,
                               interactive: false, output: StringIO.new, log_file: false)
      end.to raise_error(ArgumentError, /rate.*finite.*positive/)
      expect(input).to be_closed
    end
  end

  it 'does not finalize or emit when supervisor failure unblocks a pipe during cleanup' do
    reader, writer = IO.pipe
    threads = []
    allow(Thread).to receive(:new).and_wrap_original do |original, *args, &block|
      original.call(*args, &block).tap { |thread| threads << thread }
    end
    demod = Object.new
    demod.define_singleton_method(:feed) { |_samples| nil }
    demod.define_singleton_method(:flush) { |&emit| emit.call(event: 'incorrect-finalization') }
    output = StringIO.new
    cancel_read = lambda do
      writer.close unless writer.closed?
      threads.each { |thread| thread.join(1) }
    end
    expect do
      described_class.run_native(freq_obj: {}, source: reader, demod: demod, cancel_read: cancel_read,
                                 stop: -> { raise IOError, 'supervisor failed' },
                                 interactive: false, output: output, log_file: false)
    end.to raise_error(IOError, 'supervisor failed')
    expect(output.string).to be_empty
    expect(reader).to be_closed
    expect(threads).to all(satisfy { |thread| !thread.alive? })
  ensure
    [reader, writer].compact.each { |io| io.close unless io.closed? }
    threads&.each { |thread| thread.kill.join if thread.alive? }
  end

  it 'rejects unsupported formats before waiting on an idle pipe or flushing empty input' do
    reader, writer = IO.pipe
    demod = silent_demod
    expect(demod).not_to receive(:flush)
    expect do
      Timeout.timeout(1) do
        described_class.run_iq(freq_obj: {}, source: reader, iq_format: :cf32, demod: demod,
                               interactive: false, output: StringIO.new, log_file: false)
      end
    end.to raise_error(ArgumentError, /Unsupported IQ format/)
    expect(reader).to be_closed
  ensure
    [reader, writer].compact.each { |io| io.close unless io.closed? }
  end
end
