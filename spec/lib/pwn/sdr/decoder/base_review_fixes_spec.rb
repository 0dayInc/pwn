# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::SDR::Decoder::Base, 'review exception ownership regression' do
  it 'PSR-L01 retains clean EOF when the caller is handling an unrelated exception' do
    demod = Object.new
    demod.define_singleton_method(:feed_iq) { |_samples, rate:| rate }
    demod.define_singleton_method(:flush) { |&emit| emit.call(event: 'clean-eof') }
    output = StringIO.new
    input = StringIO.new('')
    result = begin
      raise 'unrelated caller exception'
    rescue RuntimeError
      described_class.run_iq(freq_obj: {}, source: input, demod: demod,
                             output: output, log_file: false, interactive: false)
    end
    expect(output.string.lines.map { |line| JSON.parse(line)['event'] }).to eq(['clean-eof'])
    expect(result).to include(reason: :eof, capture_complete: true, frames: 1)
    expect(input).to be_closed
  end

  it 'preserves local supervisor interruption and prevents cleanup EOF finalization' do
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
                                 stop: -> { raise Interrupt, 'cancel fixture' },
                                 interactive: false, output: output, log_file: false)
    end.to raise_error(Interrupt, 'cancel fixture')
    expect(output.string).to be_empty
    expect(reader).to be_closed
    expect(threads).to all(satisfy { |thread| !thread.alive? })
  ensure
    [reader, writer].compact.each { |io| io.close unless io.closed? }
    threads&.each { |thread| thread.kill.join if thread.alive? }
  end
end
