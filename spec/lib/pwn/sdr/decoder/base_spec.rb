# frozen_string_literal: true

require 'spec_helper'
require 'stringio'
require 'timeout'
require 'tempfile'
require 'socket'

describe PWN::SDR::Decoder::Base do
  it('exposes authors') { expect(described_class).to respond_to(:authors) }
  it('exposes help') { expect(described_class).to respond_to(:help) }

  it 'rejects unsupported IQ formats instead of interpreting them as unsigned bytes' do
    expect do
      described_class.unpack_iq(source: { format: :cf32 }, data: [0.5, -0.5].pack('e*'))
    end.to raise_error(ArgumentError, /Unsupported IQ format/)
  end

  it 'streams fragmented native audio through a real socket and logs ordered JSONL' do
    reader, writer = UNIXSocket.pair
    output = StringIO.new
    received = Queue.new
    demod = Object.new
    demod.define_singleton_method(:feed) { |samples, &emit| samples.each { |sample| emit.call(sample: sample) } }
    Tempfile.create('decoder-log') do |log|
      worker = Thread.new do
        described_class.run_native(freq_obj: {}, source: reader, demod: demod, chunk_bytes: 1,
                                   output: output, on_frame: ->(frame) { received << frame },
                                   interactive: false, log_file: log.path)
      end
      worker.report_on_exception = false
      writer.write([1024, -2048].pack('s<*'))
      frames = Timeout.timeout(2) { [received.pop, received.pop] }
      expect(writer).not_to be_closed
      writer.close
      Timeout.timeout(2) { worker.value }
      expect(frames.map { |f| f[:sample] }).to eq([1024 / 32_768.0, -2048 / 32_768.0])
      expect(File.readlines(log.path).map { |line| JSON.parse(line) }).to eq(output.string.lines.map { |line| JSON.parse(line) })
      expect(reader).to be_closed
    ensure
      writer.close unless writer.closed?
      worker&.kill
      begin
        worker&.join
      rescue StandardError
        nil
      end
    end
  ensure
    reader&.close unless reader&.closed?
  end

  %i[run_native run_iq].each do |runner|
    it "flushes #{runner} exactly once after queued frames with serialized output and callbacks" do
      reader, writer = IO.pipe
      output = StringIO.new
      received = Queue.new
      flushes = 0
      worker = nil
      demod = Object.new
      demod.define_singleton_method(:feed) { |_samples, &emit| emit.call(event: 'feed') }
      demod.define_singleton_method(:flush) do |&emit|
        flushes += 1
        emit.call(event: 'flush')
      end
      Tempfile.create('decoder-flush') do |log|
        callback = lambda do |frame|
          expect(JSON.parse(output.string.lines.last)['event']).to eq(frame[:event])
          expect(JSON.parse(File.readlines(log.path).last)['event']).to eq(frame[:event])
          received << frame[:event]
        end
        worker = Thread.new do
          described_class.public_send(runner, freq_obj: {}, source: reader, demod: demod,
                                              chunk_bytes: 2, output: output, on_frame: callback,
                                              interactive: false, log_file: log.path)
        end
        worker.report_on_exception = false
        writer.write([128, 129].pack('C*'))
        expect(Timeout.timeout(2) { received.pop }).to eq('feed')
        expect(flushes).to eq(0)
        writer.close
        result = Timeout.timeout(2) { worker.value }
        expect(flushes).to eq(1)
        expect(received.pop).to eq('flush')
        expect(result).to include(reason: :eof, frames: 2, chunks_processed: 1, bytes_processed: 2)
        expect(reader).to be_closed
      end
    ensure
      writer&.close unless writer&.closed?
      worker&.kill
      worker&.join
      reader&.close unless reader&.closed?
    end
  end

  %i[run_native run_detector run_iq].each do |runner|
    it "rejects a #{runner} source rate that differs from the configured audio timing" do
      reader, writer = IO.pipe
      demod = Object.new
      demod.define_singleton_method(:feed) { |_samples| raise 'must not feed mismatched samples' }
      source = { kind: :io, io: reader, format: :cu8, rate_hz: 96_000 }
      expect do
        Timeout.timeout(2) do
          described_class.public_send(runner, freq_obj: {}, source: source, demod: demod,
                                              rate: 48_000, sample_rate: 48_000, fm_demod: true,
                                              interactive: false, output: StringIO.new, log_file: false)
        end
      end.to raise_error(ArgumentError, /source rate.*96000.*configured.*48000/i)
      expect(reader).to be_closed
    ensure
      writer&.close unless writer&.closed?
      reader&.close unless reader&.closed?
    end
  end

  %i[run_native run_iq].each do |runner|
    it "propagates #{runner} EOF flush failures without retrying" do
      source = StringIO.new('')
      flushes = 0
      demod = Object.new
      demod.define_singleton_method(:feed) { |_samples| nil }
      demod.define_singleton_method(:flush) do
        flushes += 1
        raise IOError, 'flush failed'
      end
      expect do
        described_class.public_send(runner, freq_obj: {}, source: source, demod: demod,
                                            interactive: false, output: StringIO.new, log_file: false)
      end.to raise_error(IOError, 'flush failed')
      expect(flushes).to eq(1)
      expect(source).to be_closed
    end
  end

  it 'passes the actual descriptor rate to rate-aware IQ demodulators' do
    rates = []
    demod = Object.new
    demod.define_singleton_method(:feed_iq) { |_iq, rate:| rates << rate }
    result = described_class.run_iq(freq_obj: {}, source: { kind: :io, io: StringIO.new("\x80\x80"), rate_hz: 96_000 },
                                    sample_rate: 48_000, demod: demod, interactive: false,
                                    output: StringIO.new, log_file: false)
    expect(result[:reason]).to eq(:eof)
    expect(rates).to eq([96_000])
  end

  it 'accepts a matching nondefault audio source rate' do
    demod = Object.new
    samples = []
    demod.define_singleton_method(:feed) { |chunk| samples.concat(chunk) }
    result = described_class.run_native(freq_obj: {}, source: { io: StringIO.new([1024].pack('s<')), rate_hz: 96_000 },
                                        rate: 96_000, demod: demod, interactive: false,
                                        output: StringIO.new, log_file: false)
    expect(result[:reason]).to eq(:eof)
    expect(samples).to eq([1024 / 32_768.0])
  end

  it 'emits detector bursts from a finite audio fixture and exits on EOF' do
    Tempfile.create('decoder-audio') do |file|
      file.binmode
      file.write((([10] * 32) + ([20_000] * 32) + ([10] * 32)).pack('s<*'))
      file.flush
      frames = []
      Timeout.timeout(2) do
        described_class.run_detector(freq_obj: {}, file: file.path, chunk_bytes: 64,
                                     output: StringIO.new, interactive: false, log_file: false,
                                     on_frame: ->(frame) { frames << frame })
      end
      expect(frames.length).to eq(1)
      expect(frames.first[:event]).to eq('burst')
    end
  end
end

describe PWN::SDR::Decoder::Base do
  it 'returns bounded-stream accounting without losing queued samples' do
    source = StringIO.new([128, 129].pack('C*') * 100)
    frames = []
    demod = Object.new
    demod.define_singleton_method(:feed_iq) do |iq, rate:, &emit|
      sleep 0.001
      emit.call(samples: iq.length / 2, rate: rate)
    end
    result = described_class.run_iq(freq_obj: {}, source: source, demod: demod,
                                    chunk_bytes: 2, queue_size: 2, output: StringIO.new,
                                    interactive: false, log_file: false, on_frame: ->(f) { frames << f })
    expect(result[:reason]).to eq(:eof)
    expect(result[:bytes_processed]).to eq(200)
    expect(result[:chunks_processed]).to eq(100)
    expect(result[:frames]).to eq(100)
    expect(result[:queue_high_water]).to be <= 2
    expect(result[:backpressure_waits]).to be > 0
    expect(frames.sum { |frame| frame[:samples] }).to eq(100)
  end

  %i[run_iq run_native run_detector].each do |runner|
    %i[duration stop].each do |control|
      it "stops #{runner} with #{control} while a pipe read is blocked and joins its threads" do
        reader, writer = IO.pipe
        demod = Object.new
        demod.define_singleton_method(:feed) { |_samples, &_emit| nil }
        expect(demod).not_to receive(:flush)
        before = Thread.list
        options = { freq_obj: {}, source: reader, demod: demod, output: StringIO.new,
                    interactive: false, log_file: false }
        options[control] = control == :duration ? 0.02 : -> { true }
        result = Timeout.timeout(2) { described_class.public_send(runner, options) }
        expect(result[:reason]).to eq(control)
        expect(reader).to be_closed
        expect(Thread.list - before).to be_empty
      ensure
        writer&.close unless writer&.closed?
        reader&.close unless reader&.closed?
      end
    end
  end

  it 'propagates decoder and callback failures and closes blocked producers' do
    %i[demod callback].each do |failure|
      reader, writer = IO.pipe
      writer.write([128, 129].pack('C*'))
      demod = Object.new
      demod.define_singleton_method(:feed_iq) do |_iq, rate:, &emit|
        raise 'broken demod' if failure == :demod

        emit.call(rate: rate)
      end
      expect(demod).not_to receive(:flush)
      before = Thread.list
      expect do
        Timeout.timeout(2) do
          described_class.run_iq(freq_obj: {}, source: reader, demod: demod, output: StringIO.new,
                                 interactive: false, log_file: false, on_frame: ->(_f) { raise 'broken callback' })
        end
      end.to raise_error(RuntimeError, "broken #{failure}")
      expect(reader).to be_closed
      expect(Thread.list - before).to be_empty
    ensure
      writer&.close unless writer&.closed?
      reader&.close unless reader&.closed?
    end
  end

  %i[run_native run_iq].each do |runner|
    it "does not flush #{runner} when a reader failure closes the queue" do
      source = StringIO.new("\x80\x80")
      source.define_singleton_method(:readpartial) do |_bytes|
        sleep 0.01
        raise IOError, 'broken reader'
      end
      flushed = false
      demod = Object.new
      demod.define_singleton_method(:feed) { |_samples| nil }
      demod.define_singleton_method(:flush) { flushed = true }
      expect do
        described_class.public_send(runner, freq_obj: {}, source: source, demod: demod,
                                            stop: -> { sleep(0.05) && false },
                                            interactive: false, output: StringIO.new, log_file: false)
      end.to raise_error(IOError, 'broken reader')
      expect(flushed).to be(false)
      expect(source).to be_closed
    end
  end

  it 'surfaces reader IO failures rather than converting them into EOF' do
    source = StringIO.new('')
    source.close
    demod = Object.new
    demod.define_singleton_method(:feed) { |_samples| nil }
    expect do
      Timeout.timeout(2) do
        described_class.run_iq(freq_obj: {}, source: source, demod: demod,
                               interactive: false, output: StringIO.new, log_file: false)
      end
    end.to raise_error(IOError)
  end

  it 'preserves fragmented cs16 samples and FM phase across chunk boundaries' do
    raw = [20_000, 0, 0, 20_000, -20_000, 0, 0, -20_000].pack('s<*')
    audio = []
    demod = Object.new
    demod.define_singleton_method(:feed) { |samples| audio.concat(samples) }
    described_class.run_iq(freq_obj: {}, source: StringIO.new(raw), iq_format: :cs16,
                           demod: demod, fm_demod: true, chunk_bytes: 3,
                           interactive: false, output: StringIO.new, log_file: false)
    expected = PWN::SDR::Decoder::DSP.fm_demod_iq(iq: PWN::SDR::Decoder::DSP.unpack_cs16le(data: raw))
    expect(audio.length).to eq(3)
    expect(audio).to eq(expected)
  end

  it 'reports incomplete IQ and audio samples at EOF rather than dropping bytes' do
    %i[run_iq run_native].each do |runner|
      demod = Object.new
      demod.define_singleton_method(:feed) { |_samples| nil }
      expect(demod).not_to receive(:flush)
      expect do
        described_class.public_send(runner, freq_obj: {}, source: StringIO.new("\x01"), demod: demod,
                                            interactive: false, output: StringIO.new, log_file: false)
      end.to raise_error(IOError, /Incomplete/)
    end
  end

  it 'keeps GQRX strength polling available when the detector UDP port cannot bind' do
    socket = Object.new
    allow(PWN::SDR::GQRX).to receive(:listen_udp).and_raise(Errno::EADDRINUSE)
    allow(PWN::SDR::GQRX).to receive(:cmd).with(gqrx_sock: socket, cmd: 'l STRENGTH').and_return('-90', '-30', '-90')
    frames = []
    result = Timeout.timeout(2) do
      described_class.run_detector(freq_obj: { gqrx_sock: socket }, interactive: false,
                                   output: StringIO.new, log_file: false,
                                   stop: -> { !frames.empty? }, on_frame: ->(f) { frames << f })
    end
    expect(result[:reason]).to eq(:stop)
    expect(frames.first[:peak_dbfs]).to eq(-30)
  end

  it 'rejects unavailable explicit capture files rather than silently opening hardware or detector' do
    expect do
      described_class.resolve_iq_source(freq_obj: {}, file: '/nonexistent/pwn-fixture.cu8', source: :file)
    end.to raise_error(Errno::ENOENT)
  end

  it 'closes a hardware handle and surfaces explicit source setup failures' do
    allow(PWN::FFI).to receive(:available?).with(mod: :RTLSdr).and_return(true)
    allow(PWN::FFI::RTLSdr).to receive(:list_devices).and_return([{}])
    allow(PWN::FFI::RTLSdr).to receive(:open).and_return(:device)
    allow(PWN::FFI::RTLSdr).to receive(:configure).and_raise(IOError, 'configuration failed')
    expect(PWN::FFI::RTLSdr).to receive(:close).with(device: :device)
    expect do
      described_class.resolve_iq_source(freq_obj: {}, source: :rtlsdr)
    end.to raise_error(IOError, 'configuration failed')
  end

  it 'aborts an IQ discontinuity and preserves loss telemetry on the surfaced error' do
    handle = { overruns: 0, dropped_bytes: 0 }
    source = { kind: :hackrf, format: :cs8, handle: handle }
    allow(PWN::FFI::HackRF).to receive(:read_sync) do
      handle[:overruns] = 1
      handle[:dropped_bytes] = 512
      raise IOError, 'RX continuity lost'
    end
    allow(PWN::FFI::HackRF).to receive(:stop_rx) { handle.clear }
    demod = Object.new
    demod.define_singleton_method(:feed) { |_samples| raise 'must not decode lost stream' }
    expect do
      described_class.run_iq(freq_obj: {}, source: source, demod: demod, interactive: false,
                             output: StringIO.new, log_file: false)
    end.to raise_error(IOError, 'RX continuity lost') { |error|
      expect(error.stream_stats).to include(overruns: 1, dropped_bytes: 512, discontinuity: true,
                                            capture_complete: false, error_class: 'IOError')
    }
  end

  it 'does not treat hardware read timeouts as capture EOF and keeps unknown counts nil' do
    handle = {}
    source = { kind: :soapy, format: :cs16, handle: handle }
    allow(PWN::FFI::SoapySDR).to receive(:read_sync).and_return(nil, [1, 2].pack('s<*'))
    allow(PWN::FFI::SoapySDR).to receive(:close)
    frames = []
    demod = Object.new
    demod.define_singleton_method(:feed_iq) { |_iq, rate:, &emit| emit.call(rate: rate) }
    result = Timeout.timeout(2) do
      described_class.run_iq(freq_obj: {}, source: source, demod: demod, interactive: false,
                             output: StringIO.new, log_file: false, on_frame: ->(f) { frames << f },
                             stop: -> { !frames.empty? })
    end
    expect(result[:reason]).to eq(:stop)
    expect(result[:overruns]).to be_nil
    expect(result[:dropped_bytes]).to be_nil
    expect(frames).not_to be_empty
  end

  it 'rejects IQ with pre-existing overrun telemetry before handing samples to the demodulator' do
    source = { kind: :io, io: StringIO.new("\x80\x80"), format: :cu8, handle: { overruns: 2 } }
    demod = Object.new
    expect(demod).not_to receive(:feed)
    allow(demod).to receive(:feed)
    expect do
      described_class.run_iq(freq_obj: {}, source: source, demod: demod, interactive: false,
                             output: StringIO.new, log_file: false)
    end.to raise_error(IOError, /continuity lost/)
  end

  it 'limits default IQ read batches for low latency' do
    source = StringIO.new("\x80" * 65_536)
    lengths = []
    demod = Object.new
    demod.define_singleton_method(:feed_iq) { |iq, **_opts| lengths << iq.length }
    described_class.run_iq(freq_obj: {}, source: source, demod: demod,
                           interactive: false, output: StringIO.new, log_file: false)
    expect(lengths.max).to be <= 16_384
    expect(lengths.sum).to eq(65_536)
  end

  it 'stops with a full queue and a blocked callback without leaking threads' do
    source = StringIO.new("\x80" * 100)
    entered = Queue.new
    blocked = Queue.new
    demod = Object.new
    demod.define_singleton_method(:feed_iq) { |_iq, rate:, &emit| emit.call(rate: rate) }
    before = Thread.list
    callback = lambda do |_frame|
      entered << true
      blocked.pop
    end
    result = Timeout.timeout(2) do
      described_class.run_iq(freq_obj: {}, source: source, demod: demod, chunk_bytes: 2, queue_size: 1,
                             interactive: false, output: StringIO.new, log_file: false,
                             stop: -> { !entered.empty? }, on_frame: callback)
    end
    expect(result[:reason]).to eq(:stop)
    expect(source).to be_closed
    expect(Thread.list - before).to be_empty
  end

  it 'does not truncate UDP audio datagrams to chunk_bytes and flushes output before closure' do
    receiver = UDPSocket.new
    receiver.bind('127.0.0.1', 0)
    sender = UDPSocket.new
    output_reader, output_writer = IO.pipe
    frames = []
    demod = Object.new
    demod.define_singleton_method(:feed) { |samples, &emit| emit.call(samples: samples.length) }
    worker = Thread.new do
      described_class.run_native(freq_obj: {}, source: receiver, demod: demod, chunk_bytes: 2,
                                 interactive: false, output: output_writer, log_file: false,
                                 stop: -> { !frames.empty? }, on_frame: ->(f) { frames << f })
    end
    worker.report_on_exception = false
    sender.send([123].pack('s<') * 4_000, 0, '127.0.0.1', receiver.addr[1])
    frame = Timeout.timeout(2) { JSON.parse(output_reader.gets) }
    expect(frame['samples']).to eq(4_000)
    expect(output_writer).not_to be_closed
    Timeout.timeout(2) { worker.value }
    expect(receiver).to be_closed
  ensure
    worker&.kill
    worker&.join
    [sender, receiver, output_reader, output_writer].compact.each { |io| io.close unless io.closed? }
  end

  it 'emits IQ frames before pipe EOF and exits on EOF without ENTER' do
    # Keep interactive mode on, but model an idle keyboard, not the rake terminal.
    allow($stdin).to receive(:read_nonblock).with(1, exception: false).and_return(:wait_readable)
    reader, writer = IO.pipe
    output = StringIO.new
    received = Queue.new
    demod = Object.new
    demod.define_singleton_method(:feed_iq) { |iq, rate:, &emit| emit.call(samples: iq, rate: rate) }
    worker = Thread.new do
      described_class.run_iq(freq_obj: {}, source: reader, iq_format: :cu8, demod: demod,
                             output: output, on_frame: ->(frame) { received << frame }, log_file: false)
    end
    worker.report_on_exception = false
    writer.write([128, 129].pack('C*'))
    frame = Timeout.timeout(2) { received.pop }
    expect(frame[:samples].length).to eq(2)
    expect(writer).not_to be_closed
    writer.close
    expect(Timeout.timeout(2) { worker.value }).to include(reason: :eof, capture_complete: true)
    expect(JSON.parse(output.string)['samples']).to eq(frame[:samples])
    expect(reader).to be_closed
  ensure
    writer&.close unless writer&.closed?
    worker&.kill
    worker&.join
    reader&.close unless reader&.closed?
  end
end
