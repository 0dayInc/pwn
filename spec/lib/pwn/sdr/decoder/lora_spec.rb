# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

describe PWN::SDR::Decoder::LoRa do
  it 'exposes an explicitly separate detector entry point' do
    expect(described_class).to respond_to(:detect)
  end

  it 'raises on source loss rather than silently replacing payload decoding with detection' do
    base = PWN::SDR::Decoder::Base
    allow(base).to receive(:resolve_iq_source).and_return(nil)
    allow(base).to receive(:run_detector).and_return(reason: :eof, frames: 0)
    expect { described_class.decode(freq_obj: {}, source: :file, file: 'offline.cu8', fallback: :detector) }
      .to raise_error(RuntimeError, %r{no I/Q source available})
    expect(base).not_to have_received(:run_detector)
  end

  it 'decodes an independently encoded CRC-protected packet from chunked IQ' do
    root = File.expand_path('../../../../fixtures/sdr/lora', __dir__)
    vector = JSON.parse(File.read("#{root}/vectors.json"), symbolize_names: true).first
    iq = File.binread("#{root}/#{vector[:file]}").unpack('e*')
    frames = []
    demod = described_class::PayloadIQ.new(rate: 125_000, bw: 125_000, sf: 7)
    iq.each_slice(194) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
    expect(frames).to contain_exactly(include(payload_hex: vector[:payload_hex], decoded: true, crc_valid: true))
  end

  def lora_vectors
    root = File.expand_path('../../../../fixtures/sdr/lora', __dir__)
    JSON.parse(File.read("#{root}/vectors.json"), symbolize_names: true).map do |vector|
      [vector, File.binread("#{root}/#{vector[:file]}").unpack('e*')]
    end
  end

  def lora_receive(signal, spreading: 7, chunk: 194)
    frames = []
    demod = described_class::PayloadIQ.new(rate: 125_000, bw: 125_000, sf: spreading)
    signal.each_slice(chunk) { |part| demod.feed_iq(part) { |frame| frames << frame } }
    frames
  end

  def lora_synthetic(symbols, spreading: 7)
    n = 1 << spreading
    chirp = lambda do |bin, down = false, length = n|
      Array.new(length) do |k|
        phase = Math::PI * k * ((k.to_f / n) - 1)
        phase = -phase if down
        phase += 2 * Math::PI * bin * k / n
        [Math.cos(phase), Math.sin(phase)]
      end.flatten
    end
    (([0] * 8) + [8, 16]).flat_map { |b| chirp.call(b) } +
      (chirp.call(0, true) * 2) + chirp.call(0, true, n / 4) +
      symbols.flat_map { |b| chirp.call(b) }
  end

  it 'runs the public payload path from an explicit offline source' do
    vector, iq = lora_vectors.first
    frames = []
    described_class.decode(source: StringIO.new(iq.map { |v| (v * 16_000).round }.pack('s<*')), iq_format: :cs16, sample_rate: 125_000,
                           sf: 7, bw: 125_000, freq_obj: { freq: 915_000_000 },
                           interactive: false, log_file: false, output: StringIO.new,
                           on_frame: ->(frame) { frames << frame })
    expect(frames).to contain_exactly(include(payload_hex: vector[:payload_hex], crc_valid: true))
  end

  it 'emits a validated packet while its pipe source remains open' do
    vector, iq = lora_vectors.first
    reader, writer = IO.pipe
    frames = Queue.new
    worker = Thread.new do
      described_class.decode(source: reader, iq_format: :cs16, sample_rate: 125_000,
                             freq_obj: { freq: 915_000_000 }, interactive: false,
                             log_file: false, output: StringIO.new, on_frame: ->(frame) { frames << frame })
    end
    writer.write(iq.map { |v| (v * 16_000).round }.pack('s<*'))
    frame = Timeout.timeout(3) { frames.pop }
    expect(frame).to include(payload_hex: vector[:payload_hex], decoded: true)
    expect(writer).not_to be_closed
  ensure
    writer&.close unless writer&.closed?
    worker&.join(3)
    worker&.kill if worker&.alive?
    reader&.close unless reader&.closed?
  end

  it 'uses identical normalized chirps at each supported bandwidth' do
    vector, iq = lora_vectors.first
    [125_000, 250_000, 500_000].each do |bandwidth|
      demod = described_class::PayloadIQ.new(rate: bandwidth, bw: bandwidth, sf: 7)
      frames = []
      demod.feed_iq(iq) { |frame| frames << frame }
      expect(frames).to contain_exactly(include(payload_hex: vector[:payload_hex], bw_hz: bandwidth))
    end
  end

  it 'verifies independent fixture hashes' do
    require 'digest'
    root = File.expand_path('../../../../fixtures/sdr/lora', __dir__)
    %w[vectors.json modes.json].flat_map { |name| JSON.parse(File.read("#{root}/#{name}"), symbolize_names: true) }.each do |vector|
      expect(Digest::SHA256.file("#{root}/#{vector[:file]}").hexdigest).to eq(vector[:sha256])
    end
  end

  it 'matches every independent waveform and its symbol-derived synthetic waveform' do
    lora_vectors.each do |vector, iq|
      [iq, lora_synthetic(vector[:symbols], spreading: vector[:sf])].each do |signal|
        [1, 194, signal.length].each do |chunk|
          expect(lora_receive(signal, spreading: vector[:sf], chunk: chunk)).to contain_exactly(
            include(payload_hex: vector[:payload_hex], crc_valid: true)
          )
        end
      end
    end
  end

  it 'acquires off-grid packets with integer CFO and does not deduplicate identical packets' do
    vector, iq = lora_vectors.first
    [1, 31, 63, 95, 127].each do |offset|
      shifted = Array.new(offset * 2, 0.0) + iq
      shifted = shifted.each_slice(2).with_index.flat_map do |(i, q), k|
        cfo = Complex.polar(1, 2 * Math::PI * 3 * k / 128)
        value = Complex(i, q) * cfo
        [value.real, value.imag]
      end
      expect(lora_receive(shifted + shifted)).to contain_exactly(
        include(payload_hex: vector[:payload_hex]), include(payload_hex: vector[:payload_hex])
      )
    end
  end

  def lora_flip_codeword(symbols, delta, block: 8, width: 7, reduced: false)
    symbols = symbols.dup
    8.times do |column|
      next if delta[column].zero?

      value = reduced ? symbols[block + column] / 4 : (symbols[block + column] - 1) % 128
      gray = value ^ (value >> 1) ^ (1 << ((-column) % width))
      binary = gray
      mask = gray >> 1
      until mask.zero?
        binary ^= mask
        mask >>= 1
      end
      symbols[block + column] = ((binary * (reduced ? 4 : 1)) + 1) % 128
    end
    symbols
  end

  it 'corrects a single Hamming bit but rejects double-bit errors' do
    vector = lora_vectors.first.first
    fixed = lora_flip_codeword(vector[:symbols], 1)
    expect(lora_receive(lora_synthetic(fixed))).to contain_exactly(include(payload_hex: vector[:payload_hex]))
    broken = lora_flip_codeword(vector[:symbols], 3)
    expect(lora_receive(lora_synthetic(broken))).to be_empty
  end

  it 'rejects valid FEC with wrong payload CRC and wrong header checksum' do
    vector = lora_vectors.first.first
    # 0xD1 is the LoRa extended-Hamming codeword of nibble 1.
    # XOR preserves FEC validity but changes the protected data.
    crc_bad = lora_flip_codeword(vector[:symbols], 0xD1)
    expect(lora_receive(lora_synthetic(crc_bad))).to be_empty
    header_bad = lora_flip_codeword(vector[:symbols], 0xD1, block: 0, width: 5, reduced: true)
    expect(lora_receive(lora_synthetic(header_bad))).to be_empty
  end

  it 'rejects truncation, silence, noise and a missing SFD' do
    vector, iq = lora_vectors.first
    expect(lora_receive(iq.first(4000))).to be_empty
    expect(lora_receive(Array.new(10_000, 0.0))).to be_empty
    random = Random.new(123)
    expect(lora_receive(Array.new(10_000) { random.rand - 0.5 })).to be_empty
    missing = lora_synthetic(vector[:symbols])
    missing[128 * 10 * 2, 128 * 2 * 2] = Array.new(128 * 2 * 2, 0.0)
    expect(lora_receive(missing)).to be_empty
  end

  def lora_modes
    require 'zlib'
    root = File.expand_path('../../../../fixtures/sdr/lora', __dir__)
    JSON.parse(File.read("#{root}/modes.json"), symbolize_names: true).map do |vector|
      [vector, Zlib::GzipReader.open("#{root}/#{vector[:file]}", &:read).unpack('e*')]
    end
  end

  it 'decodes independent SF9-12, LDRO, implicit, CRC-off and inverted waveforms' do
    lora_modes.select { |v, _| v[:sample_rate] == v[:bw] }.each do |v, iq|
      [1, 8192, iq.length].each do |size|
        frames = []
        options = v.slice(:sf, :bw, :implicit_header, :payload_length, :cr, :crc, :ldro, :invert_iq)
        demod = described_class::PayloadIQ.new(**options, rate: v[:sample_rate])
        iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
        expect(frames).to contain_exactly(include(payload_hex: v[:payload_hex], crc_valid: v[:crc] ? true : nil,
                                                  header_valid: v[:implicit_header] ? nil : true))
      end
    end
  end

  it 'forwards every new mode through the public offline decode path' do
    lora_modes.each do |v, iq|
      frames = []
      options = v.slice(:sf, :sample_rate, :bw, :implicit_header, :payload_length, :cr, :crc, :ldro, :invert_iq)
      described_class.decode(**options, source: StringIO.new(iq.map { |x| (x * 12_000).round }.pack('s<*')),
                                        iq_format: :cs16, interactive: false, log_file: false, output: StringIO.new,
                                        on_frame: ->(frame) { frames << frame })
      expect(frames).to contain_exactly(include(payload_hex: v[:payload_hex], crc_present: v[:crc],
                                                implicit_header: v[:implicit_header], ldro: v[:ldro], invert_iq: v[:invert_iq]))
    end
  end

  it 'resamples independent noninteger-rate IQ with identical scalar and bulk chunk results' do
    v, iq = lora_modes.last
    [1, 194, iq.length].each do |size|
      frames = []
      demod = described_class::PayloadIQ.new(rate: v[:sample_rate], bw: v[:bw], sf: v[:sf])
      iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |frame| frames << frame } }
      expect(frames).to contain_exactly(include(payload_hex: v[:payload_hex], crc_valid: true))
    end
  end

  it 'does not complete truncated packets in any new mode' do
    lora_modes.each do |v, iq|
      options = v.slice(:sf, :bw, :implicit_header, :payload_length, :cr, :crc, :ldro, :invert_iq)
      demod = described_class::PayloadIQ.new(**options, rate: v[:sample_rate])
      frames = []
      demod.feed_iq(iq.first(iq.length * 3 / 4)) { |frame| frames << frame }
      expect(frames).to be_empty
    end
  end

  it 'automatically enables LDRO for long symbols but honors an explicit false override' do
    lora_modes.select { |v, _| !v[:implicit_header] && v[:sf] >= 11 }.each do |v, iq|
      options = v.slice(:sf, :bw)
      options[:ldro] = false unless v[:ldro]
      demod = described_class::PayloadIQ.new(**options, rate: v[:sample_rate])
      frames = []
      demod.feed_iq(iq) { |frame| frames << frame }
      expect(frames).to contain_exactly(include(payload_hex: v[:payload_hex], ldro: v[:ldro]))
    end
  end

  it 'uses the existing native dot-product kernel with Ruby resampling parity' do
    dsp = PWN::SDR::Decoder::DSP
    volk = PWN::FFI::Volk
    expect(volk).to receive(:volk_32f_x2_dot_prod_32f).at_least(:once).and_call_original if volk.available?
    v, iq = lora_modes.last
    signals = [false, true].map do |native|
      allow(dsp).to receive(:native).and_return(native)
      demod = described_class::PayloadIQ.new(rate: v[:sample_rate], bw: v[:bw], sf: v[:sf])
      iq.first(12_000).each_slice(194).flat_map { |chunk| demod.send(:resample_input, chunk) }
    end
    expect(signals.first.length).to eq(signals.last.length)
    expect(signals.first.zip(signals.last).map { |a, b| (a - b).abs }.max).to be < 1e-6
  end

  it 'rejects unsupported options before any source selection' do
    allow(PWN::SDR::Decoder::Base).to receive(:run_iq) { raise 'source must not open' }
    [{ sf: 6 }, { sf: 13 }, { sample_rate: 100_000 }, { sample_rate: Float::INFINITY },
     { mode: :fsk }, { implicit_header: true }, { implicit_header: true, payload_length: 256 },
     { implicit_header: true, payload_length: 13, cr: 5 }, { sync_word: 256 }].each do |options|
      expect { described_class.decode(options) }.to raise_error(ArgumentError)
    end
  end

  it 'does not report a preamble from zero-energy input' do
    demod = described_class::DemodIQ.new(rate: 125_000)
    frames = []
    demod.feed_iq(Array.new(128 * 13 * 2, 0.0)) { |f| frames << f }
    expect(frames).to be_empty
  end

  it 'resamples fixed source windows rather than resetting at transport boundaries' do
    dsp = PWN::SDR::Decoder::DSP
    iq = Array.new(800) { |i| Math.sin(i * 0.1) }
    inputs = [iq.length, 14].map do |size|
      windows = []
      allow(dsp).to receive(:resample_iq) do |opts|
        windows << opts[:iq].dup
        []
      end
      demod = described_class::DemodIQ.new(rate: 8000)
      iq.each_slice(size) { |chunk| demod.feed_iq(chunk) { |_f| nil } }
      windows
    end
    expect(inputs.first).not_to be_empty
    expect(inputs.last).to eq(inputs.first)
  end

  it 'labels chirp synchronization as preamble-only rather than payload decoding' do
    n = 128
    iq = (([0] * 8) + [24, 32, 64, 64, 64, 64]).flat_map do |bin|
      Array.new(n) do |k|
        phase = (Math::PI * k * ((k.to_f / n) - 1)) + (2 * Math::PI * bin * k / n)
        [Math.cos(phase), Math.sin(phase)]
      end.flatten
    end
    frames = []
    described_class::DemodIQ.new(rate: 125_000).feed_iq(iq) { |f| frames << f }
    expect(frames).not_to be_empty
    expect(frames).to all(include(capability: 'preamble-only', decoded: false))
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::Decoder::LoRa
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::Decoder::LoRa
    expect(help_response).to respond_to :help
  end
end
