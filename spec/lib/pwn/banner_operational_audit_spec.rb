# frozen_string_literal: true

require 'spec_helper'

# Offline audit coverage: no terminal drawing, input, providers or devices.
describe PWN::Banner do
  it 'returns finite, valid strings from every static banner and its metadata' do
    modules = %i[Anon Bubble Cheshire CodeCave DontPanic ForkBomb FSociety JmpEsp Matrix Ninja OffTheAir Pirate Radare2 Radare2AI WhiteRabbit]
    expect do
      modules.each do |name|
        banner = described_class.const_get(name)
        text = banner.get
        expect(text).to be_a(String)
        expect(text.valid_encoding?).to be(true)
        expect(text.length).to be_between(1, 100_000)
        expect(banner.authors).to include('AUTHOR(S):')
      end
    end.to output('').to_stdout.and output('').to_stderr
    modules.each do |name|
      banner = described_class.const_get(name)
      expect { expect(banner.help).to eq(banner.constants.sort) }.to output(/#{Regexp.escape(banner.name)}\.get/).to_stdout
    end
  end

  it 'keeps zero, negative and tiny canvases bounded without constructing a replay' do
    expect(described_class).not_to receive(:mini_replay)
    (described_class.mini_names + [:pong]).product(%i[mini_frame mini_cells], [true, false]).each do |name, method, branding|
      [-100, 0].each do |size|
        expect(described_class.public_send(method, name: name, width: size, height: 8, branding: branding)).to eq([])
        expect(described_class.public_send(method, name: name, width: 8, height: size, branding: branding)).to eq([])
      end
      [1, 2, 4].product([1, 3, 4]).each do |width, height|
        rows = described_class.public_send(method, name: name, width: width, height: height, branding: branding)
        expect(rows.length).to eq(height)
        expect(rows.map(&:length)).to all(eq(width))
        text = method == :mini_cells ? rows.flatten.map { |cell| cell[:glyph] }.join : rows.join
        expect(text).to eq(' ' * width * height) unless branding
      end
    end
  end

  it 'rejects unknown animations consistently before rendering or stepping' do
    %i[mini_frame mini_cells mini_frame_seconds].each do |method|
      expect { described_class.public_send(method, name: :unknown) }.to raise_error(ArgumentError, /Unknown mini-banner/)
    end
    expect { described_class::MiniGame.new(name: :unknown, width: 8, height: 8) }.to raise_error(ArgumentError, /Unknown mini-banner/)
  end
end

describe PWN::Banner::MiniGame do
  it 'retains safe minimum and maximum dimensions for zero, negative and oversized playable panes' do
    (PWN::Banner.mini_names + [:pong]).product([-10, 0, 10**20]).each do |name, size|
      game = described_class.new(name: name, width: size, height: size)
      cells = game.cells(game.step)
      limit = %i[falling_blocks pacman galaga frogger].include?(name) ? 64 : 16
      expected = size.clamp(5, limit)
      expect(cells.length).to eq(expected)
      expect(cells.map(&:length)).to all(eq(expected))
    end
  end

  it 'bounds and drains pending controls without retaining an unbounded key history' do
    game = described_class.new(name: :snake, width: 5, height: 5)
    1000.times { |index| game.key(index.even? ? :up : :right) }
    expect(game.controls).to eq(Array.new(8) { %i[up right] }.flatten)
    expect(game.controls).to eq([])
    game.key(:left)
    expect(game.controls).to eq([:left])
  end

  it 'yields beyond a replay lifetime without starting threads or accumulating frames' do
    expect(Thread).not_to receive(:new)
    expect(PWN::Banner).not_to receive(:sleep)
    expect(PWN::Banner).not_to receive(:mini_replay)
    expect do
      (PWN::Banner.mini_names + [:pong]).product([false, true]).each do |name, demo|
        game = described_class.new(name: name, width: 5, height: 5, seed: 3, demo: demo)
        frame = nil
        1801.times { frame = game.step }
        expect(frame).to include(:event, :state, :rows)
        expect(game.length).to eq(0)
        cells = game.cells(frame)
        expect(cells.length).to eq(5)
        expect(cells.map(&:length)).to all(eq(5))
        cells.first.first[:glyph].replace('?')
        expect(game.cells(frame).first.first[:glyph]).not_to eq('?')
      end
    end.to output('').to_stdout.and output('').to_stderr
  end
end

describe PWN::Banner::Matrix do
  it 'returns one fixed-size matrix without running the interactive loop' do
    text = described_class.get.uncolorize
    expect(text.lines.length).to eq(33)
    expect(text.lines).to all(satisfy { |row| row.strip.split.length == 33 })
  end

  it 'propagates cancellation from a single intercepted animation tick' do
    allow(described_class).to receive(:print)
    allow(described_class).to receive(:puts)
    expect(described_class).to receive(:sleep).with(0.09).once.and_raise(Interrupt)
    expect { described_class.you? }.to raise_error(Interrupt)
  end
end
