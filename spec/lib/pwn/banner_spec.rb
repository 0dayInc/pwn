# frozen_string_literal: true

require 'spec_helper'

describe PWN::Banner do
  describe '.mini_frame' do
    it 'offers retro games with deterministic cycles and branding at every square size' do
      expect(described_class.mini_names).to eq(%i[falling_blocks snake pong])
      described_class.mini_names.each do |name|
        (5..16).each do |size|
          args = { name: name, width: size, height: size }
          frames = Array.new(described_class::MINI_FRAME_COUNT) { |frame| described_class.mini_frame(**args, frame: frame) }
          expect(frames.uniq.length).to be >= 4
          expect(frames.flatten).to all(match(/\A[ -~]{#{size}}\z/))
          expect(frames.map(&:length)).to all(eq(size))
          expect(frames.map(&:first)).to all(include('PWN'))
          expect(described_class.mini_frame(**args, frame: described_class::MINI_FRAME_COUNT)).to eq(frames.first)
          expect(described_class.mini_frame(**args, name: name.to_s, frame: -1)).to eq(frames.last)
          expect(described_class.mini_frame(**args, frame: 3)).to eq(frames[3])
        end
      end
    end

    it 'returns a compact printable ASCII wordmark without terminal side effects' do
      lines = nil
      expect { lines = described_class.mini_frame(frame: 0) }.not_to output.to_stdout
      expect(lines.length).to eq(16)
      expect(lines).to all(match(/\A[ -~]{16}\z/))
      expect(lines.first).to include('PWN')
    end

    it 'clips safely for tiny panes and caps oversized requests at native dimensions' do
      described_class.mini_names.each do |name|
        [1, 3, 5, 8, 16].product([1, 3, 5, 8, 16]).each do |width, height|
          rows = described_class.mini_frame(name: name, width: width, height: height)
          expect(rows.length).to eq(height)
          expect(rows.map(&:length)).to all(eq(width))
        end
      end
      expect(described_class.mini_frame(width: 0)).to eq([])
      expect(described_class.mini_frame(height: -1)).to eq([])
      expect(described_class.mini_frame(width: -1)).to eq([])
      expect(described_class.mini_frame(width: 10**20, height: 10**20)).to eq(described_class.mini_frame)
      expect(described_class.mini_frame(name: nil, frame: nil, width: nil, height: nil)).to eq(described_class.mini_frame)
      expect(described_class.mini_frame(width: '3', height: '2').map(&:length)).to eq([3, 3])
    end

    it 'returns independent rows and name lists without retaining caller mutations' do
      original = described_class.mini_frame
      changed = described_class.mini_frame
      changed.first.replace('changed')
      changed.clear
      described_class.mini_names.clear
      expect(described_class.mini_frame).to eq(original)
      expect(described_class.mini_names.length).to eq(3)
    end

    it 'keeps recognizable pieces, bodies and paddles in the smallest complete canvas' do
      expect(described_class.mini_frame(name: :falling_blocks, width: 5, height: 5)).to eq(
        [' PWN ', ' ### ', '  #  ', '#   #', '## ##']
      )
      expect(described_class.mini_frame(name: :snake, width: 5, height: 5)).to eq(
        [' PWN ', '@    ', 'o *  ', 'o    ', 'oo   ']
      )
      expect(described_class.mini_frame(name: :pong, width: 5, height: 5)).to eq(
        [' PWN ', '|o: |', '|   |', '  :  ', '     ']
      )
    end

    it 'lands tetrominoes before flashing and clearing the completed rows' do
      [5, 8, 16].each do |size|
        [0, 30].each do |start|
          args = { name: :falling_blocks, width: size, height: size }
          expect(described_class.mini_frame(**args, frame: start + 24).last(2)).to eq(['#' * size] * 2)
          expect(described_class.mini_frame(**args, frame: start + 26).last(2)).to eq(['=' * size] * 2)
          expect(described_class.mini_frame(**args, frame: start + 29).last(2)).to eq([' ' * size] * 2)
        end
      end
    end

    it 'moves snake and ball at most one cell per axis including the loop seam' do
      { snake: '@', pong: 'o' }.each do |name, glyph|
        (5..16).each do |size|
          positions = Array.new(described_class::MINI_FRAME_COUNT + 1) do |frame|
            rows = described_class.mini_frame(name: name, frame: frame, width: size, height: size)
            y = rows.index { |row| row.include?(glyph) }
            [rows[y].index(glyph), y]
          end
          positions.each_cons(2) do |before, after|
            expect((before[0] - after[0]).abs).to be <= 1
            expect((before[1] - after[1]).abs).to be <= 1
          end
        end
      end
    end

    it 'never aliases mutable rows even during the line-clear animation' do
      described_class.mini_names.each do |name|
        described_class::MINI_FRAME_COUNT.times do |frame|
          rows = described_class.mini_frame(name: name, frame: frame)
          expect(rows.map(&:object_id).uniq.length).to eq(rows.length)
        end
      end
    end

    it 'never samples randomness, reads the clock, starts threads, sleeps, or prints' do
      expect(Random).not_to receive(:rand)
      expect(Time).not_to receive(:now)
      expect(Process).not_to receive(:clock_gettime)
      expect(Thread).not_to receive(:new)
      expect(described_class).not_to receive(:sleep)
      expect do
        described_class.mini_names.each { |name| described_class.mini_frame(name: name, frame: 5) }
      end.to output('').to_stdout.and output('').to_stderr
    end

    it 'rejects unknown artwork rather than silently randomizing it' do
      expect { described_class.mini_frame(name: :missing) }.to raise_error(ArgumentError, /Unknown mini-banner/)
    end

    it 'preserves the original static banner dispatch' do
      modules = %i[Anon Bubble Cheshire CodeCave DontPanic ForkBomb FSociety JmpEsp Matrix Ninja OffTheAir Pirate Radare2 Radare2AI WhiteRabbit]
      modules.each_with_index do |name, index|
        expect(described_class.const_get(name)).to receive(:get).and_return(name.to_s)
        expect(described_class.get(index: index + 1)).to eq(name.to_s)
      end
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::Banner
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Banner
    expect(help_response).to respond_to :help
  end
end
