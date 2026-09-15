# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh compose history' do
  it 'recalls submissions with Up/Down and restores the unfinished draft and cursor' do
    config = double('config', pwn_mesh: true)
    pry = double('pry', config: config)
    keys = ['first', "\n", '/status', "\n", 'draft', Curses::KEY_LEFT,
            Curses::KEY_UP, Curses::KEY_UP, Curses::KEY_UP,
            Curses::KEY_DOWN, Curses::KEY_DOWN, Curses::KEY_DOWN]
    frames = []
    allow(described_class).to receive(:mesh_drain_events)
    allow(described_class).to receive(:mesh_submit)
    allow(described_class).to receive(:mesh_draw_input) { |opts| frames << [opts[:text].dup, opts[:cursor]] }
    reader = proc do
      allow(config).to receive(:pwn_mesh).and_return(false) if keys.empty?
      keys.shift
    end
    described_class.send(:mesh_console_loop, pry: pry, getch: reader)
    expected = [
      ['/status', 7], ['first', 5], ['first', 5],
      ['/status', 7], ['draft', 4], ['draft', 4]
    ]
    expect(frames.last(6)).to eq(expected)
    expect(described_class).to have_received(:mesh_submit).with(request: 'first', pry: pry)
    expect(described_class).to have_received(:mesh_submit).with(request: '/status', pry: pry)
  end

  it 'edits recalled text without mutating history and skips empty submissions' do
    config = double('config', pwn_mesh: true)
    pry = double('pry', config: config)
    keys = [Curses::KEY_UP, Curses::KEY_DOWN, 'hello', "\n", "\n",
            Curses::KEY_UP, '!', Curses::KEY_DOWN, Curses::KEY_UP]
    frames = []
    allow(described_class).to receive(:mesh_drain_events)
    allow(described_class).to receive(:mesh_submit)
    allow(described_class).to receive(:mesh_draw_input) { |opts| frames << opts[:text].dup }
    reader = proc do
      allow(config).to receive(:pwn_mesh).and_return(false) if keys.empty?
      keys.shift
    end
    described_class.send(:mesh_console_loop, pry: pry, getch: reader)
    expect(frames).to include('hello!')
    expect(frames.last).to eq('hello')
  end
end
