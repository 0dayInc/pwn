# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh terminal layout' do
  it 'keeps a 5-row header and 5-row compose on a 24-line terminal' do
    layout = described_class.send(:mesh_layout, lines: 24, cols: 80)
    expect(layout[:header]).to eq(5)
    expect(layout[:tx]).to eq(5)
    expect(layout[:body]).to eq(14)
    expect(layout[:tx_top]).to eq(19)
  end

  it 'shrinks conversation so header, conversation and compose fit a 12-line terminal' do
    layout = described_class.send(:mesh_layout, lines: 12, cols: 40)
    expect(layout[:header] + layout[:body] + layout[:tx]).to eq(12)
    expect(layout[:tx_top] + layout[:tx]).to eq(12)
    expect(layout[:header]).to be >= 3
    expect(layout[:tx]).to be >= 3
    expect(layout[:body]).to be >= 3
  end

  it 'keeps compose on-screen on a 10-line terminal by shrinking conversation first' do
    layout = described_class.send(:mesh_layout, lines: 10, cols: 40)
    expect(layout[:header] + layout[:body] + layout[:tx]).to eq(10)
    expect(layout[:tx_top]).to be < 10
    expect(layout[:tx_top] + layout[:tx]).to eq(10)
  end

  it 'keeps a 32-column MSG DETAILS pane beside conversation when the terminal is wide enough' do
    layout = described_class.send(:mesh_layout, lines: 24, cols: 110)
    expect(layout[:details]).to eq(32)
    expect(layout[:conversation]).to eq(78)
    expect(layout[:header] + layout[:body] + layout[:tx]).to eq(24)
  end

  it 'omits MSG DETAILS when the terminal is too narrow for both panes' do
    layout = described_class.send(:mesh_layout, lines: 24, cols: 40)
    expect(layout[:details]).to eq(0)
    expect(layout[:conversation]).to eq(40)
  end

  it 'resizes from the terminal dup the same way pwn-ai does' do
    source = double('terminal dup', tty?: true, winsize: [30, 100])
    stub_const('PWN::MeshTerm', source)
    allow(Curses).to receive(:lines).and_return(24)
    allow(Curses).to receive(:cols).and_return(80)
    allow(Curses).to receive(:resizeterm)
    allow(described_class).to receive(:mesh_relayout!)
    _input, pipe = IO.pipe
    original = $stdout
    $stdout = pipe
    described_class.send(:mesh_apply_resize)
    expect(Curses).to have_received(:resizeterm).with(30, 100)
    expect(described_class).to have_received(:mesh_relayout!).with(lines: 30, cols: 100)
  ensure
    $stdout = original
    pipe&.close
  end

  it 'does not read winsize when getch is a test proc' do
    source = double('terminal dup', tty?: true)
    allow(source).to receive(:winsize)
    stub_const('PWN::MeshTerm', source)
    described_class.send(:mesh_apply_resize, getch: proc {})
    expect(source).not_to have_received(:winsize)
  end

  def pane_double
    win = double('pane')
    allow(win).to receive(:resize)
    allow(win).to receive(:move)
    allow(win).to receive(:erase)
    allow(win).to receive(:clear)
    allow(win).to receive(:close)
    allow(win).to receive(:maxx).and_return(40)
    allow(win).to receive(:maxy).and_return(10)
    %i[scrollok nodelay= keypad timeout= setpos addstr attron attroff refresh noutrefresh touch].each do |message|
      allow(win).to receive(message)
    end
    win
  end

  it 'keeps the same panes on resize and does not clear stdscr' do
    old = pane_double
    %i[MeshRxHeaderWin MeshRxFrameWin MeshRxBodyWin MeshSndrWin MeshRcvrWin MeshTxWin].each do |name|
      stub_const("PWN::#{name}", old)
    end
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxState', { rows: [{ header: '2026 · PEER · path · dest · RX via Serial', body: 'hello', color: 21 }], focus: :compose })
    screen = double('stdscr', erase: nil, noutrefresh: nil)
    allow(Curses).to receive(:stdscr).and_return(screen)
    allow(Curses).to receive(:doupdate)
    allow(Curses).to receive(:clear)
    allow(Curses).to receive(:refresh)
    allow(Curses).to receive(:color_pair).and_return(0)
    described_class.send(:mesh_relayout!, lines: 30, cols: 120)
    expect(old).to have_received(:resize).with(anything, 120).at_least(:once)
    expect(old).not_to have_received(:close)
    expect(PWN::MeshTxWin).to equal(old)
    expect(Curses).not_to have_received(:clear)
    expect(Curses).not_to have_received(:refresh)
    expect(PWN::MeshRxBodyWin).to have_received(:addstr).with(a_string_including('RX via Serial'))
    expect(PWN::MeshRxBodyWin).to have_received(:addstr).with(a_string_including('hello'))
    expect(old).to have_received(:touch).at_least(4).times
    expect(old).to have_received(:noutrefresh).at_least(4).times
    expect(Curses).to have_received(:doupdate)
  end

  it 'does not raise when a resize arrives before any message exists' do
    hide_const('PWN::MeshRxState')
    old = pane_double
    %i[MeshRxHeaderWin MeshRxFrameWin MeshRxBodyWin MeshTxWin].each do |name|
      stub_const("PWN::#{name}", old)
    end
    stub_const('PWN::MeshMutex', Mutex.new)
    allow(Curses).to receive(:color_pair).and_return(0)
    allow(Curses).to receive(:stdscr).and_return(double('stdscr', erase: nil, noutrefresh: nil))
    allow(Curses).to receive(:doupdate)
    expect { described_class.send(:mesh_relayout!, lines: 24, cols: 100) }.not_to raise_error
    expect(PWN::MeshTxWin).to equal(old)
    expect(old).not_to have_received(:close)
  ensure
    %i[MeshSndrWin MeshRcvrWin].each do |name|
      PWN.send(:remove_const, name) if PWN.const_defined?(name)
    end
  end

  it 'drops side-pane focus when a resize hides SENDER and RECEIVER' do
    old = pane_double
    %i[MeshRxHeaderWin MeshRxFrameWin MeshRxBodyWin MeshSndrWin MeshRcvrWin MeshTxWin].each do |name|
      stub_const("PWN::#{name}", old)
    end
    stub_const('PWN::MeshMutex', Mutex.new)
    stub_const('PWN::MeshRxState', { focus: :sndr, rows: [] })
    allow(Curses).to receive(:color_pair).and_return(0)
    allow(Curses).to receive(:stdscr).and_return(double('stdscr', erase: nil, noutrefresh: nil))
    allow(Curses).to receive(:doupdate)
    described_class.send(:mesh_relayout!, lines: 24, cols: 40)
    expect(PWN.const_defined?(:MeshSndrWin)).to be(false)
    expect(described_class.send(:mesh_focus)).to eq(:conversation)
    expect(PWN::MeshTxWin).to equal(old)
  ensure
    PWN.const_set(:MeshSndrWin, old) unless PWN.const_defined?(:MeshSndrWin)
    PWN.const_set(:MeshRcvrWin, old) unless PWN.const_defined?(:MeshRcvrWin)
  end
end
