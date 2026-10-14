# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL, 'mesh conversation scroll' do
  let(:config) { double('config', pwn_mesh: true) }
  let(:pry) { double('pry', config: config) }

  before do
    stub_const('PWN::MeshRxState', { lines: (1..10).map { |n| { text: "row #{n}", color: 21, bold: false } } })
    stub_const('PWN::MeshRxBodyWin', double('body', maxy: 3, maxx: 40, clear: nil, setpos: nil, addstr: nil, attron: nil, attroff: nil, refresh: nil, scrollok: nil))
    stub_const('PWN::MeshMutex', Mutex.new)
    allow(Curses).to receive(:color_pair).and_return(0)
    allow(described_class).to receive(:mesh_drain_events)
    allow(described_class).to receive(:mesh_draw_input)
    allow(described_class).to receive(:mesh_submit)
    allow(described_class).to receive(:mesh_paint_focus_titles)
  end

  def drive(keys)
    reader = proc do
      allow(config).to receive(:pwn_mesh).and_return(false) if keys.empty?
      keys.shift
    end
    described_class.send(:mesh_console_loop, pry: pry, getch: reader)
  end

  it 'switches to conversation with Ctrl+T and scrolls without recalling compose history' do
    drive(['sent', "\n", "\u0014", Curses::KEY_UP, Curses::KEY_UP, "\n", Curses::KEY_UP])
    expect(PWN::MeshRxState[:focus]).to eq(:compose)
    expect(PWN::MeshRxState[:scroll]).to eq(5)
    expect(described_class).to have_received(:mesh_submit).once
  end

  it 'pages and returns to a nil live bottom' do
    described_class.send(:mesh_scroll_conversation, key: :page_up)
    expect(PWN::MeshRxState[:scroll]).to eq(4)
    described_class.send(:mesh_scroll_conversation, key: :page_down)
    expect(PWN::MeshRxState[:scroll]).to be_nil
    described_class.send(:mesh_scroll_conversation, key: :page_down)
    expect(PWN::MeshRxState[:scroll]).to be_nil
    described_class.send(:mesh_scroll_conversation, key: :home)
    expect(PWN::MeshRxState[:scroll]).to eq(0)
    described_class.send(:mesh_scroll_conversation, key: :end)
    expect(PWN::MeshRxState[:scroll]).to be_nil
    described_class.send(:mesh_scroll_conversation, key: :down)
    expect(PWN::MeshRxState[:scroll]).to be_nil
  end
end
