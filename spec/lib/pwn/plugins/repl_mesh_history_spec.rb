# frozen_string_literal: true

require 'spec_helper'
require 'meshtastic'

describe PWN::Plugins::REPL, 'mesh compose history' do
  it 'does not warn when the real subscriber sees an empty protobuf Data message' do
    stub_const('PWN::MeshTransport', :serial)
    queue = Queue.new
    encoded = Meshtastic::FromRadio.new(packet: { decoded: Meshtastic::Data.new }).to_proto
    queue << Meshtastic::FromRadio.decode(encoded)
    queue << Meshtastic::FromRadio.new(queueStatus: { free: 1 })
    queue.close
    received = []
    output = StringIO.new
    old = $stdout
    $stdout = output
    described_class.send(:mesh_subscribe, obj: { from_radio_queue: queue }, psks: {}, on_message: proc { |message| received << message })
    expect(received.size).to eq(2)
    expect(output.string).not_to include("Can't decode")
    Meshtastic::MeshInterface.new.decode_payload(payload: 'unsupported', msg_type: :PRIVATE_APP)
    expect(output.string).to include("Can't decode", 'unsupported')
  ensure
    $stdout = old
  end

  it 'does not warn when a packet has an unknown portnum and no payload' do
    stub_const('PWN::MeshTransport', :serial)
    queue = Queue.new
    encoded = Meshtastic::FromRadio.new(packet: { decoded: Meshtastic::Data.new(portnum: 51) }).to_proto
    queue << Meshtastic::FromRadio.decode(encoded)
    queue.close
    output = StringIO.new
    old = $stdout
    $stdout = output
    described_class.send(:mesh_subscribe, obj: { from_radio_queue: queue }, psks: {}, on_message: proc { |_message| })
    expect(output.string).not_to include("Can't decode")
    expect(output.string).not_to include('portnum: 51')
  ensure
    $stdout = old
  end

  it 'queues warnings for acknowledgement instead of writing through the TUI' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    expect(described_class).not_to receive(:puts)
    described_class.send(:mesh_ui_puts, text: 'WARNING: fixture warning')
    expect(events.pop(true)).to eq(notice: 'WARNING: fixture warning')
  end

  it 'displays queued diagnostics on the UI thread' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    events << { notice: 'RX failed: fixture' }
    expect(described_class).to receive(:mesh_notice).with(text: 'RX failed: fixture')
    described_class.send(:mesh_drain_events)
  end

  it 'does not turn spinner cursor restores into a notice overlay' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    described_class.send(:mesh_capture_output, run: proc {
      3.times { $stdout.write("\e[?25h") }
      $stderr.write("\e[?25h")
    })
    expect(events).to be_empty
  end

  it 'does not notice TTYSpinner cursor restore during capture' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    described_class.send(:mesh_capture_output, run: proc {
      PWN::Plugins::TTYSpinner.send(:show_cursor, spin: nil)
    })
    expect(events).to be_empty
  end

  it 'keeps real warnings after stripping cursor sequences' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    described_class.send(:mesh_capture_output, run: proc {
      $stderr.write("\e[?25hWARNING: decoder fixture\e[?25h\n")
    })
    expect(events.pop(true)[:notice]).to eq('WARNING: decoder fixture')
    expect(events).to be_empty
  end

  it 'does not open a notice for the serial subscribe banner' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    described_class.send(:mesh_capture_output, run: proc {
      puts 'Subscribing to serial FromRadio stream...'
    })
    expect(events).to be_empty
  end

  it 'keeps a warning that shares a chunk with the serial subscribe banner' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    described_class.send(:mesh_capture_output, run: proc {
      $stdout.write("Subscribing to serial FromRadio stream...\nWARNING: decoder fixture\n")
    })
    expect(events.pop(true)[:notice]).to eq('WARNING: decoder fixture')
    expect(events).to be_empty
  end

  it 'captures dependency stdout and stderr and restores both streams on failure' do
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    original = [$stdout, $stderr]
    expect do
      described_class.send(:mesh_capture_output, run: proc {
        puts 'WARNING: decoder fixture'
        warn 'ERROR: transport fixture'
        raise IOError, 'fixture'
      })
    end.to raise_error(IOError, 'fixture')
    expect([$stdout, $stderr]).to eq(original)
    output = []
    output << events.pop(true)[:notice] until events.empty?
    expect(output.join).to include('WARNING: decoder fixture', 'ERROR: transport fixture')
  end

  it 'centers a reverse-colored Ok button and repaints the underlying panes' do
    win = double('notice', maxx: 78, maxy: 6)
    %i[keypad erase setpos addstr refresh close attron attroff].each { |method| allow(win).to receive(method) }
    allow(Curses).to receive(:color_pair).with(20).and_return(5120)
    allow(Curses).to receive(:cols).and_return(80)
    allow(Curses).to receive(:lines).and_return(24)
    allow(Curses::Window).to receive(:new).and_return(win)
    pane = double('pane', touch: nil, refresh: nil)
    stub_const('PWN::MeshTxWin', pane)
    keys = ["\e", 'q', "\n"]
    described_class.send(:mesh_notice, text: 'Decoder warning', getch: proc { keys.shift })
    expect(keys).to be_empty
    expect(win).to have_received(:addstr).with('Ok').exactly(3).times
    expect(win).not_to have_received(:addstr).with(a_string_matching(/Acknowledged|Enter/))
    expect(win).to have_received(:setpos).with(4, 38).exactly(3).times
    expect(win).to have_received(:attron).with(5120 | Curses::A_BOLD | Curses::A_REVERSE).exactly(3).times
    expect(win).to have_received(:attroff).with(5120 | Curses::A_BOLD | Curses::A_REVERSE).exactly(3).times
    expect(win).to have_received(:close)
    expect(pane).to have_received(:touch)
  end

  it 'keeps an idle PhoneAPI session alive and stops its heartbeat with the subscriber' do
    events = Queue.new
    beats = Queue.new
    release = Queue.new
    obj = {}
    stub_const('PWN::MeshEvents', events)
    stub_const('PWN::MeshObj', obj)
    stub_const('PWN::MeshTransport', :serial)
    allow(Meshtastic::Serial).to receive(:send_to_radio) do |args|
      beats << [Thread.current, Meshtastic::ToRadio.decode(args[:to_radio])]
    end
    allow(described_class).to receive(:mesh_subscribe) do |args|
      release.pop
      args[:on_message].call(packet: { decoded: { portnum: 1, payload: 'after idle' } })
    end
    thread = described_class.send(:mesh_start_rx!, env: { channel: {} }, obj: obj, heartbeat_interval: 0.01)
    first = beats.pop(timeout: 1)
    second = beats.pop(timeout: 1)
    expect(first).not_to be_nil
    expect(second).not_to be_nil
    expect(second.last.payload_variant).to eq(:heartbeat)
    expect(second.last.heartbeat.nonce).to eq(0)
    release << true
    expect(thread.join(1)).to eq(thread)
    expect(first.first).not_to be_alive
    expect(events.pop[:msg].dig(:packet, :decoded, :payload)).to eq('after idle')
  ensure
    thread&.kill
    thread&.join(1)
  end

  it 'drains incoming messages during idle input polls without a keypress' do
    pi = double('pry', config: double('config', pwn_mesh: true))
    events = Queue.new
    stub_const('PWN::MeshEvents', events)
    message = { packet: { decoded: { portnum: 1, payload: 'idle RX' } } }
    polls = 0
    allow(described_class).to receive(:mesh_draw_input)
    expect(described_class).to receive(:mesh_handle_rx).with(msg: message)
    reader = proc do
      polls += 1
      events << { msg: message } if polls == 20
      polls > 20 ? "\u0004" : nil
    end
    described_class.send(:mesh_console_loop, pry: pi, getch: reader)
  end

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
