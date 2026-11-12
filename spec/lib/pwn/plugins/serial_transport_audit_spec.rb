# frozen_string_literal: true

require 'spec_helper'
require 'timeout'
require 'pty'

RSpec.describe PWN::Plugins::Serial do
  it 'does not mix bytes from two open connections or flush the other connection' do
    readers = []
    writers = []
    sessions = []
    allow(File).to receive(:exist?).and_call_original
    %w[/fixture/first /fixture/second].each do |path|
      reader, writer = IO.pipe
      readers << reader
      writers << writer
      allow(File).to receive(:exist?).with(path).and_return(true)
      allow(UART).to receive(:open).with(path, 9600, '8N1').and_return(reader)
      sessions << described_class.connect(block_dev: path)
    end
    writers[0].write("\x01".b)
    writers[1].write("\x02".b)
    Timeout.timeout(2) do
      loop do
        combined = sessions.flat_map { |session| described_class.response(serial_obj: session) }.join
        break if combined.include?('01') && combined.include?('02')

        Thread.pass
      end
    end
    expect(described_class.response(serial_obj: sessions[0])).to eq(['01'])
    expect(described_class.response(serial_obj: sessions[1])).to eq(['02'])
    expect { described_class.dump_session_data }.to raise_error(ArgumentError, /serial_obj/)
    expect { described_class.flush_session_data }.to raise_error(ArgumentError, /serial_obj/)
    described_class.disconnect(serial_obj: sessions[0])
    expect(described_class.response(serial_obj: sessions[1])).to eq(['02'])
  ensure
    sessions&.each { |session| described_class.disconnect(serial_obj: session) }
    (readers.to_a + writers.to_a).each { |io| io.close unless io.closed? }
  end

  it 'closes a partially acquired connection without requiring a reader thread' do
    connection = StringIO.new
    expect { described_class.disconnect(serial_obj: { serial_conn: connection }) }.not_to raise_error
    expect(connection).to be_closed
  end

  it 'reports reader EOF to the caller after draining pending bytes rather than losing a worker exception' do
    reader, writer = IO.pipe
    allow(File).to receive(:exist?).with('/fixture/eof').and_return(true)
    allow(UART).to receive(:open).and_return(reader)
    session = described_class.connect(block_dev: '/fixture/eof')
    session[:session_thread].report_on_exception = false
    writer.write('x')
    writer.close
    expect { session[:session_thread].value }.not_to raise_error
    expect(described_class.response(serial_obj: session)).to eq(['78'])
    described_class.flush_session_data(serial_obj: session)
    expect { described_class.response(serial_obj: session) }.to raise_error(EOFError)
  ensure
    described_class.disconnect(serial_obj: session) if session
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end

  it 'queries UART modem settings through termios rather than the removed SerialPort API' do
    connection = StringIO.new
    attributes = double('termios attributes', ospeed: Termios::B9600, cflag: Termios::CS8)
    allow(Termios).to receive(:tcgetattr).with(connection).and_return(attributes)
    expect(described_class.get_modem_params(serial_obj: { serial_conn: connection })).to eq('baud' => 9600, 'data_bits' => 8, 'stop_bits' => 1, 'parity' => 0)
  end

  it 'reads modem line flags with ioctl rather than returning filesystem stat' do
    connection = double('UART file', lstat: :filesystem_stat)
    allow(connection).to receive(:ioctl).with(Termios::TIOCMGET, anything) do |_, buffer|
      buffer.replace([Termios::TIOCM_RTS | Termios::TIOCM_CTS].pack('i'))
      0
    end
    expect(described_class.get_line_state(serial_obj: { serial_conn: connection })).to eq('rts' => 1, 'dtr' => 0, 'cts' => 1, 'dsr' => 0, 'dcd' => 0, 'ri' => 0)
  end

  it 'preserves UTF-8 bytes through the real UART opener on a virtual PTY' do
    PTY.open do |master, slave|
      session = described_class.connect(block_dev: slave.path)
      begin
        expect(described_class.get_modem_params(serial_obj: session)).to include('baud' => 9600, 'data_bits' => 8)
        described_class.request(serial_obj: session, payload: "\u00e9")
        expect(master.wait_readable(1)).to equal(master)
        expect(master.read_nonblock(64).bytes).to eq([0xc3, 0xa9])
      ensure
        described_class.disconnect(serial_obj: session)
      end
    end
  end

  it 'writes every UTF-8 byte rather than the first byte of each character' do
    connection = StringIO.new(''.b)
    allow(described_class).to receive(:sleep)
    described_class.request(serial_obj: { serial_conn: connection }, payload: "\u00e9")
    expect(connection.string.bytes).to eq([0xc3, 0xa9])
  end
end
