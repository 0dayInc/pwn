# frozen_string_literal: true

require 'spec_helper'
require 'pty'
require 'timeout'

RSpec.describe PWN::Plugins::Serial do
  [Interrupt, IOError].each do |error|
    it "cleans acquired handles and registrations when reader startup raises #{error}" do
      connection = StringIO.new
      allow(File).to receive(:exist?).with('/fixture/serial').and_return(true)
      allow(UART).to receive(:open).and_return(connection)
      allow(Thread).to receive(:new).and_raise(error, 'primary startup failure')
      allow(connection).to receive(:close).and_wrap_original do |original|
        original.call
        raise IOError, 'secondary close failure'
      end
      expect { described_class.connect(block_dev: '/fixture/serial') }.to raise_error(error, 'primary startup failure')
      expect(connection).to be_closed
      expect(described_class.instance_variable_get(:@sessions)).to be_empty
    ensure
      described_class.instance_variable_get(:@sessions).delete_if { |s| s[:serial_conn].equal?(connection) }
      connection.close unless connection.closed?
    end
  end

  %i[request get_line_state get_modem_params].each do |operation|
    it "preserves the primary #{operation} failure when close fails" do
      connection = double('fake UART', closed?: false)
      allow(connection).to receive(:close).and_raise(IOError, 'secondary close failure')
      allow(connection).to receive(:putc).and_raise(IOError, 'primary operation failure')
      allow(connection).to receive(:ioctl).and_raise(IOError, 'primary operation failure')
      allow(Termios).to receive(:tcgetattr).and_raise(IOError, 'primary operation failure')
      expect { described_class.public_send(operation, serial_obj: { serial_conn: connection }, payload: 'x') }.to raise_error(IOError, 'primary operation failure')
      expect(connection).to have_received(:close).once
    end
  end

  it 'does not treat an unrelated caller rescue as a primary operation failure' do
    connection = double('fake UART', closed?: false)
    allow(connection).to receive(:close).and_raise(IOError, 'close failure')
    begin
      raise 'unrelated caller error'
    rescue RuntimeError
      expect { described_class.disconnect(serial_obj: { serial_conn: connection }) }.to raise_error(IOError, 'close failure')
    end
  end

  it 'surfaces a standalone close failure' do
    connection = double('fake UART', closed?: false)
    allow(connection).to receive(:close).and_raise(IOError, 'close failure')
    expect { described_class.disconnect(serial_obj: { serial_conn: connection }) }.to raise_error(IOError, 'close failure')
  end

  [nil, false, '', '/fixture/missing', "bad\0path"].each do |selector|
    it "rejects an explicit invalid selector #{selector.inspect} through BusPirate before acquisition" do
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with('/dev/ttyUSB0').and_return(true)
      expect(UART).not_to receive(:open)
      expect { PWN::Plugins::BusPirate.connect(block_dev: selector) }.to raise_error(ArgumentError)
    end
  end

  it 'uses the default only for an absent selector, without mutating the options' do
    reader, writer = IO.pipe
    allow(File).to receive(:exist?).with('/dev/ttyUSB0').and_return(true)
    expect(UART).to receive(:open).with('/dev/ttyUSB0', 9600, '8N1').and_return(reader)
    options = {}.freeze
    session = described_class.connect(options)
    expect(session[:serial_conn]).to equal(reader)
  ensure
    described_class.disconnect(serial_obj: session) if session
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end
end
