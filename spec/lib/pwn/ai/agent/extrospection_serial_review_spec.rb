# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

RSpec.describe PWN::AI::Agent::Extrospection, 'serial buffer ownership' do
  include_context 'pwn tmp sandbox'

  it 'senses its own connection while preserving another live session buffer' do
    serial = PWN::Plugins::Serial
    first_reader, first_writer = IO.pipe
    second_reader, second_writer = IO.pipe
    first_path = File.join(@tmp, 'first-serial-fixture')
    second_path = File.join(@tmp, 'second-serial-fixture')
    [first_path, second_path].each { |path| File.write(path, '') }
    allow(UART).to receive(:open).with(first_path, 9600, '8N1').and_return(first_reader)
    allow(UART).to receive(:open).with(second_path, 9600, '8N1').and_return(second_reader)
    allow(second_reader).to receive(:ioctl).and_return(0)
    allow(Termios).to receive(:tcgetattr).with(second_reader).and_return(double('attributes', ospeed: Termios::B9600, cflag: Termios::CS8))
    first = serial.connect(block_dev: first_path)
    first_writer.write('first-buffer')
    Timeout.timeout(2) { Thread.pass until serial.dump_session_data(serial_obj: first).join == 'first-buffer' }
    second = nil
    allow(serial).to receive(:connect).and_wrap_original do |original, opts|
      second = original.call(opts)
    end
    allow(described_class).to receive(:probe_serial).and_return([])
    allow(described_class).to receive(:sleep) do
      second_writer.write('second-buffer')
      Timeout.timeout(2) { Thread.pass until serial.dump_session_data(serial_obj: second).join == 'second-buffer' }
    end
    result = described_class.serial_sense(block_dev: second_path, settle_secs: 0.2, record: false)
    expect(result).to include(ok: true, text: 'second-buffer')
    expect(serial.dump_session_data(serial_obj: first).join).to eq('first-buffer')
    expect(first_reader).not_to be_closed
    expect(second_reader).to be_closed
  ensure
    serial.disconnect(serial_obj: first) if first
    serial.disconnect(serial_obj: second) if second
    [first_reader, first_writer, second_reader, second_writer].compact.each { |io| io.close unless io.closed? }
  end
end
