# frozen_string_literal: true

require 'spec_helper'
require 'socket'
require 'timeout'
require 'tempfile'
require 'open3'

RSpec.describe PWN::SDR::GQRX do
  it 'passes device selectors literally to the rate probe without shell expansion' do
    device = 'driver=offline,label=$(fixture),serial="mock"'
    allow(described_class).to receive(:`).and_return('')
    allow(Open3).to receive(:capture2).with('SoapySDRUtil', '--find', err: File::NULL).and_return(['', nil])
    allow(Open3).to receive(:capture2).with('SoapySDRUtil', "--probe=#{device}", err: File::NULL)
                                      .and_return(["Sample rates: 1, 2 MSps\n", nil])
    expect(described_class.device_input_rates(device: device)).to eq([1_000_000, 2_000_000])
    expect(described_class).not_to have_received(:`)
  end

  it 'updates only the input sample rate in a multi-section configuration' do
    Tempfile.create(['gqrx-config-', '.conf']) do |file|
      file.write("[other]\nsample_rate=111\n[input]\ndevice=offline\nsample_rate=222\n[output]\nsample_rate=333\n")
      file.flush
      result = described_class.set_input_rate(path: file.path, input_rate: 24_000, clamp: false, restart: false)
      expect(result).to include(previous: 222, input_rate: 24_000, restarted: false)
      expect(File.read(file.path)).to eq("[other]\nsample_rate=111\n[input]\ndevice=offline\nsample_rate=24000\n[output]\nsample_rate=333\n")
    end
  end

  it 'keeps a numeric RDS PI value unchanged rather than formatting it as a frequency' do
    client, server = UNIXSocket.pair
    server.write("1234\n")
    expect(described_class.cmd(gqrx_sock: client, cmd: 'p RDS_PI')).to eq('1234')
  ensure
    [client, server].compact.each { |io| io.close unless io.closed? }
  end

  it 'returns a complete reply even when the peer immediately closes its output' do
    client, server = UNIXSocket.pair
    server.write("RPRT 0\n")
    server.close_write
    expect(described_class.cmd(gqrx_sock: client, cmd: 'U RDS 0', resp_ok: 'RPRT 0')).to eq('RPRT 0')
  ensure
    [client, server].compact.each { |io| io.close unless io.closed? }
  end

  it 'rejects a mode response missing its passband line at EOF' do
    client, server = UNIXSocket.pair
    server.write("FM\n")
    server.close_write
    expect { described_class.cmd(gqrx_sock: client, cmd: 'm') }.to raise_error(IOError, /Incomplete.*response/)
  ensure
    [client, server].compact.each { |io| io.close unless io.closed? }
  end

  it 'bounds partial-line waits rather than blocking forever after readability' do
    client, server = UNIXSocket.pair
    server.write('RPRT ')
    expect do
      Timeout.timeout(3) { described_class.cmd(gqrx_sock: client, cmd: 'U RDS 0') }
    end.to raise_error(IOError, /response.*timed out/)
  ensure
    [client, server].compact.each { |io| io.close unless io.closed? }
  end

  it 'collects delayed mode and passband lines without consuming the next command response' do
    client, server = UNIXSocket.pair
    peer = Thread.new do
      expect(server.gets).to eq("m\n")
      server.write("FM\n")
      sleep 0.02
      server.write("12000\n")
      expect(server.gets).to eq("l STRENGTH\n")
      server.write("-50.0\n")
    end
    expect(described_class.cmd(gqrx_sock: client, cmd: 'm')).to eq('FM 12000')
    expect(described_class.cmd(gqrx_sock: client, cmd: 'l STRENGTH')).to eq('-50.0')
    Timeout.timeout(1) { peer.value }
  ensure
    peer&.kill&.join
    [client, server].compact.each { |io| io.close unless io.closed? }
  end
end
