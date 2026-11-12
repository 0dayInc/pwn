# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Sock do
  it 'closes every failed TLS attempt before retrying' do
    sockets = Array.new(4) { double('TCP socket', close: nil, closed?: false) }
    tls_sockets = Array.new(4) { double('TLS socket', close: nil, :hostname= => nil, :sync_close= => nil) }
    allow(TCPSocket).to receive(:open).and_return(*sockets)
    allow(OpenSSL::SSL::SSLSocket).to receive(:new).and_return(*tls_sockets)
    tls_sockets.each { |socket| allow(socket).to receive(:connect).and_raise(OpenSSL::SSL::SSLError, 'fixture handshake failure') }
    expect { described_class.connect(target: 'fixture.invalid', port: 443, tls: true) }.to raise_error(/fixture handshake failure/)
    sockets.each { |socket| expect(socket).to have_received(:close).once }
  end

  it 'returns an already-bound detached listener without probing the requested port zero' do
    server = double('bound server', close: nil)
    allow(TCPServer).to receive(:open).with('127.0.0.1', 0).and_return(server)
    allow(described_class).to receive(:check_port_in_use).and_raise('unnecessary probe')
    expect(described_class.listen(port: 0, detach: true)).to equal(server)
    expect(server).not_to have_received(:close)
  end

  [IOError, Interrupt].each do |error|
    it "closes a TCP handle when TLS initialization raises #{error}" do
      socket = double('TCP socket', close: nil, closed?: false)
      allow(TCPSocket).to receive(:open).and_return(socket)
      allow(OpenSSL::SSL::SSLSocket).to receive(:new).and_raise(error, 'fixture initialization failure')
      expect { described_class.connect(target: 'fixture.invalid', port: 443, tls: true) }.to raise_error(error, 'fixture initialization failure')
      expect(socket).to have_received(:close).once
    end
  end

  it 'closes each accepted client rather than the last client captured by the accept loop' do
    clients = Array.new(2) { double('client', peeraddr: ['fixture'], gets: nil, close: nil) }
    server = double('TCP server', close: nil)
    queue = clients.dup
    allow(server).to receive(:accept) { queue.empty? ? raise(Interrupt) : queue.shift }
    allow(TCPServer).to receive(:open).and_return(server)
    callbacks = []
    allow(Thread).to receive(:new) { |client, &callback| callbacks << [client, callback] }
    described_class.listen(port: 12_345)
    callbacks.first[1].call(callbacks.first[0])
    expect(clients[0]).to have_received(:close).once
    expect(clients[1]).not_to have_received(:close)
  end

  it 'closes a detached UDP listener when bind fails' do
    server = double('UDP socket', close: nil)
    allow(UDPSocket).to receive(:new).and_return(server)
    allow(server).to receive(:bind).and_raise(Errno::EADDRINUSE)
    expect { described_class.listen(port: 12_345, protocol: :udp, detach: true) }.to raise_error(Errno::EADDRINUSE)
    expect(server).to have_received(:close).once
  end
end
