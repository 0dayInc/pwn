# frozen_string_literal: true

require 'spec_helper'
require 'socket'

describe PWN::Plugins::ProcessTube do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'connect uses the same write_line/recvuntil API over TCP' do
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thr = Thread.new do
      sock = server.accept
      sock.write("banner\n")
      sock.flush
      line = sock.gets
      sock.write("ack #{line}")
      sock.close
    end
    tube = described_class.connect(host: '127.0.0.1', port: port)
    described_class.recvuntil(id: tube[:id], until: "\n", timeout: 2)
    described_class.write_line(id: tube[:id], line: 'hi')
    out = described_class.recvuntil(id: tube[:id], until: 'hi', timeout: 2)
    expect(out).to include('ack')
  ensure
    described_class.close(id: tube[:id]) if defined?(tube) && tube
    thr&.kill
    server&.close
  end
end
