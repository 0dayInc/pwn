# frozen_string_literal: true

require 'spec_helper'
require 'socket'
require 'timeout'

RSpec.describe PWN::Plugins::IRC do
  around do |example|
    @local, @peer = UNIXSocket.pair
    example.run
  ensure
    [@local, @peer].each { |io| io.close unless io.closed? }
  end

  ["#test\r\nQUIT :synthetic", "#test\0suffix", '#test extra'].each do |channel|
    it "rejects invalid structural channel #{channel.inspect} before writing" do
      expect { described_class.names(irc_obj: @local, chan: channel) }.to raise_error(ArgumentError)
      expect(@peer.wait_readable(0)).to be_nil
    end
  end

  it 'frames one valid command with CRLF' do
    described_class.ping(irc_obj: @local, message: 'synthetic')
    expect(@peer.read_nonblock(1024)).to eq("PING :synthetic\r\n")
  end

  it 'allows intentional multiline messages without permitting command injection' do
    described_class.privmsg(irc_obj: @local, chan: '#test', message: "one\ntwo")
    expect(@peer.read_nonblock(1024)).to eq("PRIVMSG #test :one\r\nPRIVMSG #test :two\r\n")
  end

  ["safe\nunsafe\rQUIT", "safe\ninvalid\0", "safe\n#{'x' * 512}"].each do |message|
    it 'prevalidates every message frame before the first write' do
      expect { described_class.privmsg(irc_obj: @local, chan: '#test', message: message) }.to raise_error(ArgumentError)
      expect(@peer.wait_readable(0)).to be_nil
    end
  end

  it 'parses complete native socket NAMES replies through the public Sock connection' do
    server = TCPServer.new('127.0.0.1', 0)
    connection = PWN::Plugins::Sock.connect(target: '127.0.0.1', port: server.addr[1])
    peer = server.accept
    peer.write(":host 353 me = #test :@one +two\r\n:host 353 me = #test :three\r\n")
    expect(described_class.names(irc_obj: connection, chan: '#test')).to eq(%w[one two three])
  ensure
    [connection, peer, server].compact.each { |io| io.close unless io.closed? }
  end

  it 'retains partial frames across deadlines and isolates connection buffers' do
    @peer.write(':host 353 me = #test :one')
    expect(Timeout.timeout(0.3) { described_class.names(irc_obj: @local, chan: '#test') }).to eq([])
    other, remote = UNIXSocket.pair
    remote.write(":host 353 me = #test :other\r\n")
    expect(described_class.names(irc_obj: other, chan: '#test')).to eq(['other'])
    @peer.write(" two\r\n")
    expect(described_class.names(irc_obj: @local, chan: '#test')).to eq(%w[one two])
  ensure
    [other, remote].compact.each { |io| io.close unless io.closed? }
  end

  it 'bounds a partial frame even when a legacy ready predicate is available' do
    @local.define_singleton_method(:ready?) { true }
    @peer.write(':host 353 me = #test :partial')
    expect(Timeout.timeout(0.3) { described_class.names(irc_obj: @local, chan: '#test') }).to eq([])
  end

  it 'returns complete frames at EOF without spinning' do
    @peer.write(":host 353 me = #test :one\r\n")
    @peer.shutdown(Socket::SHUT_WR)
    expect(Timeout.timeout(0.3) { described_class.names(irc_obj: @local, chan: '#test') }).to eq(['one'])
  end

  it 'rejects oversized incomplete peer frames without unbounded buffering' do
    @peer.write('x' * 513)
    expect { described_class.names(irc_obj: @local, chan: '#test') }.to raise_error(IOError, /frame/)
  end

  it 'hands retained command bytes to the native listener' do
    @peer.write('PING :frag')
    described_class.names(irc_obj: @local, chan: '#test')
    @peer.write("ment\r\n")
    @peer.shutdown(Socket::SHUT_WR)
    messages = []
    Timeout.timeout(0.3) { described_class.listen(irc_obj: @local) { |line| messages << line } }
    expect(messages).to eq(["PING :fragment\r\n"])
  end

  it 'rejects registration injection before connecting' do
    expect(PWN::Plugins::Sock).not_to receive(:connect)
    expect { described_class.connect(nick: "test\r\nQUIT", real: 'Synthetic') }.to raise_error(ArgumentError)
  end
end
