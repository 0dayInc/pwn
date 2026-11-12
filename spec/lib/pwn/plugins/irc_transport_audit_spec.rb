# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::IRC do
  it 'ends the receive loop on EOF without yielding nil or repeatedly reading a dead socket' do
    connection = double('IRC socket', flush: nil, close: nil)
    reads = 0
    allow(connection).to receive(:read_nonblock) do
      reads += 1
      raise IOError, 'read after EOF' if reads > 1

      nil
    end
    messages = []
    expect { described_class.listen(irc_obj: connection) { |message| messages << message } }.not_to raise_error
    expect(messages).to eq([])
    expect(connection).to have_received(:close).once
  end

  it 'addresses the join announcement to the selected channel' do
    connection, peer = UNIXSocket.pair
    described_class.join(irc_obj: connection, nick: 'fixture', chan: '#fixture')
    expect(peer.read_nonblock(1024)).to eq("JOIN #fixture\r\nPRIVMSG #fixture :fixture joined.\r\n")
  ensure
    [connection, peer].compact.each { |io| io.close unless io.closed? }
  end

  it 'collects every matching NAMES reply instead of taking an unrelated first line' do
    connection = double('IRC socket')
    allow(described_class).to receive(:irc_cmd).and_return([
                                                             'PING :fixture', ':host 353 me = #fixture :@one +two',
                                                             ':host 353 me = #other :outsider', ':host 353 me = #fixture :three', ':host 366 me #fixture :End'
                                                           ])
    expect(described_class.names(irc_obj: connection, chan: '#fixture')).to eq(%w[one two three])
  end
end
