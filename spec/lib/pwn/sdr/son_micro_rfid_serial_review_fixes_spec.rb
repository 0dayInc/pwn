# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/serial'
require 'socket'
require 'timeout'

RSpec.describe PWN::SDR::SonMicroRFID, 'review Serial session ownership regressions' do
  def with_two_sessions(reply: [0xff, 0x00, 0x06, 0x82, 0x02, 0x11, 0x22, 0x33, 0x44, 0x00])
    sessions = []
    sockets = []
    allow(File).to receive(:exist?).and_call_original
    %w[/fixture/sonmicro /fixture/other].each do |path|
      local, remote = UNIXSocket.pair
      sockets.push(local, remote)
      allow(File).to receive(:exist?).with(path).and_return(true)
      allow(UART).to receive(:open).with(path, 9600, '8N1').and_return(local)
      sessions << PWN::Plugins::Serial.connect(block_dev: path)
    end
    sockets.last.write('untouched')
    Timeout.timeout(2) do
      Thread.pass until PWN::Plugins::Serial.dump_session_data(serial_obj: sessions.last).join == 'untouched'
    end
    peer = Thread.new do
      request = sockets[1].read(5)
      if request && request.bytesize == 5
        if reply == :eof
          sockets[1].close
        else
          sockets[1].write(reply.pack('C*'))
        end
      end
    end
    Timeout.timeout(2) { yield sessions.first, sessions.last }
    expect(PWN::Plugins::Serial.dump_session_data(serial_obj: sessions.last).join).to eq('untouched')
  ensure
    peer&.kill&.join
    sessions&.each do |session|
      session[:session_data] = session[:session_data].dup if session[:session_data].frozen?
      PWN::Plugins::Serial.disconnect(serial_obj: session)
    end
    sockets&.each { |socket| socket.close unless socket.closed? }
  end

  before do
    allow(described_class).to receive(:logger).and_return(Logger.new(StringIO.new))
  end

  it 'flushes only the selected handle through real Serial and actual response parsing' do
    with_two_sessions do |selected, _other|
      result = described_class.read_tag(son_micro_rfid_obj: selected)
      expect(result).to include(resp_code_desc: :mifare_classic_1k, tag_id: '11 22 33 44')
      expect(PWN::Plugins::Serial.dump_session_data(serial_obj: selected)).to eq([])
    end
  end

  it 'preserves actual Serial EOF instead of masking it with an ambiguous cleanup error' do
    with_two_sessions(reply: :eof) do |selected, _other|
      expect { described_class.read_tag(son_micro_rfid_obj: selected) }.to raise_error(EOFError)
    end
  end

  it 'preserves command errors when real selected-session cleanup also fails' do
    with_two_sessions do |selected, _other|
      selected[:session_data].freeze
      expect { described_class.exec(son_micro_rfid_obj: selected, cmd: :unsupported_fixture) }
        .to raise_error(RuntimeError, /Unsupported Command/)
    end
  end

  it 'does not choose a global session during cleanup when no handle was supplied' do
    with_two_sessions do |_selected, _other|
      expect { described_class.exec(cmd: :unsupported_fixture) }.to raise_error(RuntimeError, /Unsupported Command/)
    end
  end
end
