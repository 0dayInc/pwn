# frozen_string_literal: true

require 'spec_helper'
require 'pty'
require 'timeout'

RSpec.describe PWN::SDR::FlipperZero do
  it 'uses and flushes only its own real UART buffer with two PTYs' do
    PTY.open do |master1, slave1|
      PTY.open do |master2, slave2|
        first = PWN::Plugins::Serial.connect(block_dev: slave1.path)
        second = PWN::Plugins::Serial.connect(block_dev: slave2.path)
        master1.write('first')
        master2.write('second')
        Timeout.timeout(2) do
          Thread.pass until [first, second].all? { |s| PWN::Plugins::Serial.dump_session_data(serial_obj: s).any? }
        end
        expect(described_class.request(flipper_zero_obj: first, payload: 'help').join).to eq('first')
        expect(master1.read_nonblock(64)).to eq("help\r\n")
        expect(PWN::Plugins::Serial.dump_session_data(serial_obj: first)).to be_empty
        expect(PWN::Plugins::Serial.dump_session_data(serial_obj: second).join).to eq('second')
      ensure
        [first, second].compact.each { |s| PWN::Plugins::Serial.disconnect(serial_obj: s) }
      end
    end
  end

  [nil, false, '', '/fixture/missing'].each do |selector|
    it "rejects invalid explicit screen selection #{selector.inspect}" do
      expect(described_class).not_to receive(:system)
      expect { described_class.connect_via_screen(block_dev: selector) }.to raise_error(ArgumentError)
    end
  end
end
