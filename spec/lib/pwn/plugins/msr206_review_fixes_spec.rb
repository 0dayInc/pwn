# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::MSR206 do
  before do
    @commands = []
    @log = StringIO.new
    allow(described_class).to receive(:logger).and_return(Logger.new(@log))
    allow(PWN::Plugins::Serial).to receive(:request) { |options| @commands << options[:payload].dup }
    allow(PWN::Plugins::Serial).to receive(:response).and_return(['5E'])
    allow(PWN::Plugins::Serial).to receive(:flush_session_data)
    allow(described_class).to receive(:gets).and_return("H\n")
    allow(described_class).to receive(:read_card).and_return([{ decoded: 'A' }, { decoded: 'B' }, { decoded: 'C' }])
  end

  [nil, false].each do |selector|
    it "rejects explicit #{selector.inspect} MSR selectors without substituting a device" do
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with('/dev/ttyUSB0').and_return(true)
      expect(UART).not_to receive(:open)
      expect { described_class.connect(block_dev: selector) }.to raise_error(ArgumentError)
    end
  end

  %i[iso_alt raw].each do |encoding|
    [nil, false, 'invalid', [], [256], [0x5f], [0x31, 0x32]].each do |format|
      it "prevalidates all #{encoding} formats including later malformed #{format.inspect}" do
        tracks = [{ decoded: 'A' }, { decoded: 'B', track_format: format }, { decoded: 'C' }]
        expect { described_class.write_card(msr206_obj: {}, encoding: encoding, track_data: tracks) }.to raise_error(ArgumentError)
        expect(@commands).to be_empty
        expect(described_class).not_to have_received(:gets)
      end
    end
  end

  %i[iso iso_alt raw].each do |encoding|
    ["synthetic\x04", "synthetic\0", "synthetic\n", "synthetic\u00e9", 'A' * 1024].each do |payload|
      it "rejects unencodable #{encoding} payloads before prompting or device commands" do
        tracks = [{ decoded: 'A' }, { decoded: 'B' }, { decoded: payload }]
        # The existing implementation can reach readback: keep that old path bounded.
        allow(described_class).to receive(:read_card).and_return(tracks)
        expect { described_class.write_card(msr206_obj: {}, encoding: encoding, track_data: tracks) }.to raise_error(ArgumentError)
        expect(@commands).to be_empty
        expect(described_class).not_to have_received(:gets)
        expect(@log.string).not_to include(payload)
      end
    end
  end
end
