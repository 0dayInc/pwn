# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::MSR206 do
  let(:track_data) { [{ decoded: 'fixture-one' }, { decoded: 'fixture-two' }, { decoded: 'fixture-three' }] }

  before do
    @log = StringIO.new
    allow(described_class).to receive(:logger).and_return(Logger.new(@log))
    allow(PWN::Plugins::Serial).to receive(:flush_session_data)
  end

  it 'compares the readback to the requested track data, not write acknowledgments' do
    allow(described_class).to receive(:gets).and_return("H\n")
    allow(described_class).to receive(:exec).and_return(msg: :ack_command_completed)
    allow(described_class).to receive(:wait_for_swipe).and_return([{ decoded: '^' }])
    readback = track_data.each_with_index.map do |track, index|
      track.merge(msg: :response, cmd: :"tx_iso_std_data_track#{index + 1}", encoding: :iso, track_format: [])
    end
    allow(described_class).to receive(:read_card).and_return(readback)
    expect(described_class.write_card(msr206_obj: {}, encoding: :iso, track_data: track_data)).to eq(track_data)
  end

  it 'fails on a mismatching readback instead of returning apparent write success' do
    allow(described_class).to receive(:gets).and_return("H\n")
    allow(described_class).to receive(:exec).and_return(msg: :ack_command_completed)
    allow(described_class).to receive(:wait_for_swipe).and_return([{ decoded: '^' }])
    allow(described_class).to receive(:read_card).and_return([{ decoded: 'different' }])
    expect { described_class.write_card(msr206_obj: {}, encoding: :iso, track_data: track_data) }.to raise_error(IOError, /readback/)
  end

  it 'validates the whole write batch before changing density or writing the first track' do
    allow(described_class).to receive(:gets).and_return("H\n")
    allow(described_class).to receive(:exec).and_raise('fixture guard: device write before validation')
    expect { described_class.write_card(msr206_obj: {}, encoding: :iso, track_data: [{ decoded: 'partial' }]) }.to raise_error(ArgumentError, /three tracks/)
    expect(described_class).not_to have_received(:exec)
  end

  it 'keeps command bytes and track responses out of diagnostic logs' do
    allow(PWN::Plugins::Serial).to receive(:request)
    allow(described_class).to receive(:parse_responses).and_return(decoded: 'fixture-private-track', hex: ['73 65 63 72 65 74'])
    described_class.exec(msr206_obj: {}, cmd: :load_iso_std_data_for_writing_track1, params: [115, 101, 99, 114, 101, 116])
    expect(@log.string).not_to include('fixture-private-track', '73 65 63 72 65 74', '[115, 101, 99, 114, 101, 116]')
  end

  %i[arm_to_read arm_to_write_no_raw].each do |type|
    %i[iso iso_alt raw].each do |encoding|
      it "keeps #{type} #{encoding} track payloads off diagnostic stdout" do
        allow(described_class).to receive(:exec).and_return(msg: :ack_command_completed, decoded: 'fixture-private-track')
        allow(described_class).to receive(:parse_responses).and_return(msg: :ack_command_completed)
        expect do
          described_class.send(:wait_for_swipe, msr206_obj: {}, type: type, encoding: encoding, track_data: track_data)
        end.not_to output(/fixture-private-track|102, 105, 120, 116/).to_stdout
      end
    end
  end

  it 'rejects unknown protocol selectors rather than sending USI1' do
    allow(described_class).to receive(:exec)
    expect { described_class.set_protocol(msr206_obj: {}, protocol: :typo) }.to raise_error(ArgumentError, /protocol/)
    expect(described_class).not_to have_received(:exec)
  end
end
