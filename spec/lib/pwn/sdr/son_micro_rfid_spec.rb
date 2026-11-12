# frozen_string_literal: true

require 'spec_helper'

describe PWN::SDR::SonMicroRFID do
  before do
    allow(described_class).to receive(:logger).and_return(Logger.new(StringIO.new))
  end

  it 'preserves connection errors instead of referencing an unassigned connection' do
    allow(PWN::Plugins::Serial).to receive(:connect).and_raise(IOError, 'serial unavailable')
    expect { described_class.connect(block_dev: '/offline/serial') }.to raise_error(IOError, 'serial unavailable')
  end

  it 'preserves the serial disconnect return value on successful antenna shutdown' do
    connection = Object.new
    allow(described_class).to receive(:exec).and_return([{ status: :off }])
    allow(PWN::Plugins::Serial).to receive(:disconnect).with(serial_obj: connection).and_return(:closed)
    expect(described_class.disconnect(son_micro_rfid_obj: connection)).to eq(:closed)
  end

  it 'closes the serial connection even when antenna shutdown fails' do
    connection = Object.new
    allow(described_class).to receive(:exec).and_raise(IOError, 'antenna shutdown failed')
    expect(PWN::Plugins::Serial).to receive(:disconnect).with(serial_obj: connection).once
    expect { described_class.disconnect(son_micro_rfid_obj: connection) }.to raise_error(IOError, 'antenna shutdown failed')
  end

  it 'raises on mismatched write readback instead of reporting a successful write' do
    connection = Object.new
    data = { resp_code_desc: :mifare_ultralight, tag_id: 'AA BB CC DD', block_data: '01 02 03 04' }
    allow(described_class).to receive(:gets).and_return("Y\n")
    allow(described_class).to receive(:exec).with(son_micro_rfid_obj: connection, cmd: :select_tag)
                                            .and_return([{ resp_code_desc: :mifare_ultralight }])
    allow(described_class).to receive(:exec).with(son_micro_rfid_obj: connection, cmd: :write_block,
                                                  params: { block: 4, data: [1, 2, 3, 4] })
                                            .and_return([{ resp_code_desc: :write_success }])
    allow(described_class).to receive(:read_tag).and_return(data.merge(block_data: '05 06 07 08'))
    expect do
      expect { described_class.write_tag(son_micro_rfid_obj: connection, rfid_data: data) }
        .to raise_error(IOError, /readback.*match/)
    end.to output(/ERROR/).to_stdout
  end

  it 'should display information for authors' do
    authors_response = PWN::SDR::SonMicroRFID
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::SDR::SonMicroRFID
    expect(help_response).to respond_to :help
  end
end
