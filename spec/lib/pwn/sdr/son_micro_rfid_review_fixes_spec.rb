# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::SDR::SonMicroRFID, 'review write/readback regressions' do
  # These are host parser fixtures, not physical-device protocol captures.
  def serial_fixture(type: '02', data: [1] * 16, read_status: '00', auth_status: '00')
    commands = []
    pending = nil
    allow(PWN::Plugins::Serial).to receive(:request) do |opts|
      payload = opts.fetch(:payload)
      commands << payload
      code = payload[3]
      pending = case code
                when 0x82, 0x83 then "FF 00 06 #{format('%02X', code)} #{type} 11 22 33 44 00"
                when 0x85 then "FF 00 02 85 #{auth_status} 00"
                when 0x87 then 'FF 00 02 87 00 00'
                when 0x86 then "FF 00 #{format('%02X', data.length + 2)} 86 #{read_status} #{data.map { |byte| format('%02X', byte) }.join(' ')} 00"
                else raise "unexpected fixture command #{code}"
                end
    end
    allow(PWN::Plugins::Serial).to receive(:response) { [pending] }
    allow(PWN::Plugins::Serial).to receive(:flush_session_data)
    commands
  end

  before do
    allow(described_class).to receive(:logger).and_return(Logger.new(StringIO.new))
    allow(described_class).to receive(:gets).and_return("Y\n")
  end

  [nil, '', 'GG', '01', ['01'], (['01'] * 17).join(' ')].each do |payload|
    it "PSR-L03 rejects absent or unsupported Classic block data #{payload.inspect} before confirmation or serial traffic" do
      commands = serial_fixture
      data = { resp_code_desc: :mifare_classic_1k, tag_id: '11 22 33 44', block_data: payload }
      expect do
        described_class.write_tag(son_micro_rfid_obj: Object.new, rfid_data: data, authn: true)
      end.to raise_error(ArgumentError, /block_data/)
      expect(described_class).not_to have_received(:gets)
      expect(commands).to be_empty
    end
  end

  it 'PSR-L03 requires authentication for a Classic write before confirmation or serial traffic' do
    commands = serial_fixture
    data = { resp_code_desc: :mifare_classic_1k, tag_id: '11 22 33 44', block_data: (['01'] * 16).join(' ') }
    expect do
      described_class.write_tag(son_micro_rfid_obj: Object.new, rfid_data: data)
    end.to raise_error(ArgumentError, /authn/)
    expect(described_class).not_to have_received(:gets)
    expect(commands).to be_empty
  end

  %i[mifare_classic_1k mifare_classic_4k].each do |type|
    it "PSR-L03 authenticates both write and real readback for #{type}" do
      commands = serial_fixture(type: type == :mifare_classic_1k ? '02' : '03', data: [0xab] * 16)
      data = { resp_code_desc: type, tag_id: '11 22 33 44', block_data: (['ab'] * 16).join(' ') }
      key = [1, 2, 3, 4, 5, 6] # synthetic authentication fixture
      result = described_class.write_tag(son_micro_rfid_obj: Object.new, rfid_data: data, authn: true, key: key)
      expect(result).to eq(data)
      expect(commands.map { |payload| payload[3] }).to eq([0x83, 0x85, 0x87, 0x82, 0x85, 0x86])
      expect(commands.select { |payload| payload[3] == 0x85 }.map { |payload| payload.drop(4) }).to eq([[0, 0x60, *key]] * 2)
      expect(commands.find { |payload| payload[3] == 0x87 }.drop(4)).to eq([0, *([0xab] * 16)])
    end
  end

  it 'preserves successful Ultralight return data after a real readback' do
    commands = serial_fixture(type: '01', data: [1, 2, 3, 4])
    data = { resp_code_desc: :mifare_ultralight, tag_id: '11 22 33 44', block_data: '01 02 03 04' }
    expect(described_class.write_tag(son_micro_rfid_obj: Object.new, rfid_data: data)).to eq(data)
    expect(commands.map { |payload| payload[3] }).to eq([0x83, 0x87, 0x82, 0x86])
  end

  %w[01 00].each do |read_status|
    it "does not verify missing/failed real readback (#{read_status.inspect})" do
      serial_fixture(type: '01', data: [], read_status: read_status)
      data = { resp_code_desc: :mifare_ultralight, tag_id: '11 22 33 44', block_data: '01 02 03 04' }
      expect do
        described_class.write_tag(son_micro_rfid_obj: Object.new, rfid_data: data)
      end.to raise_error(IOError, /readback.*match/)
    end
  end

  it 'rejects an unsupported tag type before asking for confirmation' do
    commands = serial_fixture
    data = { resp_code_desc: :unknown_tag_type, tag_id: '11 22 33 44', block_data: '01 02 03 04' }
    expect do
      described_class.write_tag(son_micro_rfid_obj: Object.new, rfid_data: data)
    end.to raise_error(ArgumentError, /Unsupported tag type/)
    expect(described_class).not_to have_received(:gets)
    expect(commands).to be_empty
  end

  it 'PSR-L03 refuses the default Classic clone when its read supplies no block payload' do
    commands = serial_fixture
    expect do
      described_class.clone_tag(son_micro_rfid_obj: Object.new)
    end.to raise_error(ArgumentError, /block_data/)
    expect(commands.map { |payload| payload[3] }).to eq([0x82])
  end

  it 'documents the supported payload and authenticated readback requirements' do
    expect { described_class.help }.to output(/4 Ultralight or 16 Classic.*authn: true/m).to_stdout
  end

  it 'retains cancellation without any write or readback' do
    commands = serial_fixture(type: '01', data: [1, 2, 3, 4])
    allow(described_class).to receive(:gets).and_return("N\n")
    data = { resp_code_desc: :mifare_ultralight, tag_id: '11 22 33 44', block_data: '01 02 03 04' }
    expect(described_class.write_tag(son_micro_rfid_obj: Object.new, rfid_data: data)).to eq(data)
    expect(commands).to be_empty
  end
end
