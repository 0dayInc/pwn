# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::MSR206 do
  before do
    @commands = []
    @log = StringIO.new
    allow(described_class).to receive(:logger).and_return(Logger.new(@log))
    allow(PWN::Plugins::Serial).to receive(:flush_session_data)
    allow(PWN::Plugins::Serial).to receive(:request) { |options| @commands << options[:payload].dup }
    allow(PWN::Plugins::Serial).to receive(:response) do
      case @commands.last&.first
      when 0x26 then ['3E']
      when 0x51, 0x71, 0x55 then ['41 41 41']
      when 0x52, 0x72, 0x56 then ['42 42 42']
      when 0x53, 0x73, 0x57 then ['43 43 43']
      else ['5E']
      end
    end
  end

  { iso: [[], [], []], iso_alt: [[0x31], [0x32], [0x33]], raw: [[0x5f, 0x35], [0x34], [0x37]] }.each do |encoding, formats|
    it "verifies actual #{encoding} command parsing using exactly the written per-track formats" do
      tracks = %w[AAA BBB CCC].each_with_index.map { |text, i| { decoded: text, track_format: formats[i] } }
      original = Marshal.dump(tracks)
      choice = { iso: 'I', iso_alt: 'A', raw: 'R' }.fetch(encoding)
      allow(described_class).to receive(:gets).and_return("H\n", "H\n", "#{choice}\n")
      result = nil
      expect { result = described_class.write_card(msr206_obj: {}, encoding: encoding, track_data: tracks) }.not_to output(/AAA|BBB|CCC/).to_stdout
      expect(result).to equal(tracks)
      expect(Marshal.dump(tracks)).to eq(original)
      readers = { iso: [0x51, 0x52, 0x53], iso_alt: [0x71, 0x72, 0x73], raw: [0x55, 0x56, 0x57] }.fetch(encoding)
      expect(@commands.select { |cmd| readers.include?(cmd.first) }).to eq(readers.each_with_index.map { |cmd, i| [cmd] + formats[i] })
      expect(@commands.last).to eq([0x7f])
      expect(@commands).to include([encoding == :raw ? 0x40 : 0x5a])
      expect(@log.string).not_to match(/AAA|BBB|CCC|41 41 41|42 42 42|43 43 43/)
    end

    it "rejects #{encoding} readback mismatches and does not replay or reset" do
      tracks = %w[AAA BBB wrong].each_with_index.map { |text, i| { decoded: text, track_format: formats[i] } }
      choice = { iso: 'I', iso_alt: 'A', raw: 'R' }.fetch(encoding)
      allow(described_class).to receive(:gets).and_return("H\n", "H\n", "#{choice}\n")
      expect { described_class.write_card(msr206_obj: {}, encoding: encoding, track_data: tracks) }.to raise_error(IOError, /readback mismatch/)
      expect(@commands).not_to include([0x7f])
      expect(@commands.count { |cmd| [0x41, 0x61, 0x45].include?(cmd.first) }).to eq(1)
    end
  end

  %i[iso_alt raw].each do |encoding|
    it "accepts actual #{encoding} backup candidates only with explicit format selections" do
      choice = encoding == :iso_alt ? 'A' : 'R'
      allow(described_class).to receive(:gets).and_return("#{choice}\n")
      tracks = described_class.read_card(msr206_obj: {})
      expect(tracks.length).to eq(encoding == :iso_alt ? 9 : 30)
      @commands.clear
      formats = encoding == :iso_alt ? [[0x31], [0x32], [0x33]] : [[0x33], [0x5f, 0x34], [0x37]]
      allow(described_class).to receive(:gets).and_return("H\n", "H\n", "#{choice}\n")
      expect(described_class.write_card(msr206_obj: {}, encoding: encoding, track_data: tracks, track_formats: formats)).to eq(tracks)
      expect(@commands.last).to eq([0x7f])
    end
  end

  it 'uses explicit format selections for three manual tracks without per-row format metadata' do
    tracks = %w[AAA BBB CCC].map { |text| { decoded: text } }
    formats = [[0x32], [0x31], [0x33]]
    allow(described_class).to receive(:gets).and_return("H\n")
    expect(described_class.write_card(msr206_obj: {}, encoding: :iso_alt, track_data: tracks, track_formats: formats)).to eq(tracks)
    expect(@commands.select { |cmd| [0x71, 0x72, 0x73].include?(cmd.first) }).to eq([[0x71, 0x32], [0x72, 0x31], [0x73, 0x33]])
  end

  %i[clone_card load_card_from_file].each do |operation|
    it "forwards explicit candidate formats through real #{operation} orchestration" do
      Dir.mktmpdir('msr-backup-') do |root|
        backup = File.join(root, 'synthetic.json')
        allow(described_class).to receive(:gets).and_return("A\n", "#{backup}\n")
        described_class.backup_card(msr206_obj: {}) if operation == :load_card_from_file
        answers = operation == :clone_card ? ["A\n", "#{backup}\n", "H\n", "H\n"] : ["#{backup}\n", "H\n", "H\n"]
        allow(described_class).to receive(:gets).and_return(*answers)
        result = described_class.public_send(operation, msr206_obj: {}, track_formats: [[0x31], [0x32], [0x33]])
        expect(result.length).to eq(9)
        expect(@commands.last).to eq([0x7f])
      end
    end
  end

  it 'does not confuse command acknowledgments with track readback' do
    allow(PWN::Plugins::Serial).to receive(:response).and_return(['5E'])
    allow(described_class).to receive(:gets).and_return("H\n", "H\n", "I\n")
    tracks = Array.new(3) { { decoded: '^' } }
    expect { described_class.write_card(msr206_obj: {}, encoding: :iso, track_data: tracks) }.to raise_error(IOError, /readback/)
  end

  it 'does not disclose synthetic track bodies in the public update prompts' do
    Dir.mktmpdir('msr-update-') do |root|
      allow(described_class).to receive(:gets).and_return("I\n", "#{File.join(root, 'synthetic.json')}\n", "\n", "\n", "\n", "N\n")
      result = nil
      expect { result = described_class.update_card(msr206_obj: {}) }.not_to output(/AAA|BBB|CCC/).to_stdout
      expect(result.map { |track| track[:decoded] }).to eq(%w[AAA BBB CCC])
      expect(@log.string).not_to match(/AAA|BBB|CCC/)
    end
  end

  it 'uses the prevalidated immutable batch even if the caller changes its source during prompts' do
    tracks = %w[AAA BBB CCC].map { |text| { decoded: text } }
    allow(described_class).to receive(:gets) do
      tracks[0][:decoded] = 'changed'
      "H\n"
    end
    # Old read_card prompts indefinitely on H; fail that old path without hardware.
    allow(described_class).to receive(:read_card).and_wrap_original do |original, options|
      raise IOError, 'readback was not format-correlated' unless options[:encoding]

      original.call(options)
    end
    expect(described_class.write_card(msr206_obj: {}, encoding: :iso, track_data: tracks)).to eq(tracks)
    expect(@commands).to include([0x41, 0x41, 0x41, 0x41, 0x04])
  end
end
