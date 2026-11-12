# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'tmpdir'
require 'fileutils'

RSpec.describe PWN::SAST::TestCaseEngine, 'runtime boundaries' do
  around do |example|
    Dir.mktmpdir('pwn-sast-engine-') do |dir|
      @source_dir = dir
      example.run
    end
  end

  before do
    stub_const('PWN::Env', { ai: { module_reflection: false } })
    allow(PWN::AI::Agent::SAST).to receive(:analyze).and_return(nil)
  end

  let(:scan_options) do
    { dir_path: @source_dir, test_case_filter: 'grep -n -e fixture {PWN_SAST_SRC_TARGET}', security_references: { sast_module: 'Fixture' } }
  end

  it 'uses exclude_extensions rather than silently falling back to defaults' do
    File.write(File.join(@source_dir, 'sample.txt'), "fixture\n")
    expect(described_class.execute(scan_options.merge(exclude_extensions: ['.txt']))).to eq([])
  end

  it 'honors the documented exclusion option without mutating caller options' do
    File.write(File.join(@source_dir, 'sample.txt'), "fixture\n")
    options = scan_options.merge(exclude_extensions: ['.txt']).freeze
    expect(described_class.execute(options)).to eq([])
  end

  it 'scans escaped filenames as files and preserves their literal names in findings' do
    filename = "space ' quote & dollar$.txt"
    File.write(File.join(@source_dir, filename), "fixture\n")
    result = described_class.execute(scan_options)
    expect(result.length).to eq(1)
    expect(result.first[:filename][:entry]).to eq("./#{filename}")
    expect(result.first[:line_no_and_contents].first[:contents]).to eq("fixture\n")
  end

  it 'scans the original JavaScript when the optional beautifier is absent' do
    File.write(File.join(@source_dir, 'source.js'), "fixture\n")
    allow(described_class).to receive(:`).and_wrap_original do |original, command|
      command.start_with?('js-beautify ') ? '' : original.call(command)
    end
    allow(Open3).to receive(:capture3).with('js-beautify', '-', stdin_data: "fixture\n").and_raise(Errno::ENOENT)
    result = described_class.execute(scan_options)
    expect(result.length).to eq(1)
    expect(result.first[:filename][:entry]).to eq('./source.js')
    expect(File.exist?(File.join(@source_dir, 'source.js.JS-BEAUTIFIED'))).to be(false)
  end

  it 'surfaces a failing beautifier rather than reporting a clean JavaScript scan' do
    File.write(File.join(@source_dir, 'source.js'), "fixture\n")
    allow(described_class).to receive(:`).and_wrap_original do |original, command|
      command.start_with?('js-beautify ') ? '' : original.call(command)
    end
    status = instance_double(Process::Status, success?: false, exitstatus: 2)
    allow(Open3).to receive(:capture3).with('js-beautify', '-', stdin_data: "fixture\n").and_return(['', 'fixture failure', status])
    expect { described_class.execute(scan_options) }.to raise_error(RuntimeError, /js-beautify.*failed/)
  end

  it 'scans successful beautifier output while leaving the original source unchanged' do
    source = 'fixture;'
    File.write(File.join(@source_dir, 'source.js'), source)
    status = instance_double(Process::Status, success?: true)
    expect(Open3).to receive(:capture3).with('js-beautify', '-', stdin_data: source).and_return(["\nfixture;\n", '', status])
    result = described_class.execute(scan_options)
    expect(result.first[:filename]).to include(entry: './source.js', entry_beautified: true)
    expect(result.first[:line_no_and_contents].first[:line_no]).to eq('2')
    expect(File.read(File.join(@source_dir, 'source.js'))).to eq(source)
  end

  it 'retains explicitly enabled AI analysis at the external boundary' do
    stub_const('PWN::Env', { ai: { module_reflection: true } })
    File.write(File.join(@source_dir, 'source.txt'), "fixture\n")
    expect(PWN::AI::Agent::SAST).to receive(:analyze).with(request: kind_of(String)).and_return('fixture analysis')
    expect(described_class.execute(scan_options).first[:line_no_and_contents].first[:ai_analysis]).to eq('fixture analysis')
  end

  it 'scans without AI configuration and never enters the optional analyzer' do
    stub_const('PWN::Env', { driver_opts: {} })
    expect(PWN::AI::Agent::SAST).not_to receive(:analyze)
    File.write(File.join(@source_dir, 'sample.txt'), "fixture\n")
    expect(described_class.execute(scan_options).first[:line_no_and_contents].first[:ai_analysis]).to eq('N/A')
  end
end
