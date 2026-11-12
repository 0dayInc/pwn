# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe PWN::SAST::PomVersion, 'runtime regressions' do
  around do |example|
    Dir.mktmpdir('pwn-pom-') do |dir|
      @source_dir = dir
      example.run
    end
  end

  before do
    stub_const('PWN::Env', { ai: { module_reflection: false } })
    allow(PWN::AI::Agent::SAST).to receive(:analyze).and_return(nil)
  end

  it 'returns version matches and dependency context from the actual pom file' do
    File.write(File.join(@source_dir, 'pom.xml'), "<dependency>\n<artifactId>fixture</artifactId>\n<version>1.2.3</version>\n</dependency>\n")
    result = described_class.scan(dir_path: @source_dir)
    expect(result.length).to eq(1)
    expect(result.first[:raw_content]).to include('3:<version>1.2.3</version>')
    expect(result.first[:line_no_and_contents]).to include(include(line_no: '2', contents: "<artifactId>fixture</artifactId>\n"))
  end

  it 'works without AI configuration and with spaces in the pom directory' do
    stub_const('PWN::Env', {})
    expect(PWN::AI::Agent::SAST).not_to receive(:analyze)
    FileUtils.mkdir_p(File.join(@source_dir, 'nested project'))
    File.write(File.join(@source_dir, 'nested project/pom.xml'), "<version>2.0</version>\n")
    result = described_class.scan(dir_path: @source_dir)
    expect(result.first[:filename][:entry]).to eq('./nested project/pom.xml')
    expect(result.first[:line_no_and_contents].first[:ai_analysis]).to eq('N/A')
  end
end
