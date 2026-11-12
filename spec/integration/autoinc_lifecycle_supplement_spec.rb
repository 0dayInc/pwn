# frozen_string_literal: true

require 'spec_helper'
require 'open3'

RSpec.describe 'pwn_autoinc_version lifecycle audit' do
  let(:script) { File.expand_path('../../bin/pwn_autoinc_version', __dir__) }

  around do |example|
    Dir.mktmpdir('pwn-version-audit-') do |directory|
      @directory = directory
      @version_path = File.join(directory, 'lib', 'pwn', 'version.rb')
      FileUtils.mkdir_p(File.dirname(@version_path))
      example.run
    end
  end

  def bump_fixture
    Open3.capture3({ 'HOME' => @directory }, RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), script, chdir: @directory)
  end

  it 'increments the target checkout version on repeated fresh invocations instead of the installed gem version' do
    File.write(@version_path, "module PWN\n  VERSION = '1.2.3'\nend\n")
    %w[1.2.4 1.2.5].each do |expected|
      output, error, status = bump_fixture
      expect(status.success?).to be(true), error
      expect(output).to include("Upgrading to #{expected}")
      expect(File.read(@version_path)).to include("VERSION = '#{expected}'")
    end
  end

  it 'carries a full minor and hotfix rollover into the major component' do
    File.write(@version_path, "module PWN\n  VERSION = '1.9.999'\nend\n")
    _, error, status = bump_fixture
    expect(status.success?).to be(true), error
    expect(File.read(@version_path)).to include("VERSION = '2.0.0'")
  end

  it 'does not replace a malformed checkout version with an unrelated installed version' do
    original = "module PWN\n  VERSION = 'not-a-release'\nend\n"
    File.write(@version_path, original)
    _, error, status = bump_fixture
    expect(status.success?).to be(false)
    expect(error).to match(/version/i)
    expect(File.read(@version_path)).to eq(original)
  end
end
