# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'rbconfig'

RSpec.describe 'PWN::Driver D1 help banner regression' do
  it 'preserves a banner installed by the OptionParser initializer block' do
    parser = PWN::Driver::Parser.new { |options| options.banner = "fixture usage\nfixture purpose\n" }
    expect(parser.banner).to eq("fixture usage\nfixture purpose\n")
    expect(parser.to_s).to include('--pwn_env=PATH', '--pwn_dec=PATH', '--version')
  end

  it 'prints customized local automatic help without invoking an executable' do
    parser = PWN::Driver::Parser.new { |options| options.banner = "fixture usage\n" }
    parser.opts = { pwn_env_path: nil, pwn_dec_path: nil }
    stub_const('ARGV', [])
    allow(PWN::Config).to receive(:refresh_env)
    expect(parser).not_to receive(:`)
    expect do
      expect { parser.parse! }.to raise_error(SystemExit) { |error| expect(error.status).to eq(1) }
    end.to output(a_string_starting_with("fixture usage\n")).to_stdout
  end

  it 'preserves the purpose and default-action banner in real pwn_setup --help' do
    Dir.mktmpdir('pwn-setup-help-') do |home|
      root = File.expand_path('../../..', __dir__)
      out, err, status = Open3.capture3(
        { 'HOME' => home, 'PWN_CRON_DIR' => File.join(home, 'cron') },
        RbConfig.ruby, '-I', File.join(root, 'lib'), File.join(root, 'bin', 'pwn_setup'), '--help'
      )
      expect(status.exitstatus).to eq(0), err
      expect(out).to include('USAGE: pwn_setup [opts]', 'Post-install doctor & capability provisioner for the PWN gem.', 'With no options, runs a read-only capability check.', '--profile=NAME', '--pwn_env=PATH')
      expect(err).to be_empty
      expect(Dir.children(home)).to be_empty
    end
  end
end
