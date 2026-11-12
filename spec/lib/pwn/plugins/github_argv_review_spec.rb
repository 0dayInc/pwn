# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'shellwords'

RSpec.describe PWN::Plugins::Github, 'literal gh boundary' do
  around do |example|
    Dir.mktmpdir('gh-argv-') do |dir|
      @dir = dir
      @old_path = ENV.fetch('PATH', '')
      # A space in the executable path also must not become shell syntax.
      bin = File.join(dir, 'fake tools')
      FileUtils.mkdir_p(bin)
      File.write(File.join(bin, 'gh'), <<~RUBY)
        #!#{RbConfig.ruby}
        require 'json'
        puts JSON.generate(argv: ARGV, token: ENV['GH_TOKEN'], prompt: ENV['GH_PROMPT_DISABLED'], color: ENV['NO_COLOR'])
        warn 'fixture stderr'
        exit 7
      RUBY
      File.chmod(0o700, File.join(bin, 'gh'))
      ENV['PATH'] = "#{bin}:#{@old_path}"
      example.run
    ensure
      ENV['PATH'] = @old_path
    end
  end

  it '[PBR-15] runs the exact executable with literal string arguments and preserves status' do
    marker = File.join(@dir, 'marker')
    cmd = "api 'repos/example/a b' ; printf bad > #{marker} $(printf expansion) $HOME *.rb"
    row = described_class.gh(cmd: cmd, token: 'synthetic-token')
    expect(File.exist?(marker)).to be(false)
    expect(row).to include(exit: 7, stderr: "fixture stderr\n")
    expect(JSON.parse(row[:stdout])).to eq('argv' => Shellwords.split(cmd), 'token' => 'synthetic-token', 'prompt' => '1', 'color' => '1')
  end

  it '[PBR-15] accepts argv without changing empty strings, quotes or metacharacters' do
    argv = ['api', 'repos/example/a b', '', "quote'\"", '$HOME', '$(printf bad)', ';', '*']
    row = described_class.gh(cmd: argv, token: 'synthetic-token')
    expect(JSON.parse(row[:stdout])['argv']).to eq(argv)
    expect(row[:exit]).to eq(7)
  end

  it '[PBR-15] rejects malformed quoting before starting the executable' do
    expect { described_class.gh(cmd: "api 'unclosed", token: 'synthetic-token') }.to raise_error(ArgumentError)
  end
end
