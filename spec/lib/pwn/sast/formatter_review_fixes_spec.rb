# frozen_string_literal: true

require 'spec_helper'
require 'digest'
require 'fileutils'
require 'open3'
require 'shellwords'
require 'tmpdir'

RSpec.describe PWN::SAST::TestCaseEngine, 'formatter review safeguards' do
  around do |example|
    Dir.mktmpdir('pwn-sast-formatter-') do |dir|
      @root = dir
      @sources = File.join(dir, 'sources')
      FileUtils.mkdir_p(@sources)
      @lock_path = File.expand_path('../../../../Gemfile.lock', __dir__)
      @lock_before = File.binread(@lock_path)
      @js_beautify_bin = Gem.bin_path('js-beautify', 'js-beautify')
      saved_env = %w[BUNDLE_GEMFILE BUNDLE_LOCKFILE RUBYOPT BUNDLE_FROZEN].to_h { |key| [key, ENV.fetch(key, nil)] }
      original_path = ENV.fetch('PATH')
      # Fixture subprocesses must not inherit the checkout lock path. Clearing
      # RUBYOPT keeps the child from booting Bundler against that disposable Gemfile.
      ENV['BUNDLE_GEMFILE'] = File.join(@root, 'Gemfile')
      ENV['BUNDLE_LOCKFILE'] = File.join(@root, 'Gemfile.lock')
      File.write(ENV.fetch('BUNDLE_GEMFILE'), "# private formatter fixture\n")
      File.write(ENV.fetch('BUNDLE_LOCKFILE'), '')
      ENV.delete('RUBYOPT')
      ENV.delete('BUNDLE_FROZEN')
      example.run
      expect(File.binread(@lock_path)).to eq(@lock_before)
    ensure
      saved_env&.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
      ENV['PATH'] = original_path if original_path
      File.binwrite(@lock_path, @lock_before) if @lock_before && File.binread(@lock_path) != @lock_before
    end
  end

  before { stub_const('PWN::Env', { ai: { module_reflection: false } }) }

  let(:options) do
    { dir_path: @sources, security_references: { sast_module: 'Fixture' },
      test_case_filter: 'grep -n -e fixture {PWN_SAST_SRC_TARGET}' }.freeze
  end

  def synthetic_formatter(body)
    commands = File.join(@root, 'commands')
    FileUtils.mkdir_p(commands)
    launcher = File.join(commands, 'js-beautify')
    File.write(launcher, "#!#{RbConfig.ruby}\n#{body}\n")
    File.chmod(0o700, launcher)
    ENV['PATH'] = "#{commands}:#{ENV.fetch('PATH')}"
  end

  it 'SERVICES-REVIEW-002 leaves an attacker sidecar symlink and its target unchanged' do
    original = "fixture;\n"
    source = File.join(@sources, 'source.js')
    sentinel = File.join(@root, 'sentinel')
    File.write(source, original)
    File.write(sentinel, 'unchanged sentinel')
    File.symlink(sentinel, "#{source}.JS-BEAUTIFIED")
    synthetic_formatter('print "\\n", STDIN.read')

    result = described_class.execute(options)

    expect(File.read(sentinel)).to eq('unchanged sentinel')
    expect(File.readlink("#{source}.JS-BEAUTIFIED")).to eq(sentinel)
    expect(File.read(source)).to eq(original)
    expect(result.first[:filename]).to include(entry: './source.js', entry_beautified: true)
    expect(result.first[:line_no_and_contents].first[:line_no]).to eq('2')
  end

  it 'SERVICES-REVIEW-002 scans formatted text without creating a source-adjacent artifact' do
    File.write(File.join(@sources, 'source.js'), "fixture;\n")
    synthetic_formatter('print STDIN.read')

    result = described_class.execute(options)
    expect(result).not_to be_empty
    temporary_path = Shellwords.split(result.first[:test_case_filter]).last
    expect(File.exist?(temporary_path)).to be(false)
    expect(Dir.children(@sources)).to eq(['source.js'])
  end

  ['', " \n\t"].each do |output|
    it "SERVICES-REVIEW-007 falls back to original input after blank formatter output #{output.inspect}" do
      File.write(File.join(@sources, 'source.js'), "fixture;\n")
      synthetic_formatter("print #{output.dump}")

      result = described_class.execute(options)

      expect(result.length).to eq(1)
      expect(result.first[:filename]).to include(entry: './source.js', entry_beautified: false)
      expect(result.first[:line_no_and_contents].first).to include(line_no: '1', contents: "fixture;\n")
      expect(Dir.children(@sources)).to eq(['source.js'])
    end
  end

  it 'SERVICES-REVIEW-002 deletes its exact private formatter file after the filter fails' do
    File.write(File.join(@sources, 'source.js'), "fixture;\n")
    synthetic_formatter('print STDIN.read')
    temporary_path = nil
    allow(Tempfile).to receive(:new).and_wrap_original do |original, *args|
      file = original.call(*args)
      temporary_path = file.path
      expect(file.stat.mode & 0o777).to eq(0o600)
      file
    end
    allow(described_class).to receive(:`).and_wrap_original do |original, command|
      raise IOError, 'fixture filter error' if command.start_with?('grep -n')

      original.call(command)
    end

    expect { described_class.execute(options) }.to raise_error(IOError, 'fixture filter error')
    expect(temporary_path).not_to be_nil
    expect(File.exist?(temporary_path)).to be(false)
  end

  it 'SERVICES-REVIEW-001 does not pass JavaScript filenames to a shell' do
    short_name = 'source;printf proof>review-marker;#.js'
    long_name = 'long;printf proof>review-marker;#.js'
    File.write(File.join(@sources, short_name), "var fixture={value:1};\n")
    File.write(File.join(@sources, long_name), 'var fixture=1;\n' * 20)
    commands = []
    argv = []
    allow(described_class).to receive(:`).and_wrap_original do |original, command|
      commands << command
      original.call(command)
    end
    allow(Open3).to receive(:capture3).and_wrap_original do |original, *args, **kwargs|
      argv << args
      original.call(*args, **kwargs)
    end
    synthetic_formatter('print STDIN.read')

    result = described_class.execute(options)

    joined = commands.join("\n")
    [short_name, long_name].each do |name|
      expect(joined).not_to include(name)
      expect(joined).not_to include(Shellwords.escape(name))
      expect(argv.flatten).not_to include(a_string_including(name))
    end
    expect(File.exist?(File.join(@sources, 'review-marker'))).to be(false)
    expect(result.map { |row| row[:filename][:entry] }).to contain_exactly("./#{short_name}", "./#{long_name}")
    expect(Digest::SHA256.file(@lock_path).hexdigest).to eq(Digest::SHA256.hexdigest(@lock_before))
  end

  it 'SERVICES-REVIEW-001 keeps a malicious filename literal through the installed launcher' do
    # Only a harmless marker inside the private source fixture can be created.
    name = 'source;printf proof>review-marker;#.js'
    source = 'var fixture={value:1};'
    File.write(File.join(@sources, name), source)
    commands_dir = File.join(@root, 'commands')
    FileUtils.mkdir_p(commands_dir)
    shell_commands = []
    allow(described_class).to receive(:`).and_wrap_original do |original, command|
      shell_commands << command
      original.call(command)
    end
    # Load the actual gem launcher by its original path: it resolves its
    # bundled parser relative to __FILE__, so symlinking that file breaks it.
    launcher = File.join(commands_dir, 'js-beautify')
    File.write(launcher, "#!#{RbConfig.ruby}\nload #{@js_beautify_bin.dump}\n")
    File.chmod(0o700, launcher)
    ENV['PATH'] = "#{commands_dir}:#{ENV.fetch('PATH')}"

    result = described_class.execute(options)

    expect(shell_commands.join("\n")).not_to include(name)
    expect(shell_commands.join("\n")).not_to include(Shellwords.escape(name))
    expect(File.exist?(File.join(@sources, 'review-marker'))).to be(false)
    expect(result.length).to eq(1)
    expect(result.first[:filename][:entry_beautified]).to be(true)
    expect(result.first[:line_no_and_contents].first[:contents]).to include('var fixture = {')
    expect(File.read(File.join(@sources, name))).to eq(source)
    expect(Digest::SHA256.file(@lock_path).hexdigest).to eq(Digest::SHA256.hexdigest(@lock_before))
  end
end
