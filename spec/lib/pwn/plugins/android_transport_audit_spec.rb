# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'
require 'rbconfig'

RSpec.describe PWN::Plugins::Android do
  around do |example|
    Dir.mktmpdir('adb-boundary-') do |root|
      @adb = File.join(root, 'adb literal ; path')
      @calls = File.join(root, 'calls')
      @output = File.join(root, 'output')
      @exit = File.join(root, 'exit')
      File.write(@output, '')
      File.write(@exit, '0')
      File.write(@adb, <<~RUBY)
        #!#{RbConfig.ruby}
        require 'json'
        File.open(#{@calls.inspect}, 'a') { |f| f.puts(JSON.generate(ARGV)) }
        print File.binread(#{@output.inspect})
        exit File.read(#{@exit.inspect}).to_i
      RUBY
      File.chmod(0o700, @adb)
      example.run
    end
  end

  %i[take_screenshot screen_record].each do |method|
    [false, true].each do |root|
      it "honors as_root: #{root} for #{method} at a real executable boundary" do
        described_class.public_send(method, adb_path: @adb, as_root: root)
        calls = File.readlines(@calls).map { |line| JSON.parse(line) }
        expect(calls.include?(['root'])).to eq(root)
      end
    end
  end

  it 'passes host filenames as literal arguments rather than a local shell command' do
    described_class.adb_push(adb_path: @adb, file: '/fixture/a b;literal', dest: '/sdcard/a b')
    expect(JSON.parse(File.read(@calls))).to eq(['push', '/fixture/a b;literal', '/sdcard/a b'])
  end

  it 'keeps intentional shell commands on Android rather than executing local shell operators' do
    described_class.adb_sh(adb_path: @adb, command: 'printf fixture; id')
    expect(JSON.parse(File.read(@calls))).to eq(['shell', 'printf fixture; id'])
  end

  it 'rejects a missing explicit adb executable instead of executing bare command names' do
    expect { described_class.adb_sh(adb_path: '/fixture/not-present', command: 'id') }.to raise_error(ArgumentError, /adb_path/)
    expect(File.exist?(@calls)).to be(false)
  end

  it 'strips the package marker from the first installed package too' do
    File.write(@output, "package:one.example\npackage:two.example\n")
    expect(described_class.list_installed_apps(adb_path: @adb)).to eq(%w[one.example two.example])
  end

  it 'surfaces an unsuccessful adb exit without echoing command output' do
    File.write(@output, 'private synthetic output')
    File.write(@exit, '1')
    expect { described_class.adb_pull(adb_path: @adb, file: '/sdcard/a', dest: '/fixture/a') }.to raise_error(IOError, /\Aadb command failed/)
  end
end
