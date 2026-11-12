# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::BareSIP do
  around do |example|
    Dir.mktmpdir('baresip-audit-') do |root|
      @root = root
      File.write(File.join(root, 'config'), "http_listen 127.0.0.1:12345\ncall_max_calls 1\n")
      example.run
    end
  end

  before do
    allow(PWN::Plugins::Sock).to receive(:get_random_unused_port).and_return(12_345)
    allow(described_class).to receive(:system).and_return(true)
  end

  ['403 Forbidden', 'account: No SIP accounts found'].each do |failure|
    it "terminates startup on fresh #{failure} alone" do
      allow(described_class).to receive(:system) do |*args|
        File.open(args[args.index('-Logfile') + 1], 'a') { |file| file.puts(failure) } if args.include?('-Logfile')
        true
      end
      expect { described_class.start(config_root: @root, session_root: @root) }.to raise_error(/#{Regexp.escape(failure)}/)
    end
  end

  [RuntimeError, Interrupt].each do |error|
    it "stops only the launched session when startup raises #{error}" do
      log = File.join(@root, 'screenlog.txt')
      allow(File).to receive(:stat).and_call_original
      allow(File).to receive(:stat).with(log).and_raise(error, 'fixture startup interruption')
      expect { described_class.start(config_root: @root, session_root: @root, screen_session: 'fixture-session') }.to raise_error(error, 'fixture startup interruption')
      expect(described_class).to have_received(:system).with('screen', '-S', 'fixture-session', '-X', 'quit').once
    end
  end

  it 'uses the current working directory as the default session root' do
    log = File.join(@root, 'screenlog.txt')
    allow(described_class).to receive(:system) do |*args|
      File.open(log, 'a') { |file| file.puts('registered successfully') } if args.include?('-Logfile')
      true
    end
    Dir.chdir(@root) do
      expect(described_class.start(config_root: @root, screenlog_path: log)[:session_root]).to eq(@root)
    end
  end

  it 'does not wait for registration when launching screen fails' do
    allow(described_class).to receive(:system).and_return(false)
    expect { described_class.start(config_root: @root, session_root: @root) }.to raise_error(/Failed to launch/)
  end

  it 'bounds missing registration logs with an explicit startup deadline' do
    expect { described_class.start(config_root: @root, session_root: @root, timeout: 0.05) }.to raise_error(Timeout::Error, /timed out/)
  end
end
