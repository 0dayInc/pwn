# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::BareSIP do
  around do |example|
    Dir.mktmpdir('baresip-review-') do |root|
      @root = root
      File.write(File.join(root, 'config'), "http_listen 127.0.0.1:1\n")
      @log = File.join(root, 'screenlog.txt')
      example.run
    end
  end

  before do
    allow(PWN::Plugins::Sock).to receive(:get_random_unused_port).and_return(12_345)
    allow(described_class).to receive(:system).and_return(true)
  end

  it 'stops the launched session if closing its readiness log prevents handoff' do
    log_handle = nil
    allow(File).to receive(:open).and_call_original
    allow(File).to receive(:open).with(@log, File::RDWR | File::CREAT, 0o600).and_wrap_original do |original, *args|
      log_handle = original.call(*args)
      allow(log_handle).to receive(:close).and_wrap_original do |close|
        close.call
        raise IOError, 'log close failure'
      end
      log_handle
    end
    allow(described_class).to receive(:system) do |*args|
      File.open(@log, 'a') { |file| file.puts('registered successfully') } if args.include?('-Logfile')
      true
    end
    expect { described_class.start(config_root: @root, session_root: @root, screenlog_path: @log, screen_session: 'fixture-owned') }.to raise_error(IOError, 'log close failure')
    expect(log_handle).to be_closed
    expect(described_class).to have_received(:system).with('screen', '-S', 'fixture-owned', '-X', 'quit').once
  end

  [Interrupt, IOError].each do |error|
    it "preserves real startup #{error} and removes the exact owned config without HTTP teardown" do
      copied = nil
      allow(FileUtils).to receive(:cp_r).and_wrap_original do |original, source, destination|
        copied = destination
        original.call(source, destination)
      end
      allow(File).to receive(:stat).and_call_original
      allow(File).to receive(:stat).with(/screenlog-.*\.txt/).and_raise(error, 'primary startup failure')
      expect(described_class).not_to receive(:baresip_http_call)
      expect do
        described_class.dial_target_in_list(config_root: @root, session_root: @root, target_num: '2025550100', src_num_rules: 'static')
      end.to raise_error(error, 'primary startup failure')
      expect(copied).not_to be_nil
      expect(Dir.exist?(copied)).to be(false)
      expect(File.exist?(File.join(@root, 'config'))).to be(true)
    end
  end

  it 'surfaces cleanup-only stop failure even inside an unrelated caller rescue' do
    allow(described_class).to receive(:system) do |*args|
      File.open(args[args.index('-Logfile') + 1], 'a') { |file| file.puts('registered successfully') } if args.include?('-Logfile')
      true
    end
    allow(described_class).to receive(:sleep)
    allow(described_class).to receive(:baresip_http_call) do |options|
      raise IOError, 'stop failure' if options[:cmd].start_with?('/quit')

      Nokogiri::HTML('<pre>synthetic</pre>')
    end
    begin
      raise 'unrelated caller error'
    rescue RuntimeError
      expect do
        described_class.dial_target_in_list(config_root: @root, session_root: @root, target_num: '2025550100', src_num_rules: 'static', seconds_to_record: 1)
      end.to raise_error(IOError, 'stop failure')
    end
  end

  it 'removes the owned config even when HTTP stop fails after successful startup' do
    copied = nil
    allow(FileUtils).to receive(:cp_r).and_wrap_original do |original, source, destination|
      copied = destination
      original.call(source, destination)
    end
    allow(described_class).to receive(:system) do |*args|
      File.open(args[args.index('-Logfile') + 1], 'a') { |file| file.puts('registered successfully') } if args.include?('-Logfile')
      true
    end
    calls = []
    allow(described_class).to receive(:baresip_http_call) do |options|
      calls << options[:cmd]
      raise IOError, calls.length == 1 ? 'primary dial failure' : 'secondary stop failure'
    end
    expect do
      described_class.dial_target_in_list(config_root: @root, session_root: @root, target_num: '2025550100', src_num_rules: 'static')
    end.to raise_error(IOError, 'primary dial failure')
    expect(calls.length).to eq(2)
    expect(Dir.exist?(copied)).to be(false)
  end

  ['registered successfully', '403 Forbidden', 'account: No SIP accounts found'].each do |stale|
    it "ignores historical #{stale} without fresh session bytes" do
      File.write(@log, "#{stale}\n")
      expect { described_class.start(config_root: @root, session_root: @root, screenlog_path: @log, timeout: 0.05) }.to raise_error(Timeout::Error)
    end
  end

  it 'recognizes fresh readiness after historical errors in an explicit log' do
    File.write(@log, "403 Forbidden\n")
    allow(described_class).to receive(:system) do |*args|
      File.open(@log, 'a') { |file| file.puts('registered successfully') } if args.include?('-Logfile')
      true
    end
    result = described_class.start(config_root: @root, session_root: @root, screenlog_path: @log, timeout: 0.1)
    expect(result[:screenlog_path]).to eq(@log)
  end

  it 'does not let historical success override a fresh failure' do
    File.write(@log, "registered successfully\n")
    allow(described_class).to receive(:system) do |*args|
      File.open(@log, 'a') { |file| file.puts('403 Forbidden') } if args.include?('-Logfile')
      true
    end
    expect { described_class.start(config_root: @root, session_root: @root, screenlog_path: @log, timeout: 0.1) }.to raise_error(/403 Forbidden/)
  end
end
