# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

describe PWN::Plugins::Log do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Log
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Log
    expect(help_response).to respond_to :help
  end

  describe 'pwn-ai debug session' do
    after do
      PWN::Plugins::Log.stop_debug if PWN::Plugins::Log.respond_to?(:stop_debug)
    end

    it 'starts a /tmp/pwn-ai-DEBUG-TIMESTAMP.log and tees progress to TUI + file' do
      expect(PWN::Plugins::Log).to respond_to(:start_debug)
      expect(PWN::Plugins::Log).to respond_to(:stop_debug)
      expect(PWN::Plugins::Log).to respond_to(:progress)
      expect(PWN::Plugins::Log).to respond_to(:debug_enabled?)
      expect(PWN::Plugins::Log).to respond_to(:debug_log_path)

      tee = StringIO.new
      path = PWN::Plugins::Log.start_debug(tee: tee, path: nil)
      expect(path).to match(%r{\A/tmp/pwn-ai-DEBUG-.+\.log\z})
      expect(File.file?(path)).to eq(true)
      expect(PWN::Plugins::Log.debug_enabled?).to eq(true)
      expect(PWN::Plugins::Log.debug_log_path).to eq(path)

      ok = PWN::Plugins::Log.progress(msg: 'Loop.run start request=hi', which_self: PWN::AI::Agent::Loop)
      expect(ok).to eq(true)
      body = File.read(path)
      expect(body).to include('Loop.run start request=hi')
      expect(body).to include('PWN::AI::Agent::Loop')
      expect(tee.string).to include('Loop.run start request=hi')

      PWN::Plugins::Log.stop_debug
      expect(PWN::Plugins::Log.debug_enabled?).to eq(false)
      expect(PWN::Plugins::Log.progress(msg: 'after stop', which_self: self)).to eq(false)
    end

    it 'quiet_tui keeps writing the file but stops teeing to the TUI' do
      expect(PWN::Plugins::Log).to respond_to(:quiet_tui!)
      expect(PWN::Plugins::Log).to respond_to(:loud_tui!)
      tee = StringIO.new
      path = PWN::Plugins::Log.start_debug(tee: tee, path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-quiet.log")
      PWN::Plugins::Log.progress(msg: 'before-quiet', which_self: PWN::AI::Agent::Loop)
      PWN::Plugins::Log.quiet_tui!
      PWN::Plugins::Log.progress(msg: 'after-quiet', which_self: PWN::AI::Agent::Loop)
      expect(tee.string).to include('before-quiet')
      expect(tee.string).not_to include('after-quiet')
      expect(File.read(path)).to include('after-quiet')
      PWN::Plugins::Log.loud_tui!
      PWN::Plugins::Log.progress(msg: 'after-loud', which_self: PWN::AI::Agent::Loop)
      expect(tee.string).to include('after-loud')
    end

    it 'rolls the debug log to .N+1 when the file exceeds 1MB' do
      stem = "/tmp/pwn-ai-DEBUG-#{Process.pid}-roll"
      first = "#{stem}.1.log"
      File.write(first, 'x' * (1_024_000 + 10))
      path = PWN::Plugins::Log.start_debug(tee: StringIO.new, path: first)
      expect(path).to eq(first)
      PWN::Plugins::Log.progress(msg: 'overflow-line', which_self: PWN::AI::Agent::Loop)
      second = "#{stem}.2.log"
      expect(PWN::Plugins::Log.debug_log_path).to eq(second)
      expect(File.file?(second)).to eq(true)
      expect(File.read(second)).to include('overflow-line')
    end

    it 'traces PWN module calls into the same debug log while the session is on' do
      path = PWN::Plugins::Log.start_debug(tee: StringIO.new, path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-#{Time.now.to_i}.log")
      PWN::AI::Agent::OpenGoal.current if defined?(PWN::AI::Agent::OpenGoal)
      body = File.read(path)
      expect(body).to match(/PWN::AI::Agent::OpenGoal/)
    end

    it 'does not raise when a traced module #name is a Symbol' do
      probe = Module.new do
        def self.name
          :symname
        end

        def self.ping
          :ok
        end
      end
      stub_const('PWN::AI::Agent::SymNameProbe', probe)
      PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-sym.log"
      )
      expect { PWN::AI::Agent::SymNameProbe.ping }.not_to raise_error
    end

    it 'logs the complete traced call including parameters' do
      probe = Module.new do
        def self.echo(opts = {})
          opts[:msg]
        end
      end
      stub_const('PWN::AI::Agent::ArgProbe', probe)
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-args.log"
      )
      PWN::AI::Agent::ArgProbe.echo(
        msg: 'hello-browser',
        url: 'https://example.test/open',
        password: 's3cret-token'
      )
      body = File.read(path)
      expect(body).to include('PWN::AI::Agent::ArgProbe.echo')
      expect(body).to include('hello-browser')
      expect(body).to include('https://example.test/open')
      expect(body).not_to include('s3cret-token')
      expect(body).to match(/\[REDACTED\]/)
    end

    it 'redacts secret-shaped values even when the key is not a password name' do
      probe = Module.new do
        def self.echo(opts = {})
          opts[:msg]
        end
      end
      stub_const('PWN::AI::Agent::ArgProbe', probe)
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-redact.log"
      )
      PWN::AI::Agent::ArgProbe.echo(
        header: 'Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb',
        blob: "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
        note: 'xai-abcdefghijklmnopqrstuvwxyz0123456789ABCD'
      )
      PWN::Plugins::Log.progress(
        msg: 'Loop.run start request=use key sk-live-SUPERSECRET999',
        which_self: PWN::AI::Agent::Loop
      )
      body = File.read(path)
      expect(body).not_to include('eyJhbGciOiJIUzI1NiJ9')
      expect(body).not_to include('BEGIN PRIVATE KEY')
      expect(body).not_to include('xai-abcdefghijklmnopqrstuvwxyz0123456789ABCD')
      expect(body).not_to include('sk-live-SUPERSECRET999')
      expect(body).to match(/\[REDACTED\]/)
    end
  end
end
