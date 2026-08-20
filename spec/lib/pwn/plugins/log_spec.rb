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
      expect(PWN::Plugins::Log).to respond_to(:next_request_log!)
      expect(PWN::Plugins::Log).to respond_to(:finish_request_log!)

      tee = StringIO.new
      PWN::Plugins::Log.start_debug(tee: tee, path: nil)
      expect(PWN::Plugins::Log.debug_enabled?).to eq(true)
      path = PWN::Plugins::Log.next_request_log!(session_id: "sess#{Process.pid}")
      expect(path).to eq("/tmp/pwn-ai-DEBUG-sess#{Process.pid}-R1.log")
      expect(File.file?(path)).to eq(true)
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

    it 'tees debug lines with raw ANSI, not PS1 SOH/STX markers' do
      tee = StringIO.new
      PWN::Plugins::Log.start_debug(
        tee: tee,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-ansi.log"
      )
      PWN::Plugins::Log.progress(msg: 'stage-line', which_self: PWN::AI::Agent::Loop)
      shown = tee.string
      expect(shown).to include('stage-line')
      expect(shown).to include("\e[35m")
      expect(shown).not_to include("\001")
      expect(shown).not_to include("\002")
    end

    it 'writes a multiline final body when keep_newlines is set' do
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-finalbody.log"
      )
      PWN::Plugins::Log.progress(
        msg: "final text:\nline-one\nline-two",
        which_self: PWN::AI::Agent::Loop,
        keep_newlines: true,
        cap: 65_536
      )
      body = File.read(path)
      expect(body).to include("final text:\nline-one\nline-two")
    end

    it 'writes a full tool request/result with no char cap when cap is 0' do
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-toolio.log"
      )
      blob = 'x' * 8_000
      PWN::Plugins::Log.progress(
        msg: "tool pwn_eval request:\n#{blob}\nresult:\n#{blob}",
        which_self: PWN::AI::Agent::Loop,
        keep_newlines: true,
        cap: 0,
        tee: nil
      )
      body = File.read(path)
      expect(body).to include('tool pwn_eval request:')
      expect(body).to include(blob)
      expect(body).to include("result:\n#{blob}")
    end

    it 'timestamps an Interrupt line into the open request log' do
      expect(PWN::Plugins::Log).to respond_to(:note_interrupt!)
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-int.log"
      )
      ok = PWN::Plugins::Log.note_interrupt!(where: 'CTRL+C')
      expect(ok).to eq true
      body = File.read(path)
      expect(body).to match(/\[DEBUG \d{4}-\d{2}-\d{2} /)
      expect(body).to include('Interrupt')
      expect(body).to include('CTRL+C')
    end

    it 'still timestamps Interrupt when progress reentrancy is stuck mid-write' do
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-int-stuck.log"
      )
      Thread.current[:pwn_log_progress] = true
      ok = PWN::Plugins::Log.note_interrupt!(where: 'CTRL+C')
      expect(ok).to eq true
      body = File.read(path)
      expect(body).to include('Interrupt')
      expect(body).to include('CTRL+C')
      expect(body).to match(/at=|→ pwn-ai → Interrupt/)
    ensure
      Thread.current[:pwn_log_progress] = false
    end

    it 'timestamps an exception and backtrace into the open request log' do
      expect(PWN::Plugins::Log).to respond_to(:note_exception!)
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-exc.log"
      )
      err = NoMethodError.new("undefined method '+' for nil")
      err.set_backtrace(['/opt/pwn/lib/pwn/ai/grok.rb:470:in grok_rest_call', 'loop.rb:1'])
      ok = PWN::Plugins::Log.note_exception!(error: err, where: 'Loop.run')
      expect(ok).to eq true
      body = File.read(path)
      expect(body).to include('NoMethodError')
      expect(body).to include("undefined method '+' for nil")
      expect(body).to include('grok.rb:470')
      expect(body).to include('Loop.run')
    end

    it 'mirrors TUI tool/task/result rows into the request log without ANSI' do
      expect(PWN::Plugins::Log).to respond_to(:mirror_tui!)
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-tui.log"
      )
      ok = PWN::Plugins::Log.mirror_tui!(
        msg: "\e[33m[ 2026-08-20 11:00:00-0600 → pwn-ai → pwn_eval ]\e[0m\n  {\"code\":\"1+1\"}\n"
      )
      expect(ok).not_to be_nil
      PWN::Plugins::Log.mirror_tui!(msg: "2026-08-20 11:00:01-0600 → result\n  {\"value\":\"2\"}\n")
      PWN::Plugins::Log.mirror_tui!(msg: '[ 2026-08-20 11:00:00-0600 → pwn-ai → task ] navigate')
      body = File.read(path)
      expect(body).to include('[ 2026-08-20 11:00:00-0600 → pwn-ai → pwn_eval ]')
      expect(body).to include('{"code":"1+1"}')
      expect(body).to include('→ result')
      expect(body).to include('→ pwn-ai → task')
      expect(body).not_to include("\e[33m")
      expect(body).not_to include("\e[0m")
    end

    it 'opens one debug log per request: SESSION_ID-R1 then SESSION_ID-R2' do
      tee = StringIO.new
      sid = "abc#{Process.pid}"
      PWN::Plugins::Log.start_debug(tee: tee)
      first = PWN::Plugins::Log.next_request_log!(session_id: sid)
      PWN::Plugins::Log.progress(msg: 'req-one', which_self: PWN::AI::Agent::Loop)
      PWN::Plugins::Log.finish_request_log!(iter: 1, tools_called: 0, engine_s: 0.1, final_chars: 4)
      second = PWN::Plugins::Log.next_request_log!(session_id: sid)
      PWN::Plugins::Log.progress(msg: 'req-two', which_self: PWN::AI::Agent::Loop)
      expect(first).to eq("/tmp/pwn-ai-DEBUG-#{sid}-R1.log")
      expect(second).to eq("/tmp/pwn-ai-DEBUG-#{sid}-R2.log")
      expect(File.read(first)).to include('req-one')
      expect(File.read(first)).to include('footer iter=1')
      expect(File.read(first)).not_to include('req-two')
      expect(File.read(second)).to include('req-two')
      expect(File.read(second)).not_to include('req-one')
    end

    it 'does not roll RN when a request log is already open' do
      tee = StringIO.new
      sid = "nest#{Process.pid}"
      PWN::Plugins::Log.start_debug(tee: tee)
      first = PWN::Plugins::Log.next_request_log!(session_id: sid)
      second = PWN::Plugins::Log.next_request_log!(session_id: sid)
      expect(second).to eq(first)
      expect(second).to eq("/tmp/pwn-ai-DEBUG-#{sid}-R1.log")
    end

    it 'does not TracePoint PWN calls unless trace: true' do
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-notrace.log"
      )
      PWN::AI::Agent::OpenGoal.current if defined?(PWN::AI::Agent::OpenGoal)
      body = File.read(path)
      expect(body).not_to match(/PWN::AI::Agent::OpenGoal\.current/)
    end

    it 'traces PWN module calls into the same debug log when trace: true' do
      path = PWN::Plugins::Log.start_debug(
        tee: StringIO.new,
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-#{Time.now.to_i}.log",
        trace: true
      )
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
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-sym.log",
        trace: true
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
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-args.log",
        trace: true
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
        path: "/tmp/pwn-ai-DEBUG-#{Process.pid}-redact.log",
        trace: true
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
