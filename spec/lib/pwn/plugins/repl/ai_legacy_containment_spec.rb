# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

describe 'regex-ReAct mission containment' do
  include_context 'pwn tmp sandbox'

  let(:repl) { PWN::Plugins::REPL }
  let(:request) { +'offline legacy request' }
  let(:pry) { double('pry', config: Pry::Config.new, input: double('input', line_buffer: request)) }

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @work = File.join(@tmp, 'work')
    FileUtils.mkdir_p(@work)
    allow(repl).to receive(:ready_tty!)
    allow(PWN::Memory).to receive(:to_context).and_return('')
    PWN::Env[:ai] = { active: :ollama, agent: { native_tools: false }, ollama: { response_history: { id: 'before' } } }
    pry.config.pwn_ai = true
    pry.config.pwn_ai_agent = true
    allow(Pry.config).to receive(:hooks).and_return(Pry::Hooks.new)
    repl.add_hooks
  end

  def submit
    Pry.config.hooks.get_hook(:after_read, :pwn_ai_hook).call(request, pry)
  end

  def namespace_pids(status)
    status.to_s[/^NSpid:[ \t]+([1-9]\d*(?:[ \t]+[1-9]\d*)*)\n/, 1].to_s.split.map(&:to_i)
  end

  def wait_for_descendant_pid(marker)
    observer = namespace_pids(File.read('/proc/self/status'))
    raise 'Cannot identify the test runner PID namespace' unless observer.last == Process.pid

    Timeout.timeout(10) do
      loop do
        if File.file?(marker)
          pids = namespace_pids(File.read(marker))
          return pids.fetch(observer.size - 1) if pids.size > observer.size
        end

        sleep 0.01
      end
    end
  end

  # Pin the live task before interrupting it. A pidfd reports exit even if
  # another process has yet to reap it, and never follows a recycled PID.
  def open_pidfd(pid)
    fd = PWN::AI::Agent::MissionNamespace.native('pidfd_open', [Fiddle::TYPE_INT, Fiddle::TYPE_INT]).call(pid, 0)
    raise SystemCallError.new('pidfd_open for descendant', Fiddle.last_error) if fd.negative?

    IO.new(fd)
  end

  it 'waits for the descendant PID contents rather than an empty readiness file' do
    marker = File.join(@tmp, 'partial-ready')
    File.write(marker, '')
    read_empty = Queue.new
    writer = Thread.new do
      read_empty.pop
      File.write(marker, "NSpid:\t12345\t1\n")
    end
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with('/proc/self/status').and_return("NSpid:\t#{Process.pid}\n")
    allow(File).to receive(:read).with(marker).and_wrap_original do |original, path|
      text = original.call(path)
      read_empty << true if text.empty?
      text
    end
    expect(wait_for_descendant_pid(marker)).to eq(12_345)
  ensure
    writer&.kill&.join
  end

  it 'selects the PID visible to a nested upgrade runner, not the outer procfs PID' do
    marker = File.join(@tmp, 'nested-ready')
    File.write(marker, "NSpid:\t12345\t82\t1\n")
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with('/proc/self/status').and_return("NSpid:\t12000\t#{Process.pid}\n")
    expect(wait_for_descendant_pid(marker)).to eq(82)
  end

  it 'distinguishes a live child from an exited child that has not been reaped' do
    reader, release = IO.pipe
    pid = fork do
      release.close
      reader.read(1)
      exit! 0
    end
    handle = open_pidfd(pid)
    expect(handle.wait_readable(0)).to be_nil
    release.close
    expect(handle.wait_readable(5)).to be_truthy
    expect(Process.kill(0, pid)).to eq(1) # The old probe still sees the zombie.
  ensure
    [release, reader, handle].compact.each { |io| io.close unless io.closed? }
    Process.wait(pid) if pid
  end

  it 'fails closed before calling a provider when mission containment is unavailable' do
    allow(PWN::AI::Sandbox::MissionProcess).to receive(:new).and_raise(PWN::AI::Sandbox::NotStarted, 'enable user/PID namespaces')
    expect(PWN::AI::Ollama).not_to receive(:chat)
    expect { submit }.to output(%r{enable user/PID namespaces.*no uncontained retry}).to_stderr
    expect(request).to eq('nil')
    expect(PWN::Env.dig(:ai, :ollama, :response_history)).to eq(id: 'before')
    expect(repl).to have_received(:ready_tty!)
  end

  it 'does not enter regex fallback after a failed native mission' do
    PWN::Env[:ai][:agent][:native_tools] = true
    allow(repl).to receive(:pwn_ai_run_steerable).and_raise(IOError, 'mission unavailable')
    expect(repl).not_to receive(:pwn_ai_run_legacy)
    expect(PWN::AI::Ollama).not_to receive(:chat)
    expect { submit }.to output(/native agent loop failed/).to_stderr
    expect(request).to eq('nil')
  end

  it 'keeps local skill names and bodies out of the system role sent to the legacy provider' do
    name = 'catalog-fixture-name'
    body = 'Catalog fixture body.'
    stub_const('PWN::Skills', { name => { content: body } })
    base = 'Configured fixture role.'
    PWN::Env[:ai][:ollama][:system_role_content] = base
    expect(PWN::AI::Ollama).to receive(:chat) do |options|
      role = options.fetch(:system_role_content)
      expect(role).to start_with(base)
      expect(role).not_to include(name, body)
      { choices: [{ content: 'Offline fixture reply.' }] }
    end
    repl.pwn_ai_run_legacy_child(request: request, original_request: request, pry: pry)
  end

  it 'does not retry a failed legacy provider in the controller or replace committed history' do
    marker = File.join(@tmp, 'provider-calls')
    allow(PWN::AI::Ollama).to receive(:chat) do
      File.open(marker, 'a') { |file| file.puts(File.read('/proc/self/status')[/^NSpid:.*$/]) }
      raise IOError, 'offline provider failed'
    end
    expect { submit }.to output(/offline provider failed.*no uncontained retry/).to_stderr
    expect(File.readlines(marker).length).to eq(1)
    expect(File.read(marker).split.length).to be > 2
    expect(PWN::Env.dig(:ai, :ollama, :response_history)).to eq(id: 'before')
    expect(request).to eq('nil')
    expect(repl).to have_received(:ready_tty!)
  end

  it 'runs the fake provider and Ruby block in a real mission and returns history to the controller', :requires_landlock do
    marker = File.join(PWN::AI::Sandbox.workspace, 'tool-owner')
    diagnostic = File.join(@tmp, 'provider-observation')
    calls = 0
    allow(PWN::AI::Ollama).to receive(:chat) do |options|
      calls += 1
      File.write(diagnostic, options[:request].to_s) if calls > 1
      text = calls == 1 ? "```ruby\nFile.write(#{marker.inspect}, File.read('/proc/self/status'))\n```" : 'offline complete'
      { id: 'after', choices: [{ content: text }] }
    end
    submit
    expect(File).to exist(marker), File.read(diagnostic)
    expect(File.read(marker)[/^NSpid:.*$/].split.length).to be > 2
    expect(calls).to eq(0)
    expect(PWN::Env.dig(:ai, :ollama, :response_history, :id)).to eq('after')
    expect(request).to eq('nil')
  end

  %w[ruby bash].each do |language|
    it "denies protected source writes through the actual legacy #{language} hook", :requires_landlock do
      source = File.join(@tmp, 'synthetic-source')
      FileUtils.mkdir_p(source)
      target = File.join(source, 'forbidden.txt')
      original = PWN::AI::Sandbox.protected_roots
      allow(PWN::AI::Sandbox).to receive(:protected_roots).and_return([source, *original])
      code = language == 'ruby' ? "File.write(#{target.inspect}, 'forbidden')" : "printf forbidden > #{target.shellescape}"
      calls = 0
      allow(PWN::AI::Ollama).to receive(:chat) do
        calls += 1
        { choices: [{ content: calls == 1 ? "```#{language}\n#{code}\n```" : 'completed' }] }
      end
      submit
      expect(File).not_to exist(target)
      expect(request).to eq('nil')
    end
  end

  it 'cancels regex-ReAct with a real PTY CTRL+C and completes the next submitted mission', :requires_landlock do
    require 'pty'
    script = File.join(@tmp, 'regex_pty.rb')
    File.write(script, <<~'RUBY')
      require 'pwn'
      require 'pry'
      require 'ostruct'
      require 'fileutils'
      $stdout.sync = true
      work = ARGV.fetch(0)
      runtime = File.join(Dir.home, '.pwn', 'workspaces', 'runtime')
      FileUtils.mkdir_p(runtime)
      PWN::Env[:ai] = { active: :ollama, ollama: {} }
      PWN::Memory.define_singleton_method(:to_context) { |*| '' }
      PWN::AI::Ollama.define_singleton_method(:chat) do |opts|
        if opts[:request] == 'second'
          { id: 'second', choices: [{ content: 'SECOND COMPLETE' }] }
        else
          payload = "Process.setsid; File.write(#{File.join(runtime, 'pty-ready').inspect}, File.read('/proc/self/status')); sleep 1; File.write(#{File.join(runtime, 'pty-late').inspect}, 'late'); sleep 30"
          code = "Process.spawn(#{RbConfig.ruby.inspect}, '-e', #{payload.inspect}, out: File::NULL, err: File::NULL); sleep 30"
          { choices: [{ content: "```ruby\n#{code}\n```" }] }
        end
      end
      pi = OpenStruct.new(config: OpenStruct.new(pwn_ai_agent: true))
      begin
        PWN::Plugins::REPL.pwn_ai_run_legacy(request: +'first', original_request: 'first', pry: pi)
      rescue Interrupt
        puts 'CANCELLED READY'
      end
      next_request = $stdin.gets.to_s.strip
      PWN::Plugins::REPL.pwn_ai_run_legacy(request: next_request.dup, original_request: next_request, pry: pi)
      puts "HISTORY #{PWN::Env.dig(:ai, :ollama, :response_history, :id)}"
    RUBY
    output = +''
    reader, writer, pid = PTY.spawn({ 'HOME' => @tmp }, RbConfig.ruby, '-I', File.expand_path('../../../../../lib', __dir__), script, @work)
    drain = Thread.new do
      loop { output << reader.readpartial(4096) }
    rescue EOFError, Errno::EIO
      nil
    end
    marker = File.join(@tmp, '.pwn', 'workspaces', 'runtime', 'pty-ready')
    descendant = open_pidfd(wait_for_descendant_pid(marker))
    expect(descendant.wait_readable(0)).to be_nil, 'descendant exited before PTY CTRL+C'
    writer.write("\x03")
    Timeout.timeout(10) { sleep 0.01 until output.include?('CANCELLED READY') }
    expect(descendant.wait_readable(0)).to be_truthy, 'detached descendant still alive at CANCELLED READY'
    writer.write("second\n")
    Timeout.timeout(10) { Process.wait(pid) }
    pid = nil
    drain.join(5)
    expect(output).to include('SECOND COMPLETE', 'HISTORY second')
    sleep 1.1
    expect(File).not_to exist(File.join(@tmp, '.pwn', 'workspaces', 'runtime', 'pty-late'))
  ensure
    if pid
      begin
        Process.kill('KILL', pid)
      rescue StandardError
        nil
      end
      begin
        Process.wait(pid)
      rescue StandardError
        nil
      end
    end
    [descendant, reader, writer].compact.each { |io| io.close unless io.closed? }
    drain&.join(5)
  end

  %w[ruby bash].each do |language|
    it "kills a detached #{language} descendant on interrupt before ready, then accepts another request", :requires_landlock do
      marker = File.join(PWN::AI::Sandbox.workspace, 'detached')
      late = File.join(PWN::AI::Sandbox.workspace, 'late')
      payload = "Process.setsid; File.write(#{marker.inspect}, File.read('/proc/self/status')); sleep 1; File.write(#{late.inspect}, 'escaped'); sleep 30"
      ruby_code = "Process.spawn(#{RbConfig.ruby.inspect}, '-e', #{payload.inspect}, out: File::NULL, err: File::NULL); sleep 30"
      code = language == 'ruby' ? ruby_code : [RbConfig.ruby, '-e', ruby_code].shelljoin
      allow(PWN::AI::Ollama).to receive(:chat).and_return(choices: [{ content: "```#{language}\n#{code}\n```" }])
      worker = Thread.new do
        submit
      rescue Interrupt
        :cancelled
      end
      descendant = open_pidfd(wait_for_descendant_pid(marker))
      expect(descendant.wait_readable(0)).to be_nil, 'descendant exited before interrupt'
      worker.raise(Interrupt)
      expect(Timeout.timeout(10) { worker.value }).to eq(:cancelled)
      expect(repl).to have_received(:ready_tty!)
      expect(descendant.wait_readable(0)).to be_truthy, 'detached descendant still alive when the terminal became ready'
      sleep 1.1
      expect(File).not_to exist(late)
      allow(PWN::AI::Ollama).to receive(:chat).and_return(id: 'second', choices: [{ content: 'second complete' }])
      request.replace('second request')
      submit
      expect(PWN::Env.dig(:ai, :ollama, :response_history, :id)).to eq('second')
      expect(request).to eq('nil')
    ensure
      descendant&.close
      worker&.raise(Interrupt) if worker&.alive?
      worker&.join(10)
    end
  end
end
