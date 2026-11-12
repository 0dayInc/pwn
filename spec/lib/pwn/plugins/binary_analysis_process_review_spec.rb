# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'shellwords'

RSpec.describe PWN::Plugins::BinaryAnalysis, 'subprocess ownership' do
  it '[PBR-02] kills a same-group child after the leader exits without touching another group' do
    Dir.mktmpdir('binary-owner-') do |dir|
      # The separate test process adopts/reaps its own orphan, never global suite children.
      probe = <<~'RUBY'
        require 'ffi'
        require 'json'
        require 'shellwords'
        require 'pwn/plugins/binary_analysis'
        native = Module.new do
          extend FFI::Library
          ffi_lib FFI::Library::LIBC
          attach_function :prctl, [:int, :ulong, :ulong, :ulong, :ulong], :int
        end
        abort 'subreaper setup failed' unless native.prctl(36, 1, 0, 0, 0).zero?
        unrelated = Process.spawn('/bin/sleep', '10', pgroup: true)
        at_exit do
          Process.kill('KILL', unrelated)
          Process.waitpid(unrelated)
          Process.waitpid(-1) while true
        rescue Errno::ECHILD
          nil
        end
        marker, pidfile = ARGV
        command = "(/bin/sleep 1; printf late > #{Shellwords.escape(marker)}) & printf '%s' $! > #{Shellwords.escape(pidfile)}; exit 7"
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          PWN::Plugins::BinaryAnalysis.run(argv: ['/bin/sh', '-c', command], timeout: 0.3)
          error = nil
        rescue StandardError => e
          error = e.class.name
        end
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        _, status = Process.wait2(Integer(File.read(pidfile)))
        puts JSON.generate(error: error, signal: status.termsig, elapsed: elapsed, late: File.exist?(marker), unrelated: Process.kill(0, unrelated))

      RUBY
      out, err, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../../../../lib', __dir__), '-e', probe, File.join(dir, 'late'), File.join(dir, 'pid'))
      expect(status.success?).to be(true), err
      row = JSON.parse(out)
      expect(row).to include('error' => 'Timeout::Error', 'signal' => 9, 'late' => false, 'unrelated' => 1)
      expect(row['elapsed']).to be_between(0.25, 0.9)
    end
  end

  it 'preserves successful output, failed status and output-limit errors' do
    expect(described_class.run(argv: ['/bin/sh', '-c', 'printf success'], timeout: 1)).to eq('success')
    expect { described_class.run(argv: ['/bin/sh', '-c', 'printf failure; exit 7'], timeout: 1) }.to raise_error(RuntimeError, /backend exited 7: failure/)
    expect { described_class.run(argv: ['/bin/sh', '-c', 'printf excessive; sleep 1'], limit: 3, timeout: 1) }.to raise_error(RuntimeError, /output limit/)
  end
end
