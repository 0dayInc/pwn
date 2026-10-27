# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'tmpdir'

RSpec.describe 'build gate diagnostics' do
  it 'reports the RSpec child signal rather than only a generic command failure' do
    Dir.mktmpdir('pwn-rake-signal-') do |home|
      spec = File.join(home, 'terminated_spec.rb')
      File.write(spec, "RSpec.describe('fixture') { it('terminates') { Process.kill('KILL', Process.pid) } }\n")
      output, status = Open3.capture2e({ 'HOME' => home, 'SPEC' => spec, 'SPEC_OPTS' => nil }, 'bundle', 'exec', 'rake', 'spec')
      expect(status.success?).to be(false)
      expect(output).to match(/RSpec child failed: (signal=KILL|exit=137)/)
    end
  end

  it 'retains the first failure details even if a later example terminates RSpec' do
    Dir.mktmpdir('pwn-rake-failure-') do |home|
      spec = File.join(home, 'terminated_spec.rb')
      File.write(spec, "RSpec.describe('fixture') { it('fails first') { expect(1).to eq(2) }; it('terminates') { Process.kill('KILL', Process.pid) } }\n")
      output, status = Open3.capture2e({ 'HOME' => home, 'SPEC' => spec, 'SPEC_OPTS' => nil }, 'bundle', 'exec', 'rake', 'spec')
      expect(status.success?).to be(false)
      expect(output).to include('fixture fails first', 'expected: 2', 'got: 1')
    end
  end

  it 'keeps a bounded log and preserves successful exit after large output' do
    Dir.mktmpdir('pwn-build-bound-') do |home|
      script = File.expand_path('../../scripts/build_gate.rb', __dir__)
      output, status = Open3.capture2e({ 'HOME' => home }, RbConfig.ruby, script, RbConfig.ruby, '-e', 'puts "x" * 2_000_000; puts "finished fixture"')
      expect(status.success?).to be(true)
      expect(output).to include('finished fixture')
      log = File.join(home, '.pwn', 'logs', 'build-gate.log')
      expect(File.size(log)).to be <= 1_048_576
      expect(File.read(log)).to include('finished fixture', 'exit=0')
    end
  end

  it 'records a directly signalled gate without inventing a summary' do
    Dir.mktmpdir('pwn-build-signal-') do |home|
      script = File.expand_path('../../scripts/build_gate.rb', __dir__)
      output, status = Open3.capture2e({ 'HOME' => home }, RbConfig.ruby, script, RbConfig.ruby, '-e', 'Process.kill("TERM", Process.pid)')
      expect(status.exitstatus).to eq(143)
      expect(output).to include('signal=TERM')
      expect(File.read(File.join(home, '.pwn', 'logs', 'build-gate.log'))).to include('signal=TERM')
    end
  end

  it 'finishes recording when both terminal streams disconnect' do
    Dir.mktmpdir('pwn-build-disconnect-') do |home|
      script = File.expand_path('../../scripts/build_gate.rb', __dir__)
      reader, writer = IO.pipe
      reader.close
      pid = Process.spawn({ 'HOME' => home }, RbConfig.ruby, script, RbConfig.ruby, '-e', 'warn "Failures: disconnected fixture"; exit 23', out: writer, err: writer)
      writer.close
      expect(Process.wait2(pid).last.exitstatus).to eq(23)
      expect(File.read(File.join(home, '.pwn', 'logs', 'build-gate.log'))).to include('Failures: disconnected fixture', 'exit=23')
    end
  end

  it 'preserves merged failure output and the gate exit status outside the terminal stream' do
    Dir.mktmpdir('pwn-build-gate-') do |home|
      script = File.expand_path('../../scripts/build_gate.rb', __dir__)
      output, status = Open3.capture2e({ 'HOME' => home }, RbConfig.ruby, script, RbConfig.ruby, '-e', '$stdout.sync = true; puts "F.F"; warn "Failures: fixture assertion"; exit 23')
      expect(status.exitstatus).to eq(23)
      expect(output).to include('Failures: fixture assertion', 'exit=23', 'Build gate log:')
      log = File.join(home, '.pwn', 'logs', 'build-gate.log')
      expect(File.read(log)).to include('F.F', 'Failures: fixture assertion', 'exit=23')
      expect(File.stat(log).mode & 0o777).to eq(0o600)
    end
  end
end
