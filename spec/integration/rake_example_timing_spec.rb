# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'open3'

RSpec.describe 'rake spec timing output' do
  it 'prints one timed stdout row per selected example and keeps failure diagnostics' do
    Dir.mktmpdir('pwn-rake-timing') do |dir|
      file = File.join(dir, 'timing_spec.rb')
      report = File.join(dir, 'results.json')
      File.write(file, <<~RUBY)
        require 'spec_helper'
        RSpec.configure { |c| c.add_formatter('json', ENV.fetch('TIMING_REPORT')) }
        RSpec.describe 'formatter fixture' do
          it 'passes', :measured do
            sleep 0.01
            STDOUT.puts 'fixture output must stay hidden'
          end
          it('fails', :measured) { raise 'timing fixture failure' }
          it('is pending', :measured)
          it('is filtered out') { raise 'unexpected execution' }
        end
      RUBY
      env = {
        'SPEC' => file, 'PWN_SPEC_VERBOSE' => nil, 'TIMING_REPORT' => report,
        'SPEC_OPTS' => '--tag measured --order defined'
      }
      stdout, stderr, status = Open3.capture3(env, RbConfig.ruby, Gem.bin_path('rake', 'rake'), 'spec', chdir: File.expand_path('../..', __dir__))
      expect(status.exitstatus).to eq(1), stderr
      results = JSON.parse(File.read(report)).fetch('examples')
      expect(results.map { |ex| ex.fetch('status') }).to eq(%w[passed failed pending])
      expect(results.first.fetch('run_time')).to be >= 0.01
      rows = results.map.with_index(1) do |ex, n|
        format("[#{n}/3] #{file}:#{ex.fetch('line_number')} %<seconds>.6fs", seconds: ex.fetch('run_time'))
      end
      expect(stdout.lines.map(&:chomp).grep(%r{^\[\d+/})).to eq(rows)
      expect(stdout).not_to include('fixture output must stay hidden')
      expect(stdout).not_to match(/^[.F*]+$/)
      expect(stdout.index('timing fixture failure')).to be < stdout.index(rows.last)
      expect(stdout).to include('3 examples, 1 failure, 1 pending')
    end
  end
end

RSpec.describe GateFailureFormatter do
  it 'colors only the duration on a terminal, using the unrounded runtime for both thresholds' do
    stream = StringIO.new
    allow(stream).to receive(:tty?).and_return(true)
    allow(RSpec.configuration).to receive(:color_mode).and_return(:automatic)
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('NO_COLOR').and_return(nil)
    formatter = described_class.new(stream)
    cases = [[0.9999999, 32], [1.0, 33], [5.0, 33], [10.0, 33], [10.0000001, 31]]
    formatter.start(RSpec::Core::Notifications::StartNotification.new(cases.size, 0))
    expected = cases.map.with_index(1) do |(seconds, code), n|
      result = instance_double(RSpec::Core::Example::ExecutionResult, run_time: seconds)
      example = instance_double(RSpec::Core::Example, metadata: { absolute_file_path: __FILE__, line_number: n }, execution_result: result)
      formatter.example_finished(RSpec::Core::Notifications::ExampleNotification.new(example))
      format("[#{n}/#{cases.size}] #{__FILE__}:#{n} \e[#{code}m%<seconds>.6fs\e[0m", seconds: seconds)
    end
    expect(stream.string.lines.map(&:chomp)).to eq(expected)
  end
end
