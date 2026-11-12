# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::PolicyEvaluation, 'temporary directory isolation' do
  it 'uses the configured temporary root before spawning an evaluator' do
    Dir.mktmpdir('pwn-evaluator-tmp-spec-') do |root|
      snapshot = File.join(root, 'snapshot.json')
      File.write(snapshot, JSON.generate(q: {}, h: {}, visits: {}, returns: [], n_updates: 0, td_abs_sum: 0.0))
      expected_parent = Dir.tmpdir
      allow(Dir).to receive(:mktmpdir).and_wrap_original do |original, *args, &block|
        expect(args[1] || Dir.tmpdir).to eq(expected_parent)
        original.call(*args, &block)
      end
      result = described_class.evaluate(baseline: snapshot, candidate: snapshot)
      expect(result[:isolation]).to include(environment_cleared: true, persistence_removed_on_exit: true)
    end
  end

  it 'keeps the fresh worker inner sandbox within its configured temporary root' do
    code = <<~RUBY
      require #{described_class::RUNNER.inspect}
      expected = Dir.tmpdir
      original = Dir.method(:mktmpdir)
      Dir.define_singleton_method(:mktmpdir) do |*args, &block|
        raise 'temporary root ignored' unless (args[1] || Dir.tmpdir) == expected
        original.call(*args, &block)
      end
      PWN::AI::Agent::PolicyEvaluation.send(:with_isolated) { |root| puts root }
    RUBY
    output, error, status = Open3.capture3({ 'HOME' => Dir.home, 'TMPDIR' => Dir.tmpdir, 'LANG' => 'C.UTF-8' }, RbConfig.ruby, '-e', code, unsetenv_others: true)
    expect(status.success?).to be(true), error
    expect(output.strip).to start_with("#{Dir.tmpdir}/")
    expect(File).not_to exist(output.strip)
  end
end
