# frozen_string_literal: true

require 'pwn'
require 'stringio'

# Harness preloads are subprocess-only; runners are explicitly required by integration specs.
Dir[File.join(__dir__, 'support', '**', '*.rb')].reject { |f| f.include?('/support/harness/') }.each { |f| require f }

# ─────────────────────────────────────────────────────────────────────────────
#  Keep `rake` output clean.
#
#  RSpec binds its formatter to $stdout at configure-time (before any example
#  runs), so redirecting $stdout / $stderr *inside* each example swallows any
#  incidental `puts` / `print` / `p` / `warn` emitted by the code under test
#  WITHOUT affecting the progress dots or failure reports.
#
#  Escape hatches:
#    - `PWN_SPEC_VERBOSE=1 rake spec`               → no redirection at all
#    - `it '...', :stdout do ... end`               → per-example opt-out
# ─────────────────────────────────────────────────────────────────────────────
RSpec.configure do |config|
  config.filter_run_excluding :harness_live unless ENV['PWN_TEST_HARNESS_LIVE'] == '1'
  config.filter_run_excluding :local_embeddings unless ENV['PWN_TEST_EMBED_ENDPOINT'] && ENV['PWN_SQLITE_VEC_EXTENSION']
  config.filter_run_excluding :proxmark3_integration unless ENV['PWN_TEST_PROXMARK3'] == '1'
  config.filter_run_excluding :rtl433_integration unless ENV['PWN_TEST_RTL433'] == '1'
  config.filter_run_excluding :liquid_integration unless ENV['PWN_TEST_LIQUID'] == '1'
  config.filter_run_excluding :radare2_integration unless ENV['PWN_TEST_RADARE2'] == '1'
  config.filter_run_excluding :gdb_integration unless ENV['PWN_TEST_GDB'] == '1'
  config.filter_run_excluding :keystone_integration unless ENV['PWN_TEST_KEYSTONE'] == '1'
  config.filter_run_excluding :capstone_integration unless ENV['PWN_TEST_CAPSTONE'] == '1'
  %w[fftw volk rtl_sdr adalm_pluto soapy_sdr hack_rf].each do |backend|
    config.filter_run_excluding :"#{backend}_integration" unless ENV["PWN_TEST_#{backend.upcase}"] == '1'
  end
  config.filter_run_excluding :rtl_sdr_hardware unless ENV['PWN_TEST_RTL_SDR_HARDWARE'] == '1'
  config.filter_run_excluding :combo_nation_mcp unless ENV['PWN_TEST_COMBO_NATION_MCP'] == '1'
  config.filter_run_excluding :x86_64_binary unless RbConfig::CONFIG['host_cpu'].to_s.match?(/amd64|x86_64/)

  config.before(:each) do
    @pwn_spec_backup_root = Dir.mktmpdir('pwn-backup-spec-')
    Thread.current[:pwn_backup_real_home] = Dir.home
    Thread.current[:pwn_backup_root] = @pwn_spec_backup_root
  end

  config.after(:each) do
    root = @pwn_spec_backup_root
    Thread.current[:pwn_backup_root] = nil
    Thread.current[:pwn_backup_real_home] = nil
    @pwn_spec_backup_root = nil
    # FileUtils.remove_entry calls Dir.children, which examples stub with a fixed path.
    system('rm', '-rf', '--', root) if root.is_a?(String) && root.start_with?('/') && root.include?('/pwn-backup-spec-') && !root.include?('..')
  end

  if ENV['PWN_RAKE_SPEC'] == '1'
    module SilenceRakeFilterBanner
      def report_filter_message(message)
        return if message.to_s.start_with?('Run options:')

        super
      end
    end
    RSpec::Core::World.prepend(SilenceRakeFilterBanner)
  end

  next if ENV['PWN_SPEC_VERBOSE']

  original_stdout = $stdout
  original_stderr = $stderr
  devnull = StringIO.new

  if ENV['PWN_RAKE_SPEC'] == '1'
    config.before(:suite) do
      next if defined?(PWN_RAKE_STDOUT_SILENCED)

      reporter = RSpec.configuration.reporter
      listeners = reporter.instance_variable_get(:@listeners).values.flat_map(&:to_a).uniq
      terminal = nil
      silenced = []
      listeners.each do |listener|
        next unless listener.instance_variable_defined?(:@output)

        wrapped = listener.instance_variable_get(:@output)
        stream = wrapped.is_a?(RSpec::Core::OutputWrapper) ? wrapped.output : wrapped
        next unless stream.respond_to?(:reopen) && stream.respond_to?(:fileno) && stream.fileno == 1
        next if silenced.include?(stream)

        terminal ||= stream.dup.tap { |io| io.sync = true }
        if wrapped.is_a?(RSpec::Core::OutputWrapper)
          wrapped.output = terminal
        else
          listener.instance_variable_set(:@output, terminal)
        end
        stream.reopen(File::NULL)
        stream.sync = true
        silenced << stream
      end
      Object.const_set(:PWN_RAKE_STDOUT_SILENCED, true)
    end
  end

  config.before(:each) do |example|
    next if example.metadata[:stdout] && ENV['PWN_RAKE_SPEC'] != '1'

    devnull.truncate(0)
    devnull.rewind
    $stdout = devnull
    $stderr = devnull
  end

  config.after(:each) do
    $stdout = original_stdout
    $stderr = original_stderr
  end
end

# During rake, PWNLogger writes nothing and STDOUT itself is /dev/null.
# Direct rspec still redirects $stdout per example. PWN_SPEC_VERBOSE=1
# leaves both attached. Point any other captured logger at /dev/null.
PWN::AI::RedTeam::TestCaseEngine.class_variable_set(:@@logger, Logger.new(File::NULL)) if defined?(PWN::AI::RedTeam::TestCaseEngine)
