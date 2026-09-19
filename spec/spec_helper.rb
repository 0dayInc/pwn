# frozen_string_literal: true

require 'pwn'
require 'stringio'

Dir[File.join(__dir__, 'support', '**', '*.rb')].each { |f| require f }

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

  next if ENV['PWN_SPEC_VERBOSE']

  original_stdout = $stdout
  original_stderr = $stderr
  devnull = StringIO.new

  config.before(:each) do |example|
    next if example.metadata[:stdout]

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

# Logger.new($stdout) captures the IO at class load — the same stream RSpec
# uses for progress dots. Reassigning $stdout in before(:each) does not
# retarget that logger. Point the red-team engine at /dev/null so execute
# banners cannot leak into rake.
PWN::AI::RedTeam::TestCaseEngine.class_variable_set(:@@logger, Logger.new(File::NULL)) if defined?(PWN::AI::RedTeam::TestCaseEngine)
