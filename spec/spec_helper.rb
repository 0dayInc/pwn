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
