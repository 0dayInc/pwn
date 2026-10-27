# frozen_string_literal: true

require 'rspec/core/formatters/base_formatter'

# The normal final summary is still printed. Emit failures immediately too,
# so a later killed example cannot erase the only actionable diagnostic.
class GateFailureFormatter < RSpec::Core::Formatters::BaseFormatter
  RSpec::Core::Formatters.register self, :example_failed

  def example_failed(notification)
    output.puts notification.fully_formatted(1)
    output.flush
  end
end
