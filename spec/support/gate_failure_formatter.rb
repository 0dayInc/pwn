# frozen_string_literal: true

require 'rspec/core/formatters/base_text_formatter'

# Show each example's elapsed time, retaining immediate failures and the normal summary.
class GateFailureFormatter < RSpec::Core::Formatters::BaseTextFormatter
  RSpec::Core::Formatters.register self, :example_finished, :example_failed

  def start(notification)
    super
    @completed = 0
  end

  def example_finished(notification)
    example = notification.example
    @completed += 1
    location = "#{example.metadata.fetch(:absolute_file_path)}:#{example.metadata.fetch(:line_number)}"
    output.puts "[#{@completed}/#{@example_count}] #{location} #{formatted_duration(example.execution_result.run_time)}"
  end

  def example_failed(notification)
    output.puts notification.fully_formatted(1)
    output.flush
  end

  private

  def formatted_duration(seconds)
    text = format('%<seconds>.6fs', seconds: seconds)
    return text unless ENV['NO_COLOR'].to_s.empty? && RSpec.configuration.color_enabled?(output)

    code = case seconds
           when ...1 then 32 # green
           when ..10 then 33 # yellow
           else 31 # red
           end
    "\e[#{code}m#{text}\e[0m"
  end
end
