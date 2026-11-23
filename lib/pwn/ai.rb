# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads AI modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module AI
    autoload :Agent, 'pwn/ai/agent'
    autoload :CLI, 'pwn/ai/cli'
    autoload :Context, 'pwn/ai/context'
    autoload :Anthropic, 'pwn/ai/anthropic'
    autoload :Gemini, 'pwn/ai/gemini'
    autoload :Grok, 'pwn/ai/grok'
    autoload :HttpRetry, 'pwn/ai/http_retry'
    autoload :MCP, 'pwn/ai/mcp'
    autoload :ModelCatalog, 'pwn/ai/model_catalog'
    autoload :Ollama, 'pwn/ai/ollama'
    autoload :OpenAI, 'pwn/ai/open_ai'
    autoload :OpenWebUI, 'pwn/ai/open_web_ui'
    autoload :RedTeam, 'pwn/ai/red_team'
    autoload :Router, 'pwn/ai/router'
    autoload :ServerTools, 'pwn/ai/server_tools'

    # Ollama and Open WebUI share a wire format. A binary-tagged non-ASCII reply
    # that previously failed framing may be recovered for display, not replayed.
    class StreamPreview
      attr_reader :body

      def initialize(body:, provider:)
        @provider = provider
        @required = body.encoding == Encoding::BINARY && !body.ascii_only?
        @body = required? ? body.dup.force_encoding(Encoding::UTF_8) : body
        raise "ERROR: #{@provider} response contains invalid UTF-8" if required? && !@body.valid_encoding?
      end

      def required?
        @required
      end

      # Only choice 0 is displayed. Another choice cannot finish its text.
      # Never return actions, arguments or reasoning, even without a console.
      def display!(payloads:, sse:, done: false)
        text = +''
        role = 'assistant'
        pending = false
        finish_reason = nil
        payloads.each do |payload|
          choices = sse ? Array(payload[:choices]) : [{ message: payload[:message], finish_reason: payload[:done_reason] }]
          choices.each_with_index do |choice, index|
            msg = choice[:delta] || choice[:message] || {}
            pending ||= %w[tool_calls function_call].include?(choice[:finish_reason]) || !Array(msg[:tool_calls]).empty? || !msg[:function_call].nil?
            next unless 0.eql?(choice.fetch(:index, index))

            finish_reason = choice[:finish_reason]
            role = msg[:role] || role
            text << msg[:content] if role == 'assistant' && msg[:content].is_a?(String)
          end
        end
        choice_finished = finish_reason.is_a?(String) && !finish_reason.empty?
        raise "ERROR: #{@provider} incomplete SSE preview: missing finish reason for choice 0" if sse && !done && !choice_finished

        Thread.current[:pwn_stream_preview]&.call(@provider, text, pending)
        raise "#{@provider} reply is display-only; no actions from this reply were submitted."
      end
    end
    private_constant :StreamPreview

    # Display a List of Every PWN::AI Module

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Display a List of Every PWN::AI Module
        #{self}.authors
      "
      constants.sort
    end
  end
end
