# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads AI modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module AI
    autoload :Agent, 'pwn/ai/agent'
    autoload :Anthropic, 'pwn/ai/anthropic'
    autoload :Gemini, 'pwn/ai/gemini'
    autoload :Grok, 'pwn/ai/grok'
    autoload :Ollama, 'pwn/ai/ollama'
    autoload :OpenAI, 'pwn/ai/open_ai'
    autoload :RedTeam, 'pwn/ai/red_team'

    # Display a List of Every PWN::AI Module

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      constants.sort
    end
  end
end
