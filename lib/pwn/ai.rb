# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP plugins
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module AI
    autoload :Grok, 'pwn/ai/grok'
    autoload :Introspection, 'pwn/ai/introspection'
    autoload :Ollama, 'pwn/ai/ollama'
    autoload :OpenAI, 'pwn/ai/open_ai'

    # Display a List of Every PWN::AI Module

    public_class_method def self.help
      constants.sort
    end
  end
end
