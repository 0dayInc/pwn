# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'

module PWN
  # PWN::Memory provides persistent cross-session memory for the pwn-ai agent.
  # Facts, user preferences,
  # environment details, lessons learned, and task state are stored in
  # ~/.pwn/memory.json and survive across REPL restarts / pwn-ai sessions.
  #
  # The pwn-ai agent (in agent mode) automatically receives relevant memory
  # injected into its system prompt. The agent can also call remember/recall
  # via ruby code blocks during execution loops.
  module Memory
    MEMORY_FILE = File.join(Dir.home, '.pwn', 'memory.json')

    # Supported Method Parameters::
    #   memory = PWN::Memory.load
    public_class_method def self.load
      FileUtils.mkdir_p(File.dirname(MEMORY_FILE))
      return {} unless File.exist?(MEMORY_FILE)

      JSON.parse(File.read(MEMORY_FILE), symbolize_names: true)
    rescue StandardError
      {}
    end

    # Supported Method Parameters::
    #   PWN::Memory.save(mem: memory_hash)
    public_class_method def self.save(opts = {})
      mem = opts[:mem] ||= {}
      FileUtils.mkdir_p(File.dirname(MEMORY_FILE))
      File.write(MEMORY_FILE, JSON.pretty_generate(mem))
      mem
    end

    # Supported Method Parameters::
    #   PWN::Memory.remember(
    #     key: 'required - Symbol or String key for the memory fact',
    #     value: 'required - The value (any JSON serializable)',
    #     category: 'optional - e.g. :fact, :preference, :lesson, :env (default: :fact)'
    #   )
    public_class_method def self.remember(opts = {})
      key = opts[:key]
      value = opts[:value]
      category = opts[:category] || :fact

      raise 'ERROR: key and value are required' if key.nil? || value.nil?

      mem = load
      mem[key.to_sym] = {
        value: value,
        category: category.to_sym,
        timestamp: Time.now.utc.iso8601,
        source: 'pwn-ai'
      }
      save(mem: mem)
      mem[key.to_sym]
    end

    # Supported Method Parameters::
    #   results = PWN::Memory.recall(
    #     query: 'optional - string to search keys/values/categories (simple match)',
    #     category: 'optional - filter by category',
    #     limit: 'optional - max results (default 50)'
    #   )
    public_class_method def self.recall(opts = {})
      query = opts[:query].to_s.downcase
      category = opts[:category]
      limit = opts[:limit] || 50

      mem = load
      results = mem.select do |k, v|
        match = true
        match &&= k.to_s.downcase.include?(query) || v[:value].to_s.downcase.include?(query) || v[:category].to_s.downcase.include?(query) if query && !query.empty?
        match &&= (v[:category] == category.to_sym) if category
        match
      end

      results.to_a.first(limit).to_h
    end

    # Supported Method Parameters::
    #   hits = PWN::Memory.recall_semantic(query: 'nmap sweep', limit: 6)
    #
    # Relevance-ranked recall via PWN::MemoryIndex (local Ollama embeddings
    # + cosine over ~/.pwn/memory.idx). Falls back to substring .recall
    # when no embedding backend is configured.
    public_class_method def self.recall_semantic(opts = {})
      return recall(query: opts[:query], limit: opts[:limit]) unless defined?(PWN::MemoryIndex) && PWN::MemoryIndex.available?

      PWN::MemoryIndex.recall_semantic(query: opts[:query], limit: opts[:limit])
    rescue StandardError
      recall(query: opts[:query], limit: opts[:limit])
    end

    # Supported Method Parameters::
    #   PWN::Memory.forget(key: :some_key)
    public_class_method def self.forget(opts = {}) # rubocop:disable Naming/PredicateMethod
      key = opts[:key]
      mem = load
      mem.delete(key.to_sym)
      save(mem: mem)
      true
    end

    # Supported Method Parameters::
    #   PWN::Memory.clear
    public_class_method def self.clear
      FileUtils.rm_f(MEMORY_FILE)
      {}
    end

    # Supported Method Parameters::
    #   context = PWN::Memory.to_context(limit: 20)
    #   (used internally by pwn-ai hook to inject into system prompt)
    public_class_method def self.to_context(opts = {})
      limit = opts[:limit] || 20
      mem = recall(limit: limit)
      return '' if mem.empty?

      ctx = "\n\nPERSISTENT MEMORY (cross-session facts, prefs, lessons - use PWN::Memory.remember to store new ones):\n"
      mem.each do |k, v|
        ctx += "- #{k} [#{v[:category]} @ #{v[:timestamp]}]: #{v[:value].to_s[0, 300]}\n"
      end
      ctx
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module
    public_class_method def self.help
      puts <<~USAGE
        USAGE:
          mem = PWN::Memory.load
          PWN::Memory.remember(key: :user_prefers_ruby, value: 'Always prefer pure Ruby + RestClient patterns', category: :preference)
          facts = PWN::Memory.recall(query: 'recon', category: :fact, limit: 10)
          hits  = PWN::Memory.recall_semantic(query: 'recon', limit: 6)  # embedding-ranked
          PWN::Memory.forget(key: :some_key)
          PWN::Memory.clear
          context_str = PWN::Memory.to_context

          #{self}.authors
      USAGE
    end
  end
end
