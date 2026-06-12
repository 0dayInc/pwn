# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'securerandom'

module PWN
  # PWN::Sessions provides session management for pwn-ai (and other drivers)
  # — list, resume, transcripts, and stats.
  # Sessions are stored as JSONL transcripts in ~/.pwn/sessions/ for durability
  # and easy search/append. pwn-ai agent mode auto-creates and appends to a
  # session on each activation.
  module Sessions
    SESSIONS_DIR = File.join(Dir.home, '.pwn', 'sessions')

    # Supported Method Parameters::
    #   dir = PWN::Sessions.sessions_dir
    public_class_method def self.sessions_dir
      FileUtils.mkdir_p(SESSIONS_DIR)
      SESSIONS_DIR
    end

    # Supported Method Parameters::
    #   sessions = PWN::Sessions.list
    public_class_method def self.list
      dir = sessions_dir
      Dir.glob(File.join(dir, '*.jsonl')).reverse.map do |f|
        {
          id: File.basename(f, '.jsonl'),
          path: f,
          size: File.size(f),
          mtime: File.mtime(f).utc.iso8601,
          lines: File.readlines(f).count
        }
      end
    end

    # Supported Method Parameters::
    #   session = PWN::Sessions.create(
    #     title: 'optional - human title',
    #     source: 'optional - e.g. pwn-ai-repl'
    #   )
    public_class_method def self.create(opts = {})
      dir = sessions_dir
      ts = Time.now.utc.strftime('%Y%m%d_%H%M%S')
      rand = SecureRandom.hex(4)
      id = "#{ts}_#{rand}"
      path = File.join(dir, "#{id}.jsonl")

      meta = {
        id: id,
        title: opts[:title] || "pwn-ai session #{id}",
        source: opts[:source] || 'pwn-ai',
        created_at: Time.now.utc.iso8601
      }

      File.open(path, 'w') do |f|
        f.puts(JSON.dump(role: 'system', content: "Session started: #{meta[:title]}", timestamp: meta[:created_at]))
      end
      { id: id, path: path, meta: meta }
    end

    # Supported Method Parameters::
    #   PWN::Sessions.append(
    #     session_id: 'required',
    #     role: 'user|assistant|system|observation',
    #     content: 'the message or obs'
    #   )
    public_class_method def self.append(opts = {})
      sid = opts[:session_id]
      raise 'ERROR: session_id required' unless sid

      path = File.join(sessions_dir, "#{sid}.jsonl")
      raise "Session #{sid} not found" unless File.exist?(path)

      entry = {
        role: opts[:role] || 'user',
        content: opts[:content],
        timestamp: Time.now.utc.iso8601
      }
      File.open(path, 'a') { |f| f.puts(JSON.dump(entry)) }
      entry
    end

    # Supported Method Parameters::
    #   transcript = PWN::Sessions.load(session_id: 'required')
    public_class_method def self.load(opts = {})
      sid = opts[:session_id]
      path = File.join(sessions_dir, "#{sid}.jsonl")
      return [] unless File.exist?(path)

      File.readlines(path).map { |l| JSON.parse(l, symbolize_names: true) }
    end

    # Supported Method Parameters::
    #   history_for_ai = PWN::Sessions.to_response_history(session_id:)
    #   (converts transcript to the response_history format used by PWN::AI::* .chat)
    public_class_method def self.to_response_history(opts = {})
      transcript = load(session_id: opts[:session_id])
      choices = transcript.map do |e|
        {
          role: e[:role],
          content: e[:content]
        }
      end

      {
        id: opts[:session_id],
        object: 'session.transcript',
        model: 'pwn-ai',
        usage: {},
        choices: choices
      }
    end

    # Supported Method Parameters::
    #   PWN::Sessions.delete(session_id:)
    public_class_method def self.delete(opts = {}) # rubocop:disable Naming/PredicateMethod
      sid = opts[:session_id]
      path = File.join(sessions_dir, "#{sid}.jsonl")
      FileUtils.rm_f(path)
      true
    end

    # Supported Method Parameters::
    #   stats = PWN::Sessions.stats
    public_class_method def self.stats
      sessions = list
      {
        total_sessions: sessions.size,
        total_lines: sessions.sum { |s| s[:lines] },
        oldest: sessions.last ? sessions.last[:mtime] : nil,
        newest: sessions.first ? sessions.first[:mtime] : nil
      }
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module
    public_class_method def self.help
      puts <<~USAGE
        USAGE:
          sess = PWN::Sessions.create(title: 'recon on target.com')
          PWN::Sessions.append(session_id: sess[:id], role: 'user', content: 'Run NmapIt...')
          transcript = PWN::Sessions.load(session_id: sess[:id])
          hist = PWN::Sessions.to_response_history(session_id: sess[:id])
          PWN::Sessions.list
          PWN::Sessions.stats
          PWN::Sessions.delete(session_id: sess[:id])

          #{self}.authors
      USAGE
    end
  end
end
