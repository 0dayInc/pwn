# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'digest'
require 'securerandom'

module PWN
  module AI
    module Agent
      # One unfinished host-work request, persisted so the next pwn-ai
      # activation can continue instead of starting a fresh essay.
      module OpenGoal
        GOAL_FILE = File.join(Dir.home, '.pwn', 'open_goal.json')
        CONTINUE_RX = /\A\s*(continue|resume|keep going|pick up|carry on)(?:\s+(?:please|the\s+)?(?:goal|task|work))?\s*[.!]?\s*\z/i

        public_class_method def self.goal_file
          runtime = Thread.current[:pwn_request_runtime]
          return File.join(File.dirname(GOAL_FILE), 'open_goals', Digest::SHA256.hexdigest(runtime.session_id), "#{Digest::SHA256.hexdigest(runtime.request_id)}.json") if runtime

          GOAL_FILE
        end

        public_class_method def self.current
          path = goal_file
          return unless File.file?(path)

          row = JSON.parse(File.read(path), symbolize_names: true)
          return if row[:request].to_s.strip.empty?

          row
        rescue StandardError
          nil
        end

        public_class_method def self.for_session(opts = {})
          sid = opts[:session_id].to_s
          pointer = File.join(File.dirname(GOAL_FILE), 'open_goals', Digest::SHA256.hexdigest(sid), 'current.json')
          path = File.file?(pointer) ? pointer : GOAL_FILE
          return unless File.file?(path)

          row = JSON.parse(File.read(path), symbolize_names: true)
          row if row[:session_id] == sid && !row[:request].to_s.empty?
        end

        public_class_method def self.begin!(opts = {})
          request = opts[:request].to_s.strip
          return if request.empty?

          FileUtils.mkdir_p(File.dirname(goal_file))
          row = {
            request: request,
            session_id: opts[:session_id].to_s,
            mission_id: opts[:mission_id].to_s,
            updated_at: Time.now.utc.iso8601
          }
          runtime = Thread.current[:pwn_request_runtime]
          row.merge!(request_id: runtime.request_id, checkpoint_path: runtime.checkpoint_path) if runtime
          path = goal_file
          if opts[:answered_id]
            waiting = pending_reply(opts)
            return :held unless waiting

            row = waiting.merge(updated_at: row[:updated_at], reply_after: Digest::SHA256.hexdigest(request))
            path = File.join(File.dirname(path), "#{Digest::SHA256.hexdigest(waiting.fetch(:request_id))}.json")
          end
          row.merge!(reply_question: opts[:reply_question], reply_medium: opts[:reply_medium]) if runtime && opts[:reply_medium]
          atomic_write(path: path, row: row)
          atomic_write(path: File.join(File.dirname(path), 'current.json'), row: row) if runtime
          row
        end

        public_class_method def self.clear!(opts = {})
          return :ok unless opts.is_a?(Hash)

          path = goal_file
          id = Thread.current[:pwn_request_runtime]&.request_id
          if (answered = opts[:answered_id])
            return :held unless pending_reply(opts)

            id = answered
            path = File.join(File.dirname(path), "#{Digest::SHA256.hexdigest(id)}.json")
          end
          return :ok unless File.file?(path)
          return :held if mission_open?

          File.delete(path)
          pointer = File.join(File.dirname(path), 'current.json')
          if Thread.current[:pwn_request_runtime] && File.file?(pointer)
            row = JSON.parse(File.read(pointer), symbolize_names: true)
            File.delete(pointer) if row[:request_id] == id
          end
          :ok
        rescue StandardError
          :ok
        end

        public_class_method def self.resume?(opts = {})
          req = opts[:request].to_s
          return false if current.nil?

          req.match?(CONTINUE_RX)
        rescue StandardError
          false
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Run goal file and return its result
            #{self}.goal_file

            # Run current and return its result
            #{self}.current

            # Look up only the named session's resumable request.
            #{self}.for_session(
              session_id: 'required - exact session identity; no cross-session fallback'
            )

            # Run begin and return its result
            #{self}.begin!(
              request: 'required - request value consumed by #begin!',
              session_id: 'optional - session id value consumed by #begin!',
              mission_id: 'optional - durable mission id consumed by #begin!',
              answered_id: 'optional - retain this immediately preceding conversational goal when another input is needed',
              reply_question: 'optional - digest of a saved question awaiting operator input',
              reply_medium: 'optional - text or information delivery for that pending answer'
            )

            # Close only the owning request or its immediately answered conversational question.
            #{self}.clear!(answered_id: 'optional - exact pending conversational request id in the current session')

            # Run resume and return its result
            #{self}.resume?(
              request: 'optional - request value consumed by #resume?'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.pending_reply(opts = {})
          runtime = Thread.current[:pwn_request_runtime]
          row = for_session(session_id: runtime.session_id) if runtime
          row if row && row[:request_id] == opts[:answered_id] && row[:reply_question] && row[:mission_id].to_s.empty?
        end

        private_class_method def self.atomic_write(opts = {})
          path = opts[:path]
          FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
          temp = "#{path}.#{SecureRandom.hex(8)}.tmp"
          File.open(temp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            file.write(JSON.generate(opts[:row]))
            file.flush
            file.fsync
          end
          File.rename(temp, path)
        ensure
          File.unlink(temp) if temp && File.exist?(temp)
        end

        private_class_method def self.mission_open?(opts = {})
          return false unless defined?(PWN::AI::Agent::Mission)

          mid = (opts[:mission_id] || (current && current[:mission_id])).to_s
          return false if mid.empty?

          !PWN::AI::Agent::Mission.done?(id: mid)
        rescue StandardError
          false
        end
      end
    end
  end
end
