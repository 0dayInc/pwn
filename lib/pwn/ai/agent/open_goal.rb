# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'

module PWN
  module AI
    module Agent
      # One unfinished host-work request, persisted so the next pwn-ai
      # activation can continue instead of starting a fresh essay.
      module OpenGoal
        GOAL_FILE = File.join(Dir.home, '.pwn', 'open_goal.json')
        CONTINUE_RX = /\A\s*(continue|resume|keep going|pick up|carry on)(?:\s+(?:please|the\s+)?(?:goal|task|work))?\s*[.!]?\s*\z/i

        public_class_method def self.goal_file
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

        public_class_method def self.begin!(opts = {})
          request = opts[:request].to_s.strip
          return if request.empty?

          FileUtils.mkdir_p(File.dirname(goal_file))
          row = {
            request: request,
            session_id: opts[:session_id].to_s,
            updated_at: Time.now.utc.iso8601
          }
          File.write(goal_file, "#{JSON.pretty_generate(row)}\n")
          row
        end

        public_class_method def self.clear!(opts = {})
          return :ok unless opts.is_a?(Hash)
          return :ok unless File.file?(goal_file)

          File.delete(goal_file)
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
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::OpenGoal.begin!(request: '...', session_id: '...')
              PWN::AI::Agent::OpenGoal.current
              PWN::AI::Agent::OpenGoal.resume?(request: 'continue')
              PWN::AI::Agent::OpenGoal.clear!

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
