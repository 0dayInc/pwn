# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze JavaScript code during a Chrome DevTools debugging session. It generates an Exploit Prediction Scoring System (EPSS) score for each step in the JavaScript code and provides proof-of-concept exploits and code fixes if the score is above a certain threshold.
      module TransparentBrowser
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::TransparentBrowser.analyze(
        #   request: 'required - current step in the JavaScript debugging session to analyze',
        #   source_to_review: 'required - the block of JavaScript code in which the current step resides'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          source_to_review = opts[:source_to_review]
          raise 'ERROR: source_to_review parameter is required' if source_to_review.nil? || source_to_review.empty?

          system_role_content = "Being an expert penetration tester skilled in code analysis, debugging, and exploitation while stepping through JavaScript in a Chrome DevTools debugging session:  1. Your sole purpose is to analyze each JavaScript step and generate an Exploit Prediction Scoring System (EPSS) score between 0% - 100%.  The step currently resides in this block of JavaScript:\n```\n#{source_to_review}\n```\n2. If the score is >= 75%, generate a JavaScript proof-of-concept that would allow a threat actor to directly exploit or target a user for exploitation (i.e. no self-exploit).  3. If the EPSS score is >= 75% also provide a code fix. *** If the EPSS score is < 75%, no explanations or summaries - just the EPSS score."

          PWN::AI::Introspection.reflect_on(
            system_role_content: system_role_content,
            request: request,
            suppress_pii_warning: true
          )
        rescue StandardError => e
          raise e.backtrace
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            ai_analysis = PWN::AI::Agent::TransparentBrowser.analyze(
              request: 'required - current step in the JavaScript debugging session to analyze',
              source_to_review: 'required - the block of JavaScript code in which the current step resides'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
