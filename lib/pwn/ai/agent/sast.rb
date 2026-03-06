# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze SAST antipatterns within source code repositories. It identifies common coding mistakes, security vulnerabilities, and areas for improvement in code quality. The agent generates an EPSS score for each identified issue, indicating the likelihood of exploitation. It provides detailed explanations of the issues found, along with recommendations for remediation and best practices to enhance code security and maintainability.
      module SAST
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::SAST.analyze(
        #   request: 'required - A string containing the source code snippet to be analyzed for SAST antipatterns and vulnerabilities.'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          system_role_content = 'Your sole purpose is to analyze source code snippets and generate an Exploit Prediction Scoring System (EPSS) score between 0% - 100%.  Just generate a score unless score is >= 75% in which a PoC and code fix should also be included.'

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
            ai_analysis = PWN::AI::Agent::SAST.analyze(
              request: 'required - A string containing the source code snippet to be analyzed for SAST antipatterns and vulnerabilities.'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
