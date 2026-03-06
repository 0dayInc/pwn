# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze various aspects of HackerOne bug bounty programs, including bounty program details, scope details, and hacktivity details. It provides insights and recommendations based on the provided data to help security researchers optimize their efforts on the platform.
      module HackerOne
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::HackerOne.analyze(
        #   request: 'required - dataset to analyze, such as bounty program details, scope details, or hacktivity details'
        #   type: 'required - type of analysis to perform, such as :bounty_programs, :scope_details, or :hacktivity'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          type = opts[:type]
          raise 'ERROR: type parameter is required' if type.nil? || type.empty?

          case type.to_s.downcase.to_sym
          when :bounty_programs
            system_role_content = 'Suggest an optimal bug bounty program to target on HackerOne to maximize potential earnings based on values within `min_payout` and publicly known vulnerabilities that have surfaced for the `name` of the program.'
          when :scope_details
            system_role_content = 'Analyze the scope details for the given bug bounty program on HackerOne. Identify key areas of interest, potential vulnerabilities, and any patterns that could inform a targeted security assessment based on the provided scope information.'
          when :hacktivity
            system_role_content = 'Analyze the hacktivity details for the given bug bounty program on HackerOne. Identify significant disclosed reports, common vulnerability types, and any trends that could inform future security assessments based on the provided hacktivity information.'
          else
            raise "ERROR: type parameter value of #{type} is not supported"
          end

          PWN::AI::Introspection.reflect_on(
            system_role_content: system_role_content,
            request: request,
            spinner: true,
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
            ai_analysis = PWN::AI::Agent::HackerOne.analyze(
              request: 'required - dataset to analyze, such as bounty program details, scope details, or hacktivity details'
              type: 'required - type of analysis to perform, such as :bounty_programs, :scope_details, or :hacktivity'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
