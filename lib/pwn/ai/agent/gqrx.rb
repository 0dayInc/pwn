# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze signal data captured by a software-defined-radio using GQRX. It uses the PWN::AI::Introspection.reflect_on method to analyze the signal data and provide insights based on the location where the data was captured. The agent can determine if the frequency is licensed or unlicensed based on FCC records and provide relevant information about the transmission. This module is useful for security professionals, researchers, and hobbyists interested in analyzing radio signals and understanding their context.
      module GQRX
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::GQRX.analyze(
        #   request: 'required - A string containing the signal data captured by GQRX that you want to analyze. This data should be in a format that can be interpreted by the AI for analysis, such as raw signal data, frequency information, or any relevant metadata associated with the capture.',
        #   location: 'required - A string containing a city, state, country, or GPS coordinates where the signal data was captured. This information will be used to provide context for the analysis and to determine if the frequency is licensed or unlicensed based on FCC records.'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          location = opts[:location]
          raise 'ERROR: location parameter is required' if location.nil? || location.empty?

          system_role_content = "Analyze signal data captured by a software-defined-radio using GQRX at the following location: #{location}. Respond with just FCC information about the transmission if available.  If the frequency is unlicensed or not found in FCC records, state that clearly.  Be clear and concise in your analysis."

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
            ai_analysis = PWN::AI::Agent::GQRX.analyze(
              request: 'required - A string containing the signal data captured by GQRX that you want to analyze. This data should be in a format that can be interpreted by the AI for analysis, such as raw signal data, frequency information, or any relevant metadata associated with the capture.',
              location: 'required - A string containing a city, state, country, or GPS coordinates where the signal data was captured. This information will be used to provide context for the analysis and to determine if the frequency is licensed or unlicensed based on FCC records.'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
