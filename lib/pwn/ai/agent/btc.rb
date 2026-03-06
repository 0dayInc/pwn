# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze Bitcoin blockchain information. It provides insights and summaries based on the latest block data retrieved from a Bitcoin node using `PWN::Blockchain::BTC.get_latest_block`.
      module BTC
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::BTC.analyze(
        #   request: 'required - latest block information retrieved from a bitcoin node via `PWN::Blockchain::BTC.get_latest_block`'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          system_role_content = 'Provide a useful summary of this latest bitcoin block returned from a bitcoin node via getblockchaininfo.'

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
            ai_analysis = PWN::AI::Agent::BTC.analyze(
              request: 'required - latest block information retrieved from a bitcoin node via `PWN::Blockchain::BTC.get_latest_block`'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
