# frozen_string_literal: true

require 'json'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Reflect is the inward-facing counterpart to
      # PWN::AI::Agent::Extrospection. Where Extrospection looks OUTWARD at
      # the world the agent operates in (host state, toolchain, network,
      # threat-intel), Reflect looks INWARD - it lets pwn hand a request to
      # the active AI engine and reflect on its own artifacts, transcripts,
      # findings, code, or decisions.
      #
      # This module is gated by `PWN::Env[:ai][:module_reflection]` so that
      # potentially-sensitive local data is never shipped to a remote LLM
      # unless the operator has explicitly opted in via pwn-vault / config.
      #
      # It is the single choke-point every PWN::AI::Agent::* domain agent
      # (Assembly, BurpSuite, GQRX, HackerOne, SAST, VulnGen, ...) routes
      # through when it wants an LLM opinion on locally-produced data, and
      # it is also what PWN::AI::Agent::Learning.reflect uses to distill
      # session transcripts into durable PWN::Memory lessons.
      module Reflect
        # Supported Method Parameters::
        # response = PWN::AI::Agent::Reflect.on(
        #   request: 'required - String - What you want the AI to reflect on',
        #   system_role_content: 'optional - context to set up the model behavior for reflection',
        #   spinner: 'optional - Boolean - Display spinner during operation (default: false)',
        #   suppress_pii_warning: 'optional - Boolean - Suppress PII Warnings (default: false)'
        # )

        public_class_method def self.on(opts = {})
          request = opts[:request]
          raise 'ERROR: request must be provided' if request.nil?

          system_role_content = opts[:system_role_content]

          spinner = opts[:spinner] || false

          suppress_pii_warning = opts[:suppress_pii_warning] || false

          response = nil

          ai_module_reflection = PWN::Env[:ai][:module_reflection]

          if ai_module_reflection && request.length.positive?
            engine = PWN::Env[:ai][:active].to_s.downcase.to_sym
            valid_ai_engines = PWN::AI.help.reject { |e| e.downcase == :agent }.map(&:downcase)
            raise "ERROR: Unsupported AI engine. Supported engines are: #{valid_ai_engines}" unless valid_ai_engines.include?(engine)

            warn "AI Reflection is enabled.  Ensure #{engine} has been authorized for use and/or requests are sanitized properly." unless suppress_pii_warning
            response = PWN::AI::Agent::Loop.run(
              request: request.chomp,
              system_role_content: system_role_content,
              enabled_toolsets: [],
              spinner: spinner
            )
          end

          response
        rescue StandardError => e
          raise e
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
            #{self}.on(
              request: 'required - String - What you want the AI to reflect on',
              system_role_content: 'optional - context to set up the model behavior for reflection',
              spinner: 'optional - Boolean - Display spinner during operation (default: false)',
              suppress_pii_warning: 'optional - Boolean - Suppress PII Warnings (default: false)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
