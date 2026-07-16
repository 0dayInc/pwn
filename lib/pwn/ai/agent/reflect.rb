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
      #
      # TEACHER-STUDENT REFLECTION
      # --------------------------
      # When PWN::Env[:ai][:reflect_engine] (or opts[:engine]) names a
      # different provider than :active, Reflect.on temporarily flips
      # :active for the duration of the introspection call. This lets a
      # local Ollama model EXECUTE the task while a frontier model WRITES
      # the durable lessons about it — the local model then reads back
      # distilled reasoning it could never have produced itself.
      module Reflect
        # Supported Method Parameters::
        # response = PWN::AI::Agent::Reflect.on(
        #   request: 'required - String - What you want the AI to reflect on',
        #   system_role_content: 'optional - context to set up the model behavior for reflection',
        #   engine: 'optional - override engine for THIS reflection only (Symbol/String); defaults to PWN::Env[:ai][:reflect_engine] || :active',
        #   model: 'optional - override model on the reflection engine for THIS call only; defaults to PWN::Env[:ai][:reflect_model]',
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
            override = opts[:engine] || PWN::Env.dig(:ai, :reflect_engine)
            model    = opts[:model]  || PWN::Env.dig(:ai, :reflect_model)
            engine   = (override || PWN::Env[:ai][:active]).to_s.downcase.to_sym
            valid_ai_engines = PWN::AI.help.reject { |e| e.downcase == :agent }.map(&:downcase)
            raise "ERROR: Unsupported AI engine. Supported engines are: #{valid_ai_engines}" unless valid_ai_engines.include?(engine)

            warn "AI Reflection is enabled.  Ensure #{engine} has been authorized for use and/or requests are sanitized properly." unless suppress_pii_warning
            response = with_engine(engine: override, model: model) do
              PWN::AI::Agent::Loop.run(
                request: request.chomp,
                system_role_content: system_role_content,
                enabled_toolsets: [],
                spinner: spinner
              )
            end
          end

          response
        rescue StandardError => e
          raise e
        end

        # Temporarily override PWN::Env[:ai][:active] so Loop.run routes to
        # the teacher engine, restoring afterwards even on raise. No-op when
        # engine is nil/blank or PWN::Env[:ai] is frozen.
        private_class_method def self.with_engine(opts = {})
          engine = opts[:engine].to_s
          model  = opts[:model].to_s
          ai = defined?(PWN::Env) && PWN::Env.is_a?(Hash) ? PWN::Env[:ai] : nil
          return yield if (engine.empty? && model.empty?) || !ai.is_a?(Hash) || ai.frozen?

          eff_engine = engine.empty? ? ai[:active].to_s : engine
          eng_key    = eff_engine.downcase.to_sym
          eng_env    = ai[eng_key].is_a?(Hash) ? ai[eng_key] : nil

          prev_active = ai[:active]
          prev_model  = eng_env ? eng_env[:model] : nil

          ai[:active]      = engine unless engine.empty?
          eng_env[:model]  = model  if eng_env && !eng_env.frozen? && !model.empty?
          begin
            yield
          ensure
            ai[:active]     = prev_active
            eng_env[:model] = prev_model if eng_env && !eng_env.frozen? && !model.empty?
          end
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
              engine: 'optional - override engine (Symbol) for teacher-student reflection; defaults to PWN::Env[:ai][:reflect_engine]',
              spinner: 'optional - Boolean - Display spinner during operation (default: false)',
              suppress_pii_warning: 'optional - Boolean - Suppress PII Warnings (default: false)'
            )

            Teacher-student config:
              PWN::Env[:ai][:reflect_engine] = :anthropic   # execute on :active, critique on :anthropic

            #{self}.authors
          "
        end
      end
    end
  end
end
