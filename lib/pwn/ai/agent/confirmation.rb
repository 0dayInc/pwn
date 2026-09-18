# frozen_string_literal: true

require 'json'
require 'yaml'
require 'fileutils'
require 'time'

module PWN
  module AI
    module Agent
      # Per-engagement ACK for exploit/destructive tool calls (PWN-AI-005 tiers).
      module Confirmation
        TIERS = %w[read_only active_scan exploit destructive].freeze
        DEFAULTS = { 'read_only' => 'auto', 'active_scan' => 'auto', 'exploit' => 'prompt', 'destructive' => 'prompt' }.freeze
        AUTONOMOUS = { 'read_only' => 'auto', 'active_scan' => 'auto', 'exploit' => 'auto', 'destructive' => 'auto' }.freeze

        public_class_method def self.required_bins
          []
        end

        # Classify a tool call into a PWN-AI-005 side-effect tier.
        public_class_method def self.tier(opts = {})
          name = opts[:name].to_s
          args = opts[:args]
          args = {} unless args.is_a?(Hash)
          tagged = (args[:side_effect] || args['side_effect']).to_s
          return tagged if TIERS.include?(tagged)
          return 'exploit' if name.match?(/exploit|gdb_run_to_crash|fuzz_campaign/)
          return 'active_scan' if name.match?(/nmap_scan|nuclei_scan|sbom_scan|http_proxy/)
          return payload_tier(payload: args[:command] || args['command']) if name == 'shell'
          return payload_tier(payload: args[:code] || args['code']) if name == 'pwn_eval'

          'read_only'
        end

        # Return an ACK pause hash, or nil when the call may proceed.
        public_class_method def self.gate(opts = {})
          name = opts[:name].to_s
          args = opts[:args]
          args = {} unless args.is_a?(Hash)
          klass = tier(name: name, args: args)
          policy = load_policy(opts)
          action = (policy[klass] || DEFAULTS[klass] || 'auto').to_s
          return { success: false, error: "confirmation deny for #{klass}", code: 'ACK_DENY', tier: klass } if action == 'deny'
          return nil unless action == 'prompt'

          eng = engagement_id(opts.merge(args: args))
          return nil if acked?(engagement_id: eng)

          if truthy?(value: opts[:operator_ack] || args[:operator_ack] || args['operator_ack'])
            persist_ack(engagement_id: eng)
            return nil
          end
          {
            success: false,
            needs_ack: true,
            code: 'ACK_REQUIRED',
            tier: klass,
            engagement_id: eng,
            diff: intended_diff(name: name, args: args, tier: klass),
            error: "operator ACK required for #{klass}-tier tool call"
          }
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # List host binaries this module expects to be installed.
            #{self}.required_bins

            # Classify a tool call into a PWN-AI-005 side-effect tier.
            #{self}.tier(
              name: 'required - registry tool name',
              args: 'optional - Hash of tool arguments'
            )

            # Return an ACK pause hash, or nil when the call may proceed.
            #{self}.gate(
              name: 'required - registry tool name',
              args: 'optional - Hash of tool arguments',
              engagement_id: 'optional - engagement id used to cache the ACK',
              operator_ack: 'optional - true records a one-time ACK for this engagement',
              scope_path: 'optional - scope.yaml path; defaults to ~/.pwn/scope.yaml'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.payload_tier(opts = {})
          kind = PWN::Plugins::AISandbox.classify(payload: opts[:payload].to_s)
          case kind.to_s
          when 'write' then 'destructive'
          when 'network' then 'active_scan'
          else 'read_only'
          end
        end

        private_class_method def self.engagement_id(opts = {})
          args = opts[:args]
          args = {} unless args.is_a?(Hash)
          value = (opts[:engagement_id] || args[:engagement_id] || args['engagement_id'] || 'default').to_s
          value = 'default' if value.empty?
          raise ArgumentError, 'engagement_id must be a simple identifier' unless value.match?(/\A[a-zA-Z0-9_-]+\z/)

          value
        end

        private_class_method def self.load_policy(opts = {})
          path = opts[:scope_path].to_s
          path = File.join(Dir.home, '.pwn', 'scope.yaml') if path.empty?
          return AUTONOMOUS unless File.file?(path)

          doc = YAML.safe_load_file(path, permitted_classes: [], aliases: false) || {}
          return AUTONOMOUS unless doc.is_a?(Hash)

          conf = doc['confirmation'] || doc[:confirmation] || {}
          return AUTONOMOUS unless conf.is_a?(Hash) && !conf.empty?

          DEFAULTS.merge(conf.transform_keys(&:to_s))
        rescue StandardError
          AUTONOMOUS
        end

        private_class_method def self.ack_path(opts = {})
          File.join(Dir.home, '.pwn', 'engagements', engagement_id(opts), 'acks.json')
        end

        private_class_method def self.acked?(opts = {})
          path = ack_path(opts)
          return false unless File.file?(path)

          JSON.parse(File.read(path))['ack'] == true
        rescue StandardError
          false
        end

        private_class_method def self.persist_ack(opts = {})
          path = ack_path(opts)
          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, JSON.generate(ack: true, at: Time.now.utc.iso8601))
          File.chmod(0o600, path)
        end

        private_class_method def self.truthy?(opts = {})
          [true, 'true', 1, '1'].include?(opts[:value])
        end

        private_class_method def self.intended_diff(opts = {})
          name = opts[:name]
          tier = opts[:tier]
          args = JSON.generate(opts[:args] || {})
          "+ tool: #{name}\n+ tier: #{tier}\n+ args: #{args}"
        end
      end
    end
  end
end
