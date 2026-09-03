# frozen_string_literal: true

require 'json'
require 'fileutils'

module PWN
  module Plugins
    # Operator-approved capability elevation (never auto-sudo).
    module Capability
      public_class_method def self.request(opts = {})
        cap = (opts[:cap] || opts[:capability]).to_s.downcase
        raise 'ERROR: cap is required' if cap.empty?

        reason = opts[:reason].to_s
        grantable = Array(grantable_caps).map(&:to_s)
        return { ok: false, cap: cap, error: 'not grantable', grantable: grantable } unless grantable.include?(cap)

        unless opts[:operator_ack] == true
          return {
            ok: false,
            cap: cap,
            needs_ack: true,
            prompt: "Approve setcap #{cap} on the pwn helper? Pass operator_ack: true. Reason: #{reason}"
          }
        end

        { ok: true, cap: cap, applied: false, note: 'operator acknowledged; apply setcap on the ruby helper out of band', reason: reason }
      end

      public_class_method def self.grantable_caps(opts = {})
        listed = Array(opts[:grantable])
        return listed.map(&:to_s) unless listed.empty?
        return %w[cap_net_raw] unless defined?(PWN::Env)

        got = Array(PWN::Env.dig(:ai, :capabilities, :grantable)).map(&:to_s)
        got.empty? ? %w[cap_net_raw] : got
      rescue StandardError
        %w[cap_net_raw]
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Request a grantable capability; never sudo without operator_ack.
          #{self}.request(
            cap: 'required - capability name (e.g. cap_net_raw)',
            capability: 'optional - alias for cap',
            reason: 'optional - why the lane needs it',
            operator_ack: 'optional - true only after the operator approved'
          )

          # List capabilities pwn.yaml allows granting.
          #{self}.grantable_caps(
            unused: 'optional - reserved',
            grantable: 'optional - Array of capability names to return instead of pwn.yaml'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
