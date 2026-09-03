# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'ipaddr'
require 'uri'

module PWN
  module AI
    module Agent
      # First-class engagement scope, RoE, and findings pointer.
      module Engagement
        ROOT = File.join(Dir.home, '.pwn', 'engagements')
        ACTIVE_FILE = File.join(ROOT, 'active')

        public_class_method def self.open(opts = {})
          name = (opts[:name] || opts[:engagement] || 'default').to_s
          raise 'ERROR: name is required' if name.empty?

          FileUtils.mkdir_p(ROOT)
          path = File.join(ROOT, "#{name}.json")
          row = File.file?(path) ? JSON.parse(File.read(path), symbolize_names: true) : {}
          row[:name] = name
          row[:scope_cidrs] = Array(opts[:scope_cidrs] || row[:scope_cidrs])
          row[:scope_domains] = Array(opts[:scope_domains] || row[:scope_domains])
          row[:excluded] = Array(opts[:excluded] || row[:excluded])
          row[:roe] = (opts[:roe] || row[:roe]).to_s
          row[:window] = opts[:window] || row[:window]
          row[:findings] ||= []
          File.write(path, JSON.pretty_generate(row))
          File.write(ACTIVE_FILE, name)
          row.merge(path: path, active: true)
        end

        public_class_method def self.close(opts = {})
          FileUtils.rm_f(ACTIVE_FILE) if opts.is_a?(Hash)
          { active: nil }
        end

        public_class_method def self.status(opts = {})
          name = (opts[:name] || current_name).to_s
          return { active: nil } if name.empty?

          path = File.join(ROOT, "#{name}.json")
          return { active: name, missing: true } unless File.file?(path)

          JSON.parse(File.read(path), symbolize_names: true).merge(active: name)
        end

        public_class_method def self.current_name(opts = {})
          return nil unless opts.is_a?(Hash)
          return nil unless File.file?(ACTIVE_FILE)

          File.read(ACTIVE_FILE).strip
        end

        public_class_method def self.in_scope?(opts = {})
          token = (opts[:host] || opts[:ip] || opts[:target] || opts[:url]).to_s
          return true if token.empty?

          row = status
          return true if row[:active].nil? || row[:missing]

          enforce = engagement_enforce
          return true if enforce == 'off'

          host = token
          begin
            host = URI.parse(token).host || token if token.include?('://')
          rescue StandardError
            host = token
          end
          host = host.sub(%r{\Ahttps?://}i, '').split('/').first.to_s.split(':').first
          return false if Array(row[:excluded]).any? { |ex| host.include?(ex.to_s) }

          cidrs = Array(row[:scope_cidrs]).map(&:to_s).reject(&:empty?)
          domains = Array(row[:scope_domains]).map(&:to_s).reject(&:empty?)
          return true if cidrs.empty? && domains.empty?

          ip_ok = begin
            addr = IPAddr.new(host)
            cidrs.any? { |c| IPAddr.new(c).include?(addr) }
          rescue StandardError
            false
          end
          dom_ok = domains.any? { |d| host == d || host.end_with?(".#{d}") }
          ip_ok || dom_ok
        end

        public_class_method def self.deny_if_out_of_scope(opts = {})
          args = opts[:args] || opts[:command] || opts[:text]
          blob = args.is_a?(Hash) ? args.inspect : args.to_s
          tokens = blob.scan(/(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}/).uniq
          bad = tokens.reject { |tok| in_scope?(host: tok) }
          return nil if bad.empty?

          {
            success: false,
            error: "out_of_scope: #{bad.first}",
            code: 'SCOPE_DENY',
            violating: bad
          }
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Open or update an engagement and mark it active.
            #{self}.open(
              name: 'required - engagement name',
              engagement: 'optional - alias for name',
              scope_cidrs: 'optional - Array of CIDR strings',
              scope_domains: 'optional - Array of DNS suffixes',
              excluded: 'optional - Array of excluded hosts',
              roe: 'optional - rules of engagement text',
              window: 'optional - time window string'
            )

            # Clear the active engagement pointer.
            #{self}.close(
              name: 'optional - unused; closing always clears the active pointer'
            )

            # Return the active engagement document.
            #{self}.status(
              name: 'optional - engagement name (defaults to active)'
            )

            # Return the active engagement name or nil.
            #{self}.current_name(
              unused: 'optional - reserved'
            )

            # True when host/ip/url is inside the active engagement scope.
            #{self}.in_scope?(
              host: 'optional - DNS hostname to test against scope_domains',
              ip: 'optional - IPv4 or IPv6 address to test against scope_cidrs',
              target: 'optional - host or IP alias when the caller has one field',
              url: 'optional - URL whose host is extracted and tested'
            )

            # Structured denial when args mention an out-of-scope host.
            #{self}.deny_if_out_of_scope(
              args: 'optional - Hash of tool args',
              command: 'optional - command string',
              text: 'optional - free-form blob to scan'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.engagement_enforce
          v = (PWN::Env.dig(:ai, :engagement, :enforce) if defined?(PWN::Env))
          (v || 'block').to_s
        rescue StandardError
          'block'
        end
      end
    end
  end
end
