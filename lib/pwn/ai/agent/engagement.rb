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
          name = validate_name(name: opts[:name] || opts[:engagement] || 'default')

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
          name = opts[:name] || opts[:engagement] || current_name
          return { active: nil } if name.nil?

          name = validate_name(name: name)
          path = File.join(ROOT, "#{name}.json")
          return { active: name, missing: true } unless File.file?(path)

          JSON.parse(File.read(path), symbolize_names: true).merge(active: name)
        end

        public_class_method def self.current_name(opts = {})
          return nil unless opts.is_a?(Hash)
          return nil unless File.file?(ACTIVE_FILE)

          validate_name(name: File.read(ACTIVE_FILE))
        end

        public_class_method def self.validate_name(opts = {})
          name = opts[:name].to_s
          raise ArgumentError, 'Invalid engagement name: expected a single nonempty filename component' if name.empty? || %w[. ..].include?(name) || name.match?(%r{[/\\\x00-\x1f\x7f]})
          raise ArgumentError, 'Invalid engagement name: active pointer and .json metadata names are reserved' if name == File.basename(ACTIVE_FILE) || name.downcase.end_with?('.json')

          name
        end

        public_class_method def self.in_scope?(opts = {})
          token = (opts[:host] || opts[:ip] || opts[:target] || opts[:url]).to_s
          return true if token.empty?

          roe = load_roe
          host = scope_host(target: token)
          if roe[:present]
            deny = Array(roe[:targets_deny])
            return false if deny.any? { |ex| scope_match?(host: host, target: ex, deny: true) }

            allow = Array(roe[:targets_allow])
            return false unless allow.empty? || allow.any? { |target| scope_match?(host: host, target: target) }
          end

          row = status(name: opts[:name] || opts[:engagement])
          return true if row[:active].nil?
          return false if row[:missing]

          enforce = engagement_enforce
          return true if enforce == 'off'

          return false if Array(row[:excluded]).any? { |ex| scope_match?(host: host, target: ex, deny: true) }

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
          roe = load_roe
          tech_hit = Array(roe[:techniques_deny]).find { |t| blob.downcase.include?(t.to_s.downcase) }
          if tech_hit
            return {
              success: false,
              error: "roe_deny: technique #{tech_hit}",
              code: 'ROE_DENY',
              violating: [tech_hit]
            }
          end
          tokens = scope_targets(value: args)
          bad = tokens.reject { |tok| in_scope?(host: tok) }
          return nil if bad.empty?

          {
            success: false,
            error: "out_of_scope: #{bad.first}",
            code: 'SCOPE_DENY',
            violating: bad
          }
        end

        public_class_method def self.load_roe(opts = {})
          path = (opts[:path] || File.join(Dir.home, '.pwn', 'roe.yaml')).to_s
          return { present: false, targets_allow: [], targets_deny: [], techniques_deny: [] } unless File.file?(path)

          require 'yaml'
          raw = YAML.safe_load_file(path, permitted_classes: [], symbolize_names: true)
          raw = {} if raw.nil?
          raise ArgumentError, 'Invalid RoE policy: expected a YAML mapping' unless raw.is_a?(Hash)

          {
            present: true,
            targets_allow: Array(raw[:targets_allow] || raw['targets_allow']),
            targets_deny: Array(raw[:targets_deny] || raw['targets_deny']),
            techniques_deny: Array(raw[:techniques_deny] || raw['techniques_deny']),
            time_windows: raw[:time_windows] || raw['time_windows']
          }
        rescue Psych::Exception, SystemCallError, IOError
          raise ArgumentError, 'Invalid RoE policy: cannot read or parse the policy file'
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
              name: 'optional - engagement name (defaults to active)',
              engagement: 'optional - alias for name'
            )

            # Return the active engagement name or nil.
            #{self}.current_name(
              unused: 'optional - reserved'
            )

            # Validate an engagement filename component without normalizing it.
            #{self}.validate_name(
              name: 'required - nonempty engagement name without separators or control characters; active and .json suffixes are reserved'
            )

            # True when host/ip/url is inside the active engagement scope.
            #{self}.in_scope?(
              host: 'optional - DNS hostname to test against scope_domains',
              ip: 'optional - IPv4 or IPv6 address to test against scope_cidrs',
              target: 'optional - host or IP alias when the caller has one field',
              url: 'optional - URL whose host is extracted and tested',
              name: 'optional - explicit engagement name; otherwise use the active engagement',
              engagement: 'optional - alias for name'
            )

            # Structured denial when args mention an out-of-scope host.
            #{self}.deny_if_out_of_scope(
              args: 'optional - Hash of tool args',
              command: 'optional - command string',
              text: 'optional - free-form blob to scan'
            )

            # Load the RoE policy file when present for allow and deny lists.
            #{self}.load_roe(
              path: 'optional - filesystem path of roe.yaml (defaults to ~/.pwn/roe.yaml)'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end

        private_class_method def self.scope_match?(opts = {})
          target = opts[:target].to_s
          host = opts[:host].to_s
          begin
            network = IPAddr.new(target)
          rescue IPAddr::InvalidAddressError
            raise ArgumentError, 'Invalid scope network' if target.include?('/')

            return host == target || host.end_with?(".#{target}") || (opts[:deny] == true && host.include?(target))
          end
          begin
            network.include?(IPAddr.new(host))
          rescue IPAddr::InvalidAddressError
            false
          end
        end

        # Read typed target fields first; scan code/commands without treating URL
        # paths as extra destinations. IPAddr validates candidates, never resolves DNS.
        private_class_method def self.scope_targets(opts = {})
          value = opts[:value]
          case value
          when Hash
            value.flat_map { |key, item| scope_targets(value: item, typed: key.to_s.match?(/\A(?:hosts?|ips?|targets?|urls?|hostname|address)\z/)) }.uniq
          when Array
            value.flat_map { |item| scope_targets(value: item, typed: opts[:typed]) }.uniq
          when String
            return [scope_host(target: value)] if opts[:typed] && !value.match?(/\s/)

            tokens = []
            rest = value.gsub(%r{[a-z][a-z0-9+.-]*://[^\s"'<>]+}i) do |url|
              tokens << scope_host(target: url)
              ' '
            end
            rest = rest.gsub(/(?<![\w:])[\da-f]*:[\da-f:.]+(?:%[\w.-]+)?/i) do |candidate|
              address = IPAddr.new(candidate)
              tokens << candidate if address.ipv6?
              ' '
            rescue IPAddr::InvalidAddressError
              candidate
            end
            (tokens + rest.scan(/(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}/)).reject(&:empty?).uniq
          else
            []
          end
        end

        private_class_method def self.scope_host(opts = {})
          token = opts[:target].to_s
          return URI.parse(token).hostname.to_s if token.include?('://')

          host = token.split('/').first.to_s
          return host[/\A\[([^\]]+)\]/, 1] if host.start_with?('[')

          host.count(':') <= 1 ? host.split(':').first.to_s : host
        rescue URI::InvalidURIError
          token
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
