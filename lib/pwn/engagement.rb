# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'ipaddr'

module PWN
  # Engagement scope, host state, and vault refs under ~/.pwn/engagements.
  module Engagement
    public_class_method def self.open(opts = {})
      row = PWN::AI::Agent::Engagement.open(opts)
      dir = File.join(PWN::AI::Agent::Engagement::ROOT, row[:name].to_s)
      FileUtils.mkdir_p(File.join(dir, 'evidence'))
      hosts = File.join(dir, 'hosts.json')
      File.write(hosts, JSON.generate({})) unless File.file?(hosts)
      row.merge(dir: dir, hosts: hosts)
    end

    public_class_method def self.close(opts = {})
      PWN::AI::Agent::Engagement.close(opts)
    end

    public_class_method def self.status(opts = {})
      PWN::AI::Agent::Engagement.status(opts).merge(hosts: hosts(opts))
    end

    public_class_method def self.in_scope?(opts = {})
      PWN::AI::Agent::Engagement.in_scope?(opts)
    end

    public_class_method def self.warn_unless_in_scope(opts = {})
      return { ok: true } if in_scope?(opts) || opts[:override] == true

      { ok: false, warning: "out of scope: #{opts[:host] || opts[:ip] || opts[:target]}", override_required: true }
    end

    public_class_method def self.record_host(opts = {})
      check = warn_unless_in_scope(opts)
      return check.merge(recorded: false) unless check[:ok]

      name = (opts[:engagement] || opts[:name] || PWN::AI::Agent::Engagement.current_name || 'default').to_s
      dir = File.join(PWN::AI::Agent::Engagement::ROOT, name)
      FileUtils.mkdir_p(dir)
      path = File.join(dir, 'hosts.json')
      store = File.file?(path) ? JSON.parse(File.read(path), symbolize_names: true) : {}
      host = (opts[:host] || opts[:ip]).to_s
      row = store[host.to_sym] || { host: host, ports: [], services: [], notes: [], creds: [] }
      incoming = Array(opts[:ports]).map do |port|
        port.is_a?(Hash) ? port.transform_keys(&:to_sym) : { port: port }
      end
      by_port = {}
      (Array(row[:ports]) + incoming).each do |item|
        item = item.is_a?(Hash) ? item.transform_keys(&:to_sym) : { port: item }
        key = item[:port]
        by_port[key] = (by_port[key] || {}).merge(item)
      end
      row[:ports] = by_port.values.map { |item| item.keys == [:port] ? item[:port] : item }
      row[:services] = (Array(row[:services]) + Array(opts[:services])).uniq
      row[:notes] = (Array(row[:notes]) + Array(opts[:notes])).uniq
      row[:creds] = (Array(row[:creds]) + Array(opts[:creds])).uniq
      store[host.to_sym] = row
      File.write(path, JSON.pretty_generate(store))
      row
    end

    public_class_method def self.hosts(opts = {})
      name = (opts[:name] || PWN::AI::Agent::Engagement.current_name || 'default').to_s
      path = File.join(PWN::AI::Agent::Engagement::ROOT, name, 'hosts.json')
      return {} unless File.file?(path)

      JSON.parse(File.read(path), symbolize_names: true)
    end

    public_class_method def self.merge_scan(opts = {})
      Array(opts[:hosts] || opts[:results]).each do |row|
        row = row.transform_keys(&:to_sym) if row.respond_to?(:transform_keys)
        record_host(
          host: row[:host] || row['host'],
          ports: [{ port: row[:port] || row['port'], proto: row[:proto], service: row[:service], version: row[:version], scripts: row[:scripts] }.compact],
          services: [row[:service] || row['service']].compact,
          override: opts[:override],
          engagement: opts[:engagement] || opts[:name]
        )
      end
      hosts(name: opts[:engagement] || opts[:name])
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Open an engagement and ensure its host/evidence directories exist.
        #{self}.open(
          name: 'optional - engagement identifier (defaults to default)',
          engagement: 'optional - alias for name',
          scope_cidrs: 'optional - Array of CIDR strings',
          scope_domains: 'optional - Array of DNS suffixes',
          excluded: 'optional - Array of excluded hosts',
          roe: 'optional - rules of engagement notes'
        )

        # Clear the active engagement pointer.
        #{self}.close(
          unused: 'optional - accepted so callers can pass a Hash'
        )

        # Return scope plus persisted host state.
        #{self}.status(
          name: 'optional - engagement identifier'
        )

        # True when a host or URL is inside the active scope.
        #{self}.in_scope?(
          host: 'optional - hostname or IP',
          ip: 'optional - alias for host',
          target: 'optional - alias for host',
          url: 'optional - URL whose host is checked'
        )

        # Warn on out-of-scope targets unless override is true.
        #{self}.warn_unless_in_scope(
          host: 'optional - hostname or IP',
          ip: 'optional - alias for host',
          target: 'optional - alias for host',
          override: 'optional - true continues despite a scope miss'
        )

        # Deep-merge ports, services, notes, and vault refs for a host.
        #{self}.record_host(
          host: 'required - hostname or IP',
          ip: 'optional - alias for host',
          ports: 'optional - Array of open ports',
          services: 'optional - Array of service labels',
          notes: 'optional - Array of freeform notes',
          creds: 'optional - Array of vault references',
          override: 'optional - true records an out-of-scope host'
        )

        # Return the host map for an engagement.
        #{self}.hosts(
          name: 'optional - engagement identifier'
        )

        # Merge structured scan rows into host state.
        #{self}.merge_scan(
          hosts: 'optional - Array of {host, port, service} hashes',
          results: 'optional - alias for hosts',
          override: 'optional - true records out-of-scope hosts'
        )

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
    end
  end
end
