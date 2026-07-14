# frozen_string_literal: true

require 'json'
require 'shellwords'
require 'tmpdir'

module PWN
  module AI
    module Agent
      # Local-tool OSINT bridges for PWN::AI::Agent::Extrospection.osint.
      # Wraps host binaries (theHarvester, spiderfoot, amass, recon-ng)
      # already common on Kali / offensive-tooling images, parses their
      # JSON/CSV output, and returns compact structured hits so they behave
      # like any other feed. Every bridge:
      #   * checks binary presence first (returns {skipped:} when absent)
      #   * runs passive-only / bounded (timeouts, `-passive`, module lists)
      #   * NEVER launches a GUI or web UI
      module Extrospection
        BRIDGE_FEEDS = %i[theharvester spiderfoot amass reconng].freeze

        # ── config ──────────────────────────────────────────────────

        private_class_method def self.osint_bridge_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :osint, :bridges) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          {
            timeout: (cfg[:timeout] || 120).to_i,
            theharvester_sources: (cfg[:theharvester_sources] || 'anubis,crtsh,hackertarget,otx,rapiddns,urlscan,certspotter,dnsdumpster,duckduckgo').to_s,
            spiderfoot_modules: (cfg[:spiderfoot_modules] || 'sfp_dnsresolve,sfp_crt,sfp_hackertarget,sfp_dnsdumpster,sfp_wayback,sfp_social').to_s,
            amass_passive: cfg.key?(:amass_passive) ? !cfg[:amass_passive].nil? && cfg[:amass_passive] != false : true
          }
        rescue StandardError
          { timeout: 120, theharvester_sources: 'crtsh,hackertarget,otx', spiderfoot_modules: 'sfp_dnsresolve,sfp_crt', amass_passive: true }
        end

        private_class_method def self.bridge_json(opts = {})
          JSON.parse(opts[:str].to_s, symbolize_names: true)
        rescue StandardError
          nil
        end

        private_class_method def self.bridge_bin(opts = {})
          Array(opts[:names]).each do |n|
            path = sh(cmd: "command -v #{Shellwords.escape(n)} 2>/dev/null")
            return path unless path.empty?
          end
          nil
        end

        private_class_method def self.bridge_domain(opts = {})
          q = opts[:query].to_s.strip.sub(%r{\Ahttps?://}i, '').sub(%r{/.*\z}, '')
          q = q.split('@').last if q.include?('@')
          q
        end

        # ── theHarvester ────────────────────────────────────────────

        private_class_method def self.osint_theharvester(opts = {})
          bin = bridge_bin(names: %w[theHarvester theharvester])
          return { skipped: 'theHarvester not installed' } unless bin

          cfg    = osint_bridge_config
          domain = bridge_domain(query: opts[:query])
          return { error: 'theHarvester requires a domain/email query' } if domain.to_s.empty? || !domain.include?('.')

          limit = (opts[:limit] || 50).to_i
          Dir.mktmpdir('pwn-theharvester') do |dir|
            out = File.join(dir, 'th')
            cmd = "timeout #{cfg[:timeout]} #{Shellwords.escape(bin)} -d #{Shellwords.escape(domain)} " \
                  "-b #{Shellwords.escape(cfg[:theharvester_sources])} -l #{limit} " \
                  "-f #{Shellwords.escape(out)} 2>&1"
            raw = sh(cmd: cmd)
            json_path = %W[#{out}.json #{out}].find { |p| File.exist?(p) }
            data = json_path ? bridge_json(str: File.read(json_path)) : nil
            if data.is_a?(Hash)
              {
                source: 'theHarvester',
                bin: bin,
                domain: domain,
                sources: cfg[:theharvester_sources],
                hosts: Array(data[:hosts]).first(limit),
                emails: Array(data[:emails]).first(limit),
                ips: Array(data[:ips]).first(limit),
                asns: Array(data[:asns]).first(limit),
                interesting_urls: Array(data[:interesting_urls]).first(20),
                counts: { hosts: Array(data[:hosts]).size, emails: Array(data[:emails]).size, ips: Array(data[:ips]).size }
              }
            else
              # Parse stdout fallback (older builds without -f json).
              hosts  = raw.scan(/^\s*([a-z0-9][a-z0-9.-]+\.#{Regexp.escape(domain)})/i).flatten.uniq
              emails = raw.scan(/[A-Za-z0-9._%+-]+@#{Regexp.escape(domain)}/i).uniq
              { source: 'theHarvester', bin: bin, domain: domain, hosts: hosts.first(limit), emails: emails.first(limit), stdout_tail: raw.to_s.split("\n").last(10), note: 'JSON output not found; parsed stdout' }
            end
          end
        rescue StandardError => e
          { source: 'theHarvester', error: "#{e.class}: #{e.message.to_s[0, 160]}" }
        end

        # ── amass (passive enum) ────────────────────────────────────

        private_class_method def self.osint_amass(opts = {})
          bin = bridge_bin(names: %w[amass])
          return { skipped: 'amass not installed' } unless bin

          cfg    = osint_bridge_config
          domain = bridge_domain(query: opts[:query])
          return { error: 'amass requires a domain query' } if domain.to_s.empty? || !domain.include?('.')

          limit = (opts[:limit] || 100).to_i
          Dir.mktmpdir('pwn-amass') do |dir|
            jf = File.join(dir, 'amass.json')
            passive = cfg[:amass_passive] ? '-passive' : ''
            cmd = "timeout #{cfg[:timeout]} #{Shellwords.escape(bin)} enum #{passive} -silent -norecursive " \
                  "-d #{Shellwords.escape(domain)} -json #{Shellwords.escape(jf)} 2>&1"
            raw = sh(cmd: cmd)
            names = []
            addrs = []
            if File.exist?(jf)
              File.foreach(jf) do |line|
                j = bridge_json(str: line)
                next unless j

                names << j[:name] if j[:name]
                Array(j[:addresses]).each { |a| addrs << a[:ip] if a.is_a?(Hash) && a[:ip] }
              end
            elsif !raw.to_s.empty?
              names = raw.split("\n").grep(/#{Regexp.escape(domain)}\s*$/i).map(&:strip)
            end
            {
              source: 'amass',
              bin: bin,
              domain: domain,
              passive: cfg[:amass_passive],
              subdomains: names.uniq.first(limit),
              addresses: addrs.uniq.first(limit),
              counts: { subdomains: names.uniq.size, addresses: addrs.uniq.size }
            }
          end
        rescue StandardError => e
          { source: 'amass', error: "#{e.class}: #{e.message.to_s[0, 160]}" }
        end

        # ── spiderfoot (headless CLI, JSON output) ──────────────────

        private_class_method def self.osint_spiderfoot(opts = {})
          bin = bridge_bin(names: %w[spiderfoot sf sf.py])
          return { skipped: 'spiderfoot not installed' } unless bin

          cfg    = osint_bridge_config
          target = opts[:query].to_s.strip
          return { error: 'spiderfoot requires a non-empty target' } if target.empty?

          limit = (opts[:limit] || 100).to_i
          cmd = "timeout #{cfg[:timeout]} #{Shellwords.escape(bin)} -s #{Shellwords.escape(target)} " \
                "-m #{Shellwords.escape(cfg[:spiderfoot_modules])} -o json -q 2>/dev/null"
          raw = sh(cmd: cmd)
          rows = bridge_json(str: raw)
          rows = raw.to_s.each_line.map { |l| bridge_json(str: l) }.compact if rows.nil?
          rows = Array(rows)
          by_type = rows.group_by { |r| r[:type] || r[:Type] }.transform_values { |v| v.map { |r| r[:data] || r[:Data] }.compact.uniq }
          {
            source: 'spiderfoot',
            bin: bin,
            target: target,
            modules: cfg[:spiderfoot_modules],
            events: rows.length,
            types: by_type.keys,
            data: by_type.transform_values { |v| v.first(limit) },
            note: 'headless CLI (`-o json -q`); web UI never launched'
          }
        rescue StandardError => e
          { source: 'spiderfoot', error: "#{e.class}: #{e.message.to_s[0, 160]}" }
        end

        # ── recon-ng (workspace enum, non-interactive resource) ─────

        private_class_method def self.osint_reconng(opts = {})
          bin = bridge_bin(names: %w[recon-ng])
          return { skipped: 'recon-ng not installed' } unless bin

          cfg    = osint_bridge_config
          domain = bridge_domain(query: opts[:query])
          return { error: 'recon-ng bridge requires a domain query' } if domain.to_s.empty? || !domain.include?('.')

          Dir.mktmpdir('pwn-reconng') do |dir|
            ws = "pwn_#{Time.now.to_i}"
            rc = File.join(dir, 'run.rc')
            hosts_out = File.join(dir, 'hosts.txt')
            File.write(rc, <<~RC)
              workspaces create #{ws}
              db insert domains #{domain}~
              modules load recon/domains-hosts/hackertarget
              run
              modules load recon/domains-hosts/certificate_transparency
              run
              show hosts
              exit
            RC
            raw = sh(cmd: "timeout #{cfg[:timeout]} #{Shellwords.escape(bin)} -w #{Shellwords.escape(ws)} -r #{Shellwords.escape(rc)} --no-analytics --no-check 2>&1 | tee #{Shellwords.escape(hosts_out)}")
            hosts = raw.scan(/([a-z0-9][a-z0-9.-]+\.#{Regexp.escape(domain)})/i).flatten.uniq
            # Best-effort workspace cleanup.
            sh(cmd: "timeout 15 #{Shellwords.escape(bin)} -w default --no-analytics --no-check -x 'workspaces remove #{ws}' 2>/dev/null")
            {
              source: 'recon-ng',
              bin: bin,
              domain: domain,
              workspace: ws,
              modules: %w[recon/domains-hosts/hackertarget recon/domains-hosts/certificate_transparency],
              hosts: hosts.first((opts[:limit] || 100).to_i),
              counts: { hosts: hosts.size },
              stdout_tail: raw.to_s.split("\n").last(8)
            }
          end
        rescue StandardError => e
          { source: 'recon-ng', error: "#{e.class}: #{e.message.to_s[0, 160]}" }
        end
        # Marker submodule so this file satisfies PWN module conventions
        # (def self.help / def self.authors per-file) WITHOUT clobbering
        # PWN::AI::Agent::Extrospection.help defined in the parent file.
        module OSINTBridges
          # Author(s):: 0day Inc. <support@0dayinc.com>

          public_class_method def self.authors
            "AUTHOR(S):\n0day Inc. <support@0dayinc.com>\n"
          end

          # Display Usage for this Module

          public_class_method def self.help
            <<~USAGE
              Local-tool OSINT bridge feeds for PWN::AI::Agent::Extrospection.osint.
              Feeds: #{BRIDGE_FEEDS.join(', ')}
              Bins probed: theHarvester, spiderfoot, amass, recon-ng (skips cleanly when absent).
              See PWN::AI::Agent::Extrospection.help / documentation/Extrospection.md.
            USAGE
          end
        end
      end
    end
  end
end
