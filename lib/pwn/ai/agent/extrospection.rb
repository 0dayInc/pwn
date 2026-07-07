# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'digest'
require 'socket'
require 'open3'
require 'etc'
require 'uri'
require 'shellwords'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Extrospection is the outward-facing counterpart to
      # PWN::AI::Agent::Learning (introspection). Where Learning/Metrics
      # look INWARD at the agent's own tool telemetry, task outcomes and
      # session transcripts, Extrospection looks OUTWARD at the world the
      # agent operates in: host state, toolchain versions, network posture,
      # repo drift, and external threat-intel (CVE / Exploit-DB / ATT&CK).
      #
      # Together they close BOTH halves of the pwn-ai feedback loop:
      #
      #   INTROSPECTIVE (self)        EXTROSPECTIVE (world)
      #   ----------------------      -------------------------------------
      #   Metrics.record              Extrospection.snapshot   (host probe)
      #   Learning.note_outcome       Extrospection.observe    (recon fact)
      #   Learning.reflect            Extrospection.drift      (env delta)
      #   Learning.stats              Extrospection.intel      (CVE/EDB)
      #                               Extrospection.correlate  (self x world)
      #
      # PromptBuilder re-injects Extrospection.to_context on every turn so
      # the model gains situational awareness of what changed on THIS host
      # between sessions ("kernel upgraded", "nmap now missing", "port 8080
      # newly listening", "CVE-2026-XXXX matches installed openssl") and
      # can correlate that drift against introspective failures.
      #
      # Everything is file-backed under ~/.pwn/extrospection.json so it
      # survives across REPL restarts and is shared by every future session.
      module Extrospection
        EXTRO_FILE = File.join(Dir.home, '.pwn', 'extrospection.json')
        MAX_OBSERVATIONS = 500
        PROBE_BINS = %w[nmap curl git ruby python3 gcc msfconsole sqlmap burpsuite zaproxy openssl docker].freeze

        # Supported Method Parameters::
        # store = PWN::AI::Agent::Extrospection.load

        public_class_method def self.load
          FileUtils.mkdir_p(File.dirname(EXTRO_FILE))
          return { snapshot: {}, previous: {}, observations: [], updated_at: nil } unless File.exist?(EXTRO_FILE)

          JSON.parse(File.read(EXTRO_FILE), symbolize_names: true)
        rescue StandardError
          { snapshot: {}, previous: {}, observations: [], updated_at: nil }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Extrospection.save(
        #   store: 'required - Hash returned by .load / mutated in place'
        # )

        public_class_method def self.save(opts = {})
          store = opts[:store] ||= { snapshot: {}, previous: {}, observations: [] }
          store[:updated_at] = Time.now.utc.iso8601
          FileUtils.mkdir_p(File.dirname(EXTRO_FILE))
          File.write(EXTRO_FILE, JSON.pretty_generate(store))
          store
        end

        # Supported Method Parameters::
        # snap = PWN::AI::Agent::Extrospection.snapshot(
        #   persist: 'optional - Boolean, write snapshot to disk & rotate previous (default true)',
        #   sections: 'optional - Array subset of [:host, :net, :toolchain, :repo, :env] (default all)'
        # )
        #
        # Captures a fingerprint of the OUTSIDE world. When persist:true the
        # prior snapshot is rotated into :previous so .drift can diff them.

        public_class_method def self.snapshot(opts = {})
          persist  = if opts.key?(:persist)
                       opts[:persist] ? true : false
                     else
                       true
                     end
          sections = Array(opts[:sections]).map(&:to_sym)
          sections = %i[host net toolchain repo env] if sections.empty?

          snap = {}
          snap[:host]      = probe_host      if sections.include?(:host)
          snap[:net]       = probe_net       if sections.include?(:net)
          snap[:toolchain] = probe_toolchain if sections.include?(:toolchain)
          snap[:repo]      = probe_repo      if sections.include?(:repo)
          snap[:env]       = probe_env       if sections.include?(:env)
          snap[:captured_at] = Time.now.utc.iso8601
          snap[:fingerprint] = Digest::SHA256.hexdigest(JSON.generate(snap.except(:captured_at)))[0, 16]

          if persist
            store = load
            store[:previous] = store[:snapshot] || {}
            store[:snapshot] = snap
            save(store: store)
          end

          drift = compute_drift(before: load[:previous] || {}, after: snap)
          { snapshot: snap, drift: drift, persisted: persist }
        end

        # Supported Method Parameters::
        # obs = PWN::AI::Agent::Extrospection.observe(
        #   source: 'required - where the observation came from (nmap, shodan, burp, cve, human, ...)',
        #   data: 'required - the observation payload (String or Hash)',
        #   category: 'optional - :recon, :vuln, :intel, :target, :network, :misc (default :misc)',
        #   target: 'optional - host/ip/url/asset the observation is about',
        #   tags: 'optional - Array of String labels',
        #   ttl: 'optional - seconds until this observation is considered stale (default nil = forever)'
        # )
        #
        # Records a fact about the OUTSIDE world (as opposed to
        # Learning.note_outcome which records a fact about the agent's own
        # behaviour). Observations are re-injected via .to_context so recon
        # findings and threat-intel persist across sessions.

        public_class_method def self.observe(opts = {})
          source = opts[:source].to_s
          data   = opts[:data]
          raise 'ERROR: source is required' if source.strip.empty?
          raise 'ERROR: data is required'   if data.to_s.strip.empty?

          entry = {
            id: Digest::SHA256.hexdigest("#{source}-#{data}-#{Time.now.to_f}")[0, 12],
            source: source,
            category: (opts[:category] || :misc).to_s,
            target: opts[:target].to_s.empty? ? nil : opts[:target].to_s,
            data: data.is_a?(String) ? data[0, 4_000] : data,
            tags: Array(opts[:tags]).map(&:to_s),
            ttl: opts[:ttl]&.to_i,
            timestamp: Time.now.utc.iso8601
          }
          store = load
          store[:observations] ||= []
          store[:observations] << entry
          store[:observations].shift(store[:observations].length - MAX_OBSERVATIONS) if store[:observations].length > MAX_OBSERVATIONS
          save(store: store)
          entry
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Extrospection.observations(
        #   limit: 'optional - max entries newest-first (default 50)',
        #   source: 'optional - filter by source substring',
        #   category: 'optional - filter by category',
        #   target: 'optional - filter by target substring',
        #   tag: 'optional - filter by tag substring',
        #   fresh_only: 'optional - drop entries whose ttl has expired (default false)'
        # )

        public_class_method def self.observations(opts = {})
          limit  = opts[:limit] || 50
          src    = opts[:source].to_s.downcase
          cat    = opts[:category].to_s.downcase
          tgt    = opts[:target].to_s.downcase
          tag    = opts[:tag].to_s.downcase
          fresh  = opts[:fresh_only] ? true : false
          now    = Time.now.utc

          rows = Array(load[:observations])
          rows = rows.reject do |o|
            next true if fresh && o[:ttl] && (Time.parse(o[:timestamp].to_s) + o[:ttl].to_i) < now

            (src.empty? ? false : !o[:source].to_s.downcase.include?(src)) ||
              (cat.empty? ? false : o[:category].to_s.downcase != cat) ||
              (tgt.empty? ? false : !o[:target].to_s.downcase.include?(tgt)) ||
              (tag.empty? ? false : Array(o[:tags]).none? { |t| t.to_s.downcase.include?(tag) })
          rescue StandardError
            false
          end
          rows.reverse.first(limit)
        end

        # Supported Method Parameters::
        # delta = PWN::AI::Agent::Extrospection.drift(
        #   live: 'optional - probe host NOW and diff vs stored snapshot (default true). When false, diff stored :snapshot vs stored :previous.'
        # )

        public_class_method def self.drift(opts = {})
          live  = if opts.key?(:live)
                    opts[:live] ? true : false
                  else
                    true
                  end
          store = load
          if live
            after  = snapshot(persist: false)[:snapshot]
            before = store[:snapshot] || {}
          else
            after  = store[:snapshot] || {}
            before = store[:previous] || {}
          end
          compute_drift(before: before, after: after)
        end

        # Supported Method Parameters::
        # hits = PWN::AI::Agent::Extrospection.intel(
        #   query: 'required - keyword / product / CVE id to search external threat-intel for',
        #   feeds: 'optional - Array subset of [:nvd, :circl, :exploitdb] (default all)',
        #   limit: 'optional - max results per feed (default 5)',
        #   record: 'optional - also persist each hit as an observation (default false)'
        # )
        #
        # Best-effort external lookups. Network / API failures degrade to
        # an empty result for that feed rather than raising, so learning
        # never breaks the primary loop when offline.

        public_class_method def self.intel(opts = {})
          query = opts[:query].to_s.strip
          raise 'ERROR: query is required' if query.empty?

          feeds  = Array(opts[:feeds]).map(&:to_sym)
          feeds  = %i[nvd circl exploitdb] if feeds.empty?
          limit  = opts[:limit] || 5
          record = opts[:record] ? true : false

          results = {}
          results[:nvd]       = intel_nvd(query: query, limit: limit)       if feeds.include?(:nvd)
          results[:circl]     = intel_circl(query: query, limit: limit)     if feeds.include?(:circl)
          results[:exploitdb] = intel_exploitdb(query: query, limit: limit) if feeds.include?(:exploitdb)

          if record
            results.each do |feed, hits|
              Array(hits).each do |h|
                observe(source: feed.to_s, category: :intel, data: h, tags: ['intel', query], target: h.is_a?(Hash) ? h[:id].to_s : nil)
              end
            end
          end
          { query: query, feeds: feeds, results: results, total: results.values.flatten.compact.length }
        end

        # Supported Method Parameters::
        # findings = PWN::AI::Agent::Extrospection.correlate(
        #   limit: 'optional - max findings returned (default 10)'
        # )
        #
        # THE join between introspection and extrospection. Cross-references:
        #   * Metrics tools with success_rate < 50 %  vs  toolchain drift / missing bins
        #   * Learning failures                       vs  host / net drift on the same day
        #   * Observations tagged :vuln / :intel      vs  installed package versions
        # Emits human-readable, actionable findings the model can reason on.

        public_class_method def self.correlate(opts = {})
          limit    = opts[:limit] || 10
          findings = []
          delta    = drift(live: false)
          snap     = load[:snapshot] || {}

          # 1) failing tools whose backing binary vanished / changed version
          if defined?(Metrics)
            Metrics.summary(limit: 50).each do |m|
              next unless m[:success_rate] < 0.5 && m[:calls] > 2

              bin = m[:name].to_s.split('_').first
              tc  = Array(delta[:changed]).find { |c| c[:path].to_s.include?("toolchain.#{bin}") }
              miss = snap.dig(:toolchain, bin.to_sym).to_s.empty?
              next unless tc || miss

              findings << { kind: :tool_env_mismatch, tool: m[:name], success_rate: m[:success_rate], evidence: tc || "binary '#{bin}' not found in PATH", advice: "Re-verify `which #{bin}` / reinstall before relying on #{m[:name]}." }
            end
          end

          # 2) introspective failures coinciding with extrospective drift
          if defined?(Learning)
            Learning.outcomes(limit: 30, success: false).each do |o|
              day = o[:timestamp].to_s[0, 10]
              hit = Array(delta[:changed]).find { |c| c[:after].to_s.include?(day) || c[:path].to_s.match?(/kernel|repo|net/) }
              findings << { kind: :failure_during_drift, task: o[:task], on: day, drift: hit, advice: 'Environment changed around this failure — re-test under current snapshot before trusting the negative result.' } if hit
            end
          end

          # 3) intel observations matching installed components
          pkgs = snap[:toolchain] || {}
          observations(category: 'intel', limit: 100).each do |ob|
            blob = ob[:data].to_s.downcase
            pkgs.each do |bin, ver|
              next if ver.to_s.empty?
              next unless blob.include?(bin.to_s.downcase)

              findings << { kind: :intel_matches_host, component: bin, installed: ver, intel: ob[:data], source: ob[:source], advice: "Review #{ob[:source]} advisory for #{bin} #{ver} on this host." }
            end
          end

          # 4) raw drift as low-priority findings when nothing else matched
          Array(delta[:added]).first(5).each   { |c| findings << { kind: :env_added,   detail: c } } if findings.empty?
          Array(delta[:removed]).first(5).each { |c| findings << { kind: :env_removed, detail: c } } if findings.empty?

          findings.uniq.first(limit)
        end

        # Supported Method Parameters::
        # ctx = PWN::AI::Agent::Extrospection.to_context(
        #   drift_limit: 'optional - max drift lines (default 4)',
        #   obs_limit: 'optional - max observation lines (default 4)'
        # )

        public_class_method def self.to_context(opts = {})
          dlim = opts[:drift_limit] || 4
          olim = opts[:obs_limit]   || 4
          store = load
          return '' if (store[:snapshot] || {}).empty? && Array(store[:observations]).empty?

          snap  = store[:snapshot] || {}
          delta = compute_drift(before: store[:previous] || {}, after: snap)
          lines = []
          host  = snap[:host] || {}
          lines << "  host_fp   : #{snap[:fingerprint]}  (#{host[:os]} #{host[:kernel]}, #{host[:arch]})" if snap[:fingerprint]
          lines << "  captured  : #{snap[:captured_at]}" if snap[:captured_at]

          ch = Array(delta[:changed]).first(dlim).map { |c| "    ~ #{c[:path]}: #{c[:before].to_s[0, 40]} -> #{c[:after].to_s[0, 40]}" }
          ad = Array(delta[:added]).first(dlim).map   { |c| "    + #{c[:path]}: #{c[:after].to_s[0, 60]}" }
          rm = Array(delta[:removed]).first(dlim).map { |c| "    - #{c[:path]}: #{c[:before].to_s[0, 60]}" }
          unless ch.empty? && ad.empty? && rm.empty?
            lines << '  drift     :'
            lines.concat(ch).concat(ad).concat(rm)
          end

          obs = observations(limit: olim, fresh_only: true)
          unless obs.empty?
            lines << '  observed  :'
            obs.each { |o| lines << "    * [#{o[:category]}/#{o[:source]}] #{"#{o[:target]} — " if o[:target]}#{o[:data].to_s.gsub(/\s+/, ' ')[0, 120]}" }
          end

          "EXTROSPECTION (world-state; correlate with introspective failures)\n#{lines.join("\n")}\n\n"
        end

        # Supported Method Parameters::
        # stats = PWN::AI::Agent::Extrospection.stats

        public_class_method def self.stats
          store = load
          snap  = store[:snapshot] || {}
          delta = compute_drift(before: store[:previous] || {}, after: snap)
          {
            snapshot_captured_at: snap[:captured_at],
            snapshot_fingerprint: snap[:fingerprint],
            observations: Array(store[:observations]).length,
            drift_changed: Array(delta[:changed]).length,
            drift_added: Array(delta[:added]).length,
            drift_removed: Array(delta[:removed]).length,
            toolchain_bins: (snap[:toolchain] || {}).count { |_, v| !v.to_s.empty? },
            listening_ports: Array(snap.dig(:net, :listening)).length
          }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Extrospection.auto_extrospect(
        #   session_id: 'optional - id of the just-completed session (for tagging)'
        # )
        #
        # Called by Learning.auto_reflect when
        # PWN::Env[:ai][:agent][:auto_extrospect] is truthy. Captures a fresh
        # snapshot and, if drift is non-trivial, records it as an observation
        # and a PWN::Memory :env fact so the NEXT session's system prompt
        # already knows the world moved. Never raises.

        public_class_method def self.auto_extrospect(opts = {})
          sid = opts[:session_id]
          return unless auto_extrospect_enabled?

          res   = snapshot(persist: true)
          delta = res[:drift]
          moved = Array(delta[:changed]).length + Array(delta[:added]).length + Array(delta[:removed]).length
          return res if moved.zero?

          summary = summarise_drift(delta: delta)
          observe(source: 'auto_extrospect', category: :env, data: summary, tags: ['drift', sid.to_s].reject(&:empty?))
          if defined?(PWN::Memory)
            key = :"extro_drift_#{res[:snapshot][:fingerprint]}"
            PWN::Memory.remember(key: key, value: "ENV DRIFT #{res[:snapshot][:captured_at]}: #{summary[0, 260]}", category: :env)
          end
          res
        rescue StandardError => e
          warn "[pwn-ai/extrospection] auto_extrospect swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Extrospection.reset

        public_class_method def self.reset
          FileUtils.rm_f(EXTRO_FILE)
          { cleared: true }
        end

        # -------------------------------------------------------------
        # privates
        # -------------------------------------------------------------

        private_class_method def self.auto_extrospect_enabled?
          return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          PWN::Env.dig(:ai, :agent, :auto_extrospect) ? true : false
        rescue StandardError
          false
        end

        private_class_method def self.sh(opts = {})
          cmd = opts[:cmd].to_s
          return '' if cmd.empty?

          out, = Open3.capture2e(cmd)
          out.to_s.strip
        rescue StandardError
          ''
        end

        private_class_method def self.probe_host
          {
            hostname: begin
              Socket.gethostname
            rescue StandardError
              ''
            end,
            os: sh(cmd: 'uname -s'),
            kernel: sh(cmd: 'uname -r'),
            arch: sh(cmd: 'uname -m'),
            distro: begin
              File.read('/etc/os-release')[/PRETTY_NAME="?([^"\n]+)/, 1]
            rescue StandardError
              nil
            end,
            uptime_s: begin
              File.read('/proc/uptime').split.first.to_i
            rescue StandardError
              nil
            end,
            user: ENV.fetch('USER', ''),
            cpu_count: (Etc.respond_to?(:nprocessors) ? Etc.nprocessors : nil)
          }
        end

        private_class_method def self.probe_net
          listen = sh(cmd: 'ss -tlnH 2>/dev/null').lines.map { |l| l.split[3].to_s.split(':').last }.compact.uniq.sort
          ifaces = sh(cmd: 'ip -o -4 addr show 2>/dev/null').lines.map do |l|
            p = l.split
            { if: p[1], addr: p[3] }
          end
          route = sh(cmd: 'ip route show default 2>/dev/null').lines.first.to_s.strip
          { listening: listen, interfaces: ifaces, default_route: route }
        end

        private_class_method def self.probe_toolchain
          PROBE_BINS.each_with_object({}) do |b, h|
            path = sh(cmd: "which #{b} 2>/dev/null")
            h[b.to_sym] = path.empty? ? '' : "#{path} #{sh(cmd: "#{b} --version 2>/dev/null").lines.first.to_s.strip[0, 80]}"
          end
        end

        private_class_method def self.probe_repo
          root = defined?(PWN::ROOT) ? PWN::ROOT.to_s : Dir.pwd
          return {} unless Dir.exist?(File.join(root, '.git'))

          {
            root: root,
            head: sh(cmd: "git -C #{root} rev-parse --short HEAD"),
            branch: sh(cmd: "git -C #{root} rev-parse --abbrev-ref HEAD"),
            dirty: !sh(cmd: "git -C #{root} status --porcelain").empty?,
            pwn_version: (defined?(PWN::VERSION) ? PWN::VERSION : nil)
          }
        end

        private_class_method def self.probe_env
          {
            cwd: Dir.pwd,
            ruby: RUBY_VERSION,
            path_entries: ENV.fetch('PATH', '').split(':').length,
            ai_engine: (PWN::Env.dig(:ai, :active) if defined?(PWN::Env) && PWN::Env.is_a?(Hash))
          }
        rescue StandardError
          { cwd: Dir.pwd, ruby: RUBY_VERSION }
        end

        private_class_method def self.flatten(opts = {})
          hash   = opts[:hash] || {}
          prefix = opts[:prefix].to_s
          out    = opts[:out] || {}
          hash.each do |k, v|
            path = prefix.empty? ? k.to_s : "#{prefix}.#{k}"
            case v
            when Hash  then flatten(hash: v, prefix: path, out: out)
            when Array then out[path] = v.map(&:to_s).sort
            else            out[path] = v
            end
          end
          out
        end

        private_class_method def self.compute_drift(opts = {})
          before = flatten(hash: (opts[:before] || {}).except(:captured_at, :fingerprint))
          after  = flatten(hash: (opts[:after]  || {}).except(:captured_at, :fingerprint))
          changed = []
          added   = []
          removed = []
          (before.keys | after.keys).each do |k|
            next if k =~ /uptime_s$/

            b = before[k]
            a = after[k]
            if b.nil? && !a.nil?
              added << { path: k, after: a }
            elsif a.nil? && !b.nil?
              removed << { path: k, before: b }
            elsif a != b
              changed << { path: k, before: b, after: a }
            end
          end
          { changed: changed, added: added, removed: removed }
        end

        private_class_method def self.summarise_drift(opts = {})
          d = opts[:delta] || {}
          parts = Array(d[:changed]).first(5).map { |c| "~#{c[:path]}:#{c[:before].to_s[0, 30]}->#{c[:after].to_s[0, 30]}" }
          Array(d[:added]).first(5).each   { |c| parts << "+#{c[:path]}" }
          Array(d[:removed]).first(5).each { |c| parts << "-#{c[:path]}" }
          parts.empty? ? '(no drift)' : parts.join(' | ')
        end

        private_class_method def self.http_get_json(opts = {})
          url = opts[:url].to_s
          return nil if url.empty?

          require 'rest-client'
          resp = RestClient::Request.execute(method: :get, url: url, timeout: 8, open_timeout: 4, headers: { accept: :json, user_agent: 'pwn-ai-extrospection' })
          JSON.parse(resp.body, symbolize_names: true)
        rescue StandardError
          nil
        end

        private_class_method def self.intel_nvd(opts = {})
          q     = opts[:query].to_s
          limit = opts[:limit] || 5
          url   = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=#{URI.encode_www_form_component(q)}&resultsPerPage=#{limit}"
          body  = http_get_json(url: url)
          return [] unless body

          Array(body[:vulnerabilities]).first(limit).map do |v|
            c = v[:cve] || {}
            { id: c[:id], published: c[:published], desc: Array(c[:descriptions])&.first&.dig(:value).to_s[0, 300], cvss: c.dig(:metrics, :cvssMetricV31, 0, :cvssData, :baseScore) }
          end
        rescue StandardError
          []
        end

        private_class_method def self.intel_circl(opts = {})
          q     = opts[:query].to_s
          limit = opts[:limit] || 5
          body  = if q =~ /^CVE-\d{4}-\d+$/i
                    r = http_get_json(url: "https://cve.circl.lu/api/cve/#{q.upcase}")
                    r ? [r] : []
                  else
                    http_get_json(url: "https://cve.circl.lu/api/search/#{URI.encode_www_form_component(q)}") || []
                  end
          Array(body).flatten.first(limit).map do |c|
            { id: c[:id], cvss: c[:cvss], summary: c[:summary].to_s[0, 300], refs: Array(c[:references]).first(3) }
          end
        rescue StandardError
          []
        end

        private_class_method def self.intel_exploitdb(opts = {})
          q     = opts[:query].to_s
          limit = opts[:limit] || 5
          bin   = sh(cmd: 'which searchsploit 2>/dev/null')
          return [] if bin.empty?

          raw = sh(cmd: "searchsploit --json #{q.shellescape} 2>/dev/null")
          j   = begin
            JSON.parse(raw, symbolize_names: true)
          rescue StandardError
            nil
          end
          return [] unless j

          Array(j[:RESULTS_EXPLOIT]).first(limit).map { |e| { id: "EDB-#{e[:'EDB-ID']}", title: e[:Title].to_s[0, 200], path: e[:Path] } }
        rescue StandardError
          []
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Extrospection.snapshot                          # probe host, persist, return {snapshot:, drift:}
              PWN::AI::Agent::Extrospection.drift(live: true)                 # what changed vs last snapshot
              PWN::AI::Agent::Extrospection.observe(source: 'nmap', category: :recon, target: '10.0.0.5', data: '22/tcp open ssh 9.6')
              PWN::AI::Agent::Extrospection.observations(category: 'recon', target: '10.0.0.5')
              PWN::AI::Agent::Extrospection.intel(query: 'openssl 3.0', record: true)
              PWN::AI::Agent::Extrospection.correlate                         # introspection x extrospection findings
              PWN::AI::Agent::Extrospection.to_context                        # injected by PromptBuilder
              PWN::AI::Agent::Extrospection.stats
              PWN::AI::Agent::Extrospection.auto_extrospect(session_id: sid)  # called from Learning.auto_reflect
              PWN::AI::Agent::Extrospection.reset

              Enable end-of-run auto-extrospection with:
                PWN::Env[:ai][:agent][:auto_extrospect] = true

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
