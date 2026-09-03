# frozen_string_literal: true

module PWN
  module Plugins
    # Plugin/binary/capability preflight. Plugins declare required_bins /
    # required_caps; HOST summaries list degraded modules without autoloading
    # the whole plugin tree.
    module PreflightChecker
      class MissingBinary < StandardError; end
      class MissingCapability < StandardError; end
      class MissingService < StandardError; end

      PLUGIN_DEPS = {
        'PWN::Plugins::Radare2' => { bins: %w[r2] },
        'PWN::Plugins::GDB' => { bins: %w[gdb] },
        'PWN::Plugins::Nuclei' => { bins: %w[nuclei] },
        'PWN::Plugins::Sqlmap' => { bins: %w[sqlmap] },
        'PWN::Plugins::Frida' => { bins: %w[frida] },
        'PWN::Plugins::AFLplusplus' => { bins: %w[afl-fuzz] },
        'PWN::Plugins::Volatility' => { bins: %w[vol] },
        'PWN::Plugins::NmapIt' => { bins: %w[nmap] },
        'PWN::Plugins::Metasploit' => { bins: %w[msfconsole] },
        'PWN::Plugins::BurpSuite' => { bins: %w[burpsuite] },
        'PWN::Plugins::Zaproxy' => { bins: %w[zaproxy] },
        'PWN::Plugins::Packet' => { bins: [], caps: %w[CAP_NET_RAW] },
        'PWN::Plugins::K8s' => { bins: %w[trivy], services: [{ name: 'docker', path: '/var/run/docker.sock' }] },
        'PWN::Plugins::Semgrep' => { bins: %w[semgrep] },
        'PWN::Plugins::ExploitDB' => { bins: %w[searchsploit] },
        'PWN::Plugins::Recon' => { bins: %w[subfinder httpx] },
        'PWN::Plugins::CredentialAttack' => { bins: %w[hydra john hashcat] }
      }.freeze

      FALLBACKS = {
        'PWN::Plugins::Metasploit' => %w[exploitdev pwn_eval],
        'PWN::Plugins::BurpSuite' => %w[TransparentBrowser nuclei],
        'PWN::Plugins::Zaproxy' => %w[nuclei TransparentBrowser],
        'PWN::Plugins::K8s' => %w[pwn_eval],
        'PWN::Plugins::ExploitDB' => %w[intel_lookup]
      }.freeze

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.bin?(opts = {})
        name = opts[:name].to_s
        return false if name.empty?

        ENV['PATH'].to_s.split(File::PATH_SEPARATOR).any? do |dir|
          File.executable?(File.join(dir, name))
        end
      end

      public_class_method def self.require_bin!(opts = {})
        name = opts[:name].to_s
        return true if bin?(name: name)

        raise MissingBinary, "ERROR: required binary missing: #{name}. Install via pwn setup --profile re (or the plugin profile)."
      end

      public_class_method def self.route(opts = {})
        name = opts[:name].to_s
        raise 'ERROR: name is required' if name.empty?

        return { ok: true, name: name } if bin?(name: name)

        { ok: false, name: name, degraded: true, hint: "missing #{name}; install via pwn setup --deps" }
      end

      CAPABILITIES = {
        web_scan: %w[nuclei burpsuite zaproxy],
        raw_packet: %w[],
        decompile: %w[analyzeHeadless r2],
        debug: %w[gdb]
      }.freeze

      public_class_method def self.capability_coverage(opts = {})
        want = opts[:capability] || opts[:cap]
        if want
          bins = Array(CAPABILITIES[want.to_sym])
          covered = bins.any? { |b| bin?(name: b) }
          return { capability: want.to_s, covered: covered, bins: bins }
        end
        CAPABILITIES.keys.map { |k| capability_coverage(capability: k) }
      end

      TASK_BINS = {
        'proxy' => %w[burpsuite zaproxy],
        'vuln-scan' => %w[nuclei openvas],
        're' => %w[r2 gdb]
      }.freeze

      public_class_method def self.pick(opts = {})
        task = opts[:task].to_s
        raise 'ERROR: task is required' if task.empty?

        tried = Array(TASK_BINS[task])
        tried.each do |name|
          return { ok: true, name: name, task: task } if bin?(name: name)
        end
        { ok: false, task: task, tried: tried, hint: "no healthy alternative for #{task}" }
      end

      public_class_method def self.cap_net_raw?(opts = {})
        return true unless File.readable?('/proc/self/status')

        line = File.readlines('/proc/self/status').find { |l| l.start_with?('CapEff:') }
        return false unless line

        hex = line.split.last.to_s
        hex.to_i(16).anybits?(1 << 13)
      rescue StandardError
        opts[:default] == true
      end

      public_class_method def self.require_cap_net_raw!(opts = {})
        return true if cap_net_raw?(opts)

        raise MissingCapability,
              'ERROR: CAP_NET_RAW is missing. Packet.send cannot inject L2 frames. ' \
              'Hint: sudo setcap cap_net_raw,cap_net_admin+ep "$(readlink -f "$(command -v ruby)")" ' \
              'or run as root. Fallback: PWN::Plugins::Sock.connect (no raw).'
      end

      public_class_method def self.service?(opts = {})
        path = opts[:path].to_s
        return File.socket?(path) unless path.empty?

        false
      end

      public_class_method def self.check(opts = {})
        deps = PLUGIN_DEPS
        if opts[:names]
          want = Array(opts[:names]).map(&:to_s)
          deps = deps.slice(*want)
        end
        deps.map do |plugin, dep|
          bins = Array(dep[:bins])
          caps = Array(dep[:caps])
          services = Array(dep[:services])
          missing_bins = bins.reject { |b| bin?(name: b) }
          missing_caps = []
          missing_caps << 'CAP_NET_RAW' if caps.include?('CAP_NET_RAW') && !cap_net_raw?
          missing_services = services.reject { |s| service?(name: s[:name] || s['name'], path: s[:path] || s['path']) }.map { |s| s[:name] || s['name'] }
          status = if missing_bins.empty? && missing_caps.empty? && missing_services.empty?
                     :ok
                   elsif bins.any? && missing_bins.length == bins.length
                     :dead
                   else
                     :degraded
                   end
          { plugin: plugin, status: status, missing_bins: missing_bins, missing_caps: missing_caps, missing_services: missing_services }
        end
      end

      public_class_method def self.host_summary(opts = {})
        rows = check(names: opts[:names])
        cap = (opts[:limit] || 12).to_i
        dead = rows.select { |r| r[:status] == :dead }
        degraded = rows.select { |r| r[:status] == :degraded }
        lines = ["HOST plugins ok=#{rows.count { |r| r[:status] == :ok }} degraded=#{degraded.length} dead=#{dead.length}"]
        (degraded + dead).first(cap).each do |r|
          miss = (Array(r[:missing_bins]) + Array(r[:missing_caps]) + Array(r[:missing_services])).join(',')
          fb = Array(FALLBACKS[r[:plugin]]).join(',')
          extra = fb.empty? ? '' : " fallback=#{fb}"
          lines << "  #{r[:status]} #{r[:plugin]} missing=#{miss}#{extra}"
        end
        lines.join("\n")
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run bin and return its result
          #{self}.bin?(
            name: 'required - binary or identifier name'
          )

          # Run require bin and return its result
          #{self}.require_bin!(
            name: 'required - binary or identifier name'
          )

          # Return ok/degraded for a binary without raising.
          #{self}.route(
            name: 'required - binary name to probe'
          )

          # Report whether a named capability is covered by any healthy plugin binary.
          #{self}.capability_coverage(
            capability: 'optional - capability name such as web_scan',
            cap: 'optional - alias for capability'
          )

          # First healthy binary for a task (proxy, vuln-scan, re).
          #{self}.pick(
            task: 'required - capability name such as proxy or vuln-scan'
          )

          # Run cap net raw and return its result
          #{self}.cap_net_raw?(
            default: 'optional - default value consumed by #cap_net_raw?'
          )

          # Run require cap net raw and return its result
          #{self}.require_cap_net_raw!

          # True when a unix socket/service path exists.
          #{self}.service?(
            name: 'optional - service name for the report row',
            path: 'required - unix socket path (e.g. /var/run/docker.sock)'
          )

          # Run check and return its result
          #{self}.check(
            names: 'optional - Array names value consumed by #check'
          )

          # Run host summary and return its result
          #{self}.host_summary(
            names: 'optional - names value consumed by #host_summary',
            limit: 'optional - limit value consumed by #host_summary'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
