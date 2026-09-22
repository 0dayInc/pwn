# frozen_string_literal: true

require 'nmap/command'
require 'nmap/xml'
require 'open3'
require 'securerandom'
require 'tmpdir'
require 'rexml/document'
require 'time'

module PWN
  module Plugins
    # This plugin is used as an  interface to nmap, the exploration tool and security / port scanner.  More info on available options can be found at: https://github.com/postmodern/ruby-nmap/blob/main/lib/nmap/command.rb
    module NmapIt
      # Supported Method Parameters::
      # PWN::Plugins::NmapIt.port_scan do |nmap|
      #   puts nmap.public_methods
      #   nmap.connect_scan = true
      #   nmap.service_scan = true
      #   nmap.verbose = true
      #   nmap.ports = [1..1024, 1337]
      #   nmap.targets = '127.0.0.1'
      #   nmap.xml = '/tmp/nmap_port_scan_res.xml' # alias of output_xml
      # end
      #
      # PWN::Plugins::NmapIt.port_scan(
      #   targets: '127.0.0.1',
      #   ports: '1-65535',
      #   connect_scan: true,
      #   service_scan: true,
      #   script: 'vuln,safe',
      #   xml: '/tmp/nmap_port_scan_res.xml'
      # )

      public_class_method def self.port_scan(opts = {})
        Nmap::Command.sudo do |nmap|
          apply_port_scan_opts(nmap: nmap, opts: opts)
          yield(nmap_compat(nmap: nmap)) if block_given?
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.apply_port_scan_opts(opts = {})
        nmap = opts[:nmap]
        args = opts[:opts]
        return nmap unless args.is_a?(Hash)

        nmap.targets = args[:targets] || args[:target] if args[:targets] || args[:target]
        nmap.ports = args[:ports] if args.key?(:ports)
        xml = args[:xml] || args[:output_xml]
        nmap.output_xml = xml if xml
        nmap.connect_scan = args[:connect_scan] if args.key?(:connect_scan)
        nmap.service_scan = args[:service_scan] || args[:service_detection] if args.key?(:service_scan) || args.key?(:service_detection)
        nmap.verbose = args[:verbose] if args.key?(:verbose)
        scripts = args[:script] || args[:scripts] || args[:vuln_scripts]
        nmap.script = scripts if scripts
        nmap
      end

      private_class_method def self.nmap_compat(opts = {})
        nmap = opts[:nmap]
        nmap.define_singleton_method(:xml=) { |path| self.output_xml = path }
        nmap.define_singleton_method(:xml) { output_xml }
        nmap
      end

      # Supported Method Parameters::
      # PWN::Plugins::NmapIt.parse_xml_results(:xml_file => 'required - path to nmap xml results') do |xml|
      #   puts xml.public_methods
      #   xml.each_host do |host|
      #     puts "[#{host.ip}]"
      #
      #     host.scripts.each do |name,output|
      #       output.each_line { |line| puts "  #{line}" }
      #     end
      #
      #     host.each_port do |port|
      #       puts "  [#{port.number}/#{port.protocol}]"
      #
      #       port.scripts.each do |name,output|
      #         puts "    [#{name}]"
      #         output.each_line { |line| puts "      #{line}" }
      #       end
      #     end
      #   end
      # end

      public_class_method def self.parse_xml_results(opts = {})
        xml_file = opts[:xml_file].to_s.scrub.strip.chomp if File.exist?(opts[:xml_file].to_s.scrub.strip.chomp)

        Nmap::XML.open(xml_file) do |xml|
          yield(xml)
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NmapIt.diff_xml_results(
      #   xml_a: 'required - path to nmap xml results',
      #   xml_b: 'required - path to nmap xml results',
      #   diff: 'required - path to nmap xml results diff'
      # )
      public_class_method def self.diff_xml_results(opts = {})
        xml_a = opts[:xml_a].to_s.scrub.strip.chomp
        xml_b = opts[:xml_b].to_s.scrub.strip.chomp
        diff = opts[:diff].to_s.scrub.strip.chomp

        stdout, _stderr, _status = Open3.capture3(
          'ndiff',
          '--xml',
          xml_a,
          xml_b
        )

        File.write(diff, stdout)
      rescue StandardError => e
        raise e
      end

      public_class_method def self.to_findings(opts = {})
        inventory(opts)[:ports]
      end

      public_class_method def self.inventory(opts = {})
        xml_file = (opts[:xml_file] || opts[:xml]).to_s
        raise 'ERROR: xml_file is required' if xml_file.empty?
        return { hosts: [], ports: [] } unless File.file?(xml_file)

        doc = REXML::Document.new(File.read(xml_file))
        hosts = []
        ports = []
        doc.elements.each('nmaprun/host') do |node|
          ip = node.elements['address']&.attributes&.[]('addr').to_s
          next if ip.empty?

          host_scripts = script_map(node: node.elements['hostscript'])
          host_ports = []
          node.elements.each('ports/port') do |port_node|
            number = port_node.attributes['portid'].to_i
            proto = port_node.attributes['protocol'].to_s
            state = port_node.elements['state']&.attributes&.[]('state').to_s
            svc = port_node.elements['service']
            scripts = script_map(node: port_node)
            row = {
              host: ip,
              port: number,
              proto: proto,
              state: state,
              service: svc&.attributes&.[]('name'),
              version: svc&.attributes&.[]('version') || svc&.attributes&.[]('product'),
              scripts: scripts,
              template_id: nil,
              severity: 'info'
            }
            host_ports << row
            ports << row
          end
          hosts << { host: ip, ports: host_ports, services: host_ports.map { |row| row[:service] }.compact.uniq, scripts: host_scripts }
        end
        { hosts: hosts, ports: ports, xml: xml_file }
      end

      public_class_method def self.scan(opts = {})
        targets = opts[:targets] || opts[:target]
        check = PWN::Engagement.warn_unless_in_scope(host: Array(targets).first, override: opts[:override]) if defined?(PWN::Engagement) && opts[:engagement] != false
        return check.merge(scanned: false) if check.is_a?(Hash) && check[:ok] == false

        xml = (opts[:xml_file] || opts[:xml]).to_s
        if xml.empty? || opts[:run] == true
          skipped = skip_known_ports(opts)
          return skipped if skipped

          xml = File.join(Dir.tmpdir, "pwn-nmap-#{Process.pid}-#{SecureRandom.hex(4)}.xml") if xml.empty?
          port_scan(opts.merge(xml: xml, targets: targets))
        end
        inv = inventory(xml_file: xml)
        rows = inv[:ports]
        eng = opts[:engagement] || opts[:name]
        if defined?(PWN::Engagement) && opts[:engagement] != false
          PWN::Engagement.merge_scan(results: rows, override: opts[:override], engagement: eng)
          PWN::Engagement.record_scan(hosts: inv[:hosts], ports: rows, xml: xml, at: opts[:at], engagement: eng, kind: 'nmap')
        end
        grouped = inv[:hosts]
        {
          hosts: grouped,
          ports: rows,
          xml: xml,
          diff: changes(opts.merge(engagement: eng, latest: inv[:hosts]))
        }
      end

      public_class_method def self.changes(opts = {})
        eng = opts[:engagement] || opts[:name]
        snaps = defined?(PWN::Engagement) ? PWN::Engagement.scans(engagement: eng, name: eng) : []
        latest_hosts = opts[:latest]
        if latest_hosts.nil?
          return { since: opts[:since], added_hosts: [], removed_hosts: [], added_ports: [], removed_ports: [], changed_scripts: [], first: true } if snaps.empty?

          latest_hosts = Array(snaps.last[:hosts])
        end
        cutoff = parse_since(since: opts[:since])
        pool = Array(snaps[0..-2])
        previous = pool.reverse.find do |snap|
          at = Time.parse(snap[:at].to_s).utc
          cutoff.nil? || at <= cutoff
        end
        previous ||= snaps[-2]
        return { since: opts[:since], previous_at: nil, added_hosts: [], removed_hosts: [], added_ports: [], removed_ports: [], changed_scripts: [], first: true } unless previous

        diff_inventories(previous: Array(previous[:hosts]), current: latest_hosts).merge(since: opts[:since], previous_at: previous[:at], current_at: snaps.last && snaps.last[:at])
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
          # nmap.connect_scan = true
          #{self}.port_scan(
            targets: 'optional - hostname, IP, CIDR, or list of targets',
            ports: 'optional - port, list, or range (e.g. 22,80,443 or 1-1024)',
            connect_scan: 'optional - connect scan value consumed by #port_scan',
            service_scan: 'optional - service scan value consumed by #port_scan',
            script: 'optional - script value consumed by #port_scan',
            xml: 'optional - /tmp/nmap_port_scan_res.xml'
          )

          # xml.each_host do |host|
          #{self}.parse_xml_results(
            xml_file: 'optional - xml file value consumed by #parse_xml_results'
          )

          # Run diff xml results and return its result
          #{self}.diff_xml_results(
            xml_a: 'required - path to nmap xml results',
            xml_b: 'required - path to nmap xml results',
            diff: 'required - path to nmap xml results diff'
          )

          # Normalize nmap XML into {host, port, proto, service, version} rows.
          #{self}.to_findings(
            xml_file: 'required - path to nmap XML output'
          )

          # Parse nmap XML into enumerable host/port hashes and merge engagement state.
          #{self}.scan(
            xml_file: 'optional - existing nmap XML path',
            xml: 'optional - alias for xml_file',
            run: 'optional - true forces port_scan even when xml_file is set',
            engagement: 'optional - false skips host-state merge',
            override: 'optional - true records out-of-scope hosts',
            target: 'optional - alias for targets',
            name: 'optional - engagement name for host-state merge',
            at: 'optional - Time or ISO8601 timestamp stored on the scan snapshot',
            refresh: 'optional - true rescans ports that already have an observation',
            ports: 'optional - ports to scan; known observation ports are skipped unless refresh is true',
            handoff: 'optional - recon asset hash used as the scan target'
          )

          # Parse nmap XML into hosts, ports, and script output hashes.
          #{self}.inventory(
            xml_file: 'required - path to nmap XML output unless xml is set',
            xml: 'optional - alias for xml_file'
          )

          # Diff the latest engagement snapshot against yesterday or a prior scan.
          #{self}.changes(
            since: 'optional - yesterday, last-scan, ISO8601, or Time (defaults to previous snapshot)',
            engagement: 'optional - engagement identifier',
            name: 'optional - alias for engagement',
            latest: 'optional - inventory host array to treat as current'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.skip_known_ports(opts = {})
        return nil if opts[:refresh]
        return nil unless defined?(PWN::Plugins::Recon)

        handoff = PWN::Plugins::Recon.handoff(handoff: opts[:handoff] || opts[:asset]) if opts[:handoff] || opts[:asset]
        host = handoff && !handoff[:host].empty? ? handoff[:host] : Array(opts[:targets] || opts[:target]).first.to_s
        return nil if host.empty?

        known = PWN::Plugins::Recon.known_ports(host: host, engagement_id: opts[:engagement] || opts[:name])
        requested = Array(opts[:ports]).map(&:to_i)
        requested = [handoff[:port].to_i] if requested.empty? && handoff && handoff[:port]
        covered = requested.empty? ? known : (requested & known)
        return nil if covered.empty?
        return nil if !requested.empty? && (requested - known).any?

        { hosts: [], ports: [], scanned: false, skipped_ports: covered, reason: 'existing observation' }
      end

      private_class_method def self.script_map(opts = {})
        node = opts[:node]
        return {} unless node

        map = {}
        node.elements.each('script') do |script|
          map[script.attributes['id'].to_s] = script.attributes['output'].to_s
        end
        map
      end

      private_class_method def self.parse_since(opts = {})
        token = opts[:since]
        return nil if token.nil? || token.to_s.empty? || token.to_s.match?(/last.?scan/i)
        return token.getutc if token.is_a?(Time)

        return Time.now.utc - 86_400 if token.to_s.match?(/yesterday/i)

        Time.parse(token.to_s).utc
      rescue ArgumentError
        Time.now.utc - 86_400
      end

      private_class_method def self.diff_inventories(opts = {})
        prev = index_inventory(hosts: opts[:previous])
        curr = index_inventory(hosts: opts[:current])
        added_ports = (curr[:ports].keys - prev[:ports].keys).map { |key| curr[:ports][key] }
        removed_ports = (prev[:ports].keys - curr[:ports].keys).map { |key| prev[:ports][key] }
        changed_scripts = []
        curr[:scripts].each do |key, now|
          was = prev[:scripts][key]
          next if was == now

          changed_scripts << { host: key[0], port: key[1], name: key[2], before: was, after: now }
        end
        {
          added_hosts: (curr[:hosts] - prev[:hosts]).to_a,
          removed_hosts: (prev[:hosts] - curr[:hosts]).to_a,
          added_ports: added_ports,
          removed_ports: removed_ports,
          changed_scripts: changed_scripts
        }
      end

      private_class_method def self.index_inventory(opts = {})
        hosts = []
        ports = {}
        scripts = {}
        Array(opts[:hosts]).each do |host|
          host = host.transform_keys(&:to_sym) if host.respond_to?(:transform_keys)
          ip = host[:host].to_s
          hosts << ip
          Array(host[:scripts]).each do |name, output|
            scripts[[ip, 0, name.to_s]] = output.to_s
          end
          Array(host[:ports]).each do |port|
            port = port.transform_keys(&:to_sym) if port.respond_to?(:transform_keys)
            key = [ip, port[:port], port[:proto].to_s]
            ports[key] = { host: ip, port: port[:port], proto: port[:proto], service: port[:service], version: port[:version] }
            Array(port[:scripts]).each do |name, output|
              scripts[[ip, port[:port], name.to_s]] = output.to_s
            end
          end
        end
        { hosts: hosts, ports: ports, scripts: scripts }
      end
    end
  end
end
