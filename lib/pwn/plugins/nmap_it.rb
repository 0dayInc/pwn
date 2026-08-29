# frozen_string_literal: true

require 'nmap/command'
require 'nmap/xml'
require 'open3'

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

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
