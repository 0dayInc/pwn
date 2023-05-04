# frozen_string_literal: true

require 'nmap/command'
require 'nmap/xml'

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
      #   nmap.ports = [1..1024,1337]
      #   nmap.targets = '127.0.0.1'
      #   nmap.xml = '/tmp/nmap_port_scan_res.xml'
      # end

      public_class_method def self.port_scan
        Nmap::Command.sudo do |nmap|
          yield(nmap)
        end
      rescue StandardError => e
        raise e
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

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.port_scan do |nmap|
            puts nmap.public_methods
            nmap.connect_scan = true
            nmap.service_scan = true
            nmap.verbose = true
            nmap.ports = [1..1024,1337]
            nmap.targets = '127.0.0.1'
            nmap.xml = '/tmp/nmap_port_scan_res.xml'
          end

          #{self}.parse_xml_results(:xml_file => 'required - path to nmap xml results') do |xml|
            xml.each_host do |host|
              puts host.ip

              host.scripts.each do |name,output|
                output.each_line { |line| puts line }
              end

              host.each_port do |port|
                puts port

                port.scripts.each do |name,output|
                  puts name
                  output.each_line { |line| puts line }
                end
              end
            end
          end

          #{self}.authors
        "
      end
    end
  end
end
