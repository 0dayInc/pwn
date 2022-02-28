# frozen_string_literal: true

require 'nexpose'
require 'ipaddr'

module PWN
  module Plugins
    # This plugin is used for interacting w/ Nexpose using the Nexpose API.
    module NexposeVulnScan
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.login(
      #   console_ip: 'required host/ip of Nexpose Console (server)',
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.login(opts = {})
        console_ip = opts[:console_ip]
        username = opts[:username].to_s

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s
                   end

        nsc_obj = Nexpose::Connection.new(console_ip, username, password)
        nsc_obj.login
        config = Nexpose::Console.load(nsc_obj)
        config.session_timeout = 21_600
        # config.save(nsc_obj) # This will change the global sesion timeout config in the console
        nsc_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.list_all_individual_site_assets(
      #  nsc_obj: 'required nsc_obj returned from login method',
      #  site_name: 'required Nexpose site name to update (case-sensitive)'
      # )

      public_class_method def self.list_all_individual_site_assets(opts = {})
        nsc_obj = opts[:nsc_obj]
        site_name = opts[:site_name]

        site_id = -1
        nsc_obj.list_sites.each do |site|
          site_id = site.id if site.name == site_name
        end

        all_individual_site_assets_arr = []
        if site_id > -1
          @@logger.info("Listing All Assets from #{site_name} (site id: #{site_id}):")
          nsc_obj.filter(Nexpose::Search::Field::SITE_ID, Nexpose::Search::Operator::IN, site_id).each do |asset|
            @@logger.info("#{asset.id}|#{asset.ip}|#{asset.last_scan}")
            all_individual_site_assets_arr.push(asset.ip)
          end
        else
          @@logger.error("Site: #{site_name} Not Found.  Please check the spelling and try again.")
        end

        all_individual_site_assets_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.update_site_assets(
      #  nsc_obj: 'required nsc_obj returned from login method',
      #  site_name: 'required Nexpose site name to update (case-sensitive),
      #  assets: 'required array of hashes containing called :ip => values being IP address (All IPs not included in the :assets parameter will be removed from Nexpose)'
      # )

      public_class_method def self.update_site_assets(opts = {})
        nsc_obj = opts[:nsc_obj]
        site_name = opts[:site_name]
        assets = opts[:assets]

        nsc_obj.list_sites.each do |site|
          next unless site.name == site_name

          # Load Site
          site_id = site.id
          refresh_site = Nexpose::Site.load(nsc_obj, site_id)

          # Obtain Current List of Assets for Given Site & Remove Old List of Assets from Given Site (if applicable)
          @@logger.info('Removing the Following Assets:')
          current_site_assets = nsc_obj.filter(Nexpose::Search::Field::SITE_ID, Nexpose::Search::Operator::IN, site_id)
          new_site_assets = []
          assets.each { |ip_host_hash| new_site_assets.push(ip_host_hash[:ip].to_s.scrub.strip.chomp) }
          current_site_assets.each do |current_site_asset|
            next if new_site_assets.include?(current_site_asset.ip)

            @@logger.info("Removing #{current_site_asset.ip}")
            # refresh_site.remove_included_asset(current_asset) # This should work and be less invasive but no worky :(
            nsc_obj.delete_asset(current_site_asset.id) # So we completely remove the asset from Nexpose altogether :/
          end
          @@logger.info('Complete.')

          # Add New List of Assets to Given Site
          @@logger.info("Adding the Following Assets to #{site.name} (site id: #{site_id}):")
          assets.each do |ip_host_hash|
            current_ip = IPAddr.new(ip_host_hash[:ip].to_s.scrub.strip.chomp)
            unless current_ip.to_s.match?('255') # || current_ip =~ /^[224-239]/ # Multicast?
              # TODO: try to reverse DNS word to see if an IP s available as well
              @@logger.info("Adding #{current_ip}")
              refresh_site.include_asset(current_ip)
            end
          rescue StandardError
            next
          end
          refresh_site.save(nsc_obj)
          @@logger.info('Complete.')
        end

        nsc_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.delete_site_assets_older_than(
      #  nsc_obj: 'required nsc_obj returned from login method',
      #  site_name: 'required Nexpose site name to update (case-sensitive),
      #  days: 'required assets to remove older than number of days in this parameter'
      # )

      public_class_method def self.delete_site_assets_older_than(opts = {})
        nsc_obj = opts[:nsc_obj]
        site_name = opts[:site_name]
        days = opts[:days].to_i

        site_id = -1
        nsc_obj.list_sites.each do |site|
          site_id = site.id if site.name == site_name
        end

        if site_id > -1
          @@logger.info("Removing the Following Assets from #{site.name} (site id: #{site_id}) Older than #{days} Days:")
          nsc_obj.filter(Nexpose::Search::Field::SCAN_DATE, Nexpose::Search::Operator::EARLIER_THAN, days).each do |asset|
            if asset.site_id == site_id
              @@logger.info("#{asset.id}|#{asset.ip}|#{asset.last_scan}")
              nsc_obj.delete_asset(asset.id)
            end
          end
        else
          @@logger.error("Site: #{site_name} Not Found.  Please check the spelling and try again.")
        end

        nsc_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.scan_site_by_name(
      #  nsc_obj: 'required nsc_obj returned from login method',
      #  site_name: 'required Nexpose site name to scan (case-sensitive),
      #  poll_interval: 'optional poll interval to check the completion status of the scan (defaults to 3 minutes)
      # )

      public_class_method def self.scan_site_by_name(opts = {})
        nsc_obj = opts[:nsc_obj]
        site_name = opts[:site_name].to_s
        site_id = nil

        poll_interval = if opts[:poll_interval].nil?
                          60
                        else
                          opts[:poll_interval].to_i
                        end

        # Find the site and kick off the scan
        nsc_obj.list_sites.each do |site|
          next unless site.name == site_name

          nsc_obj.scan_site(site.id)
          @@logger.info("Scan Started for #{site_name} @ #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}")
          site_id = site.id
        end

        # Periodically check the status of the scan
        raise @logger.error("Site name: #{site_name} does not exist as a site in Nexpose.  Please check your spelling and try again.") if site_id == ''

        @@logger.info("Info: Checking status for an interval of #{poll_interval} seconds until completion.")
        loop do
          scan_status = nil
          nsc_obj.scan_activity.each { |scan| scan_status = scan.status if scan.site_id == site_id }
          if scan_status == 'running'
            print '~' # Seeing progress is good :)
            sleep poll_interval # Sleep and check the status again...
          else
            @@logger.info("Scan Completed for #{site_name} @ #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}")
            break
          end
        end

        nsc_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.generate_report_via_existing_config(
      #   nsc_obj: 'required nsc_obj returned from login method',
      #   config_id: 'relevant r.config_id returned when invoking the block nsc_obj.reports.each {|r| puts "#{r.name} => #{r.config_id}"}',
      # )

      public_class_method def self.generate_report_via_existing_config(opts = {})
        nsc_obj = opts[:nsc_obj]
        config_id = opts[:config_id].to_i

        existing_report_config = Nexpose::ReportConfig.load(nsc_obj, config_id)
        existing_report_config.generate(nsc_obj)

        nsc_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.download_recurring_report(
      #   nsc_obj: 'required nsc_obj returned from login method',
      #   report_names: 'required array of report name/types to generate e.g. ["report.html", "report.pdf", "report.xml"]',
      #   poll_interval: 'optional poll interval to check the completion status of report generation (defaults to 60 seconds)
      # )

      public_class_method def self.download_recurring_report(opts = {})
        nsc_obj = opts[:nsc_obj]
        report_names = opts[:report_names].to_s.scrub.split(',')
        @@logger.info("Generating #{report_names.count} Report(s): #{report_names.inspect}...")

        poll_interval = if opts[:poll_interval].nil?
                          60
                        else
                          opts[:poll_interval].to_i
                        end

        report_arr = []
        report_status_arr = []
        until report_status_arr.count == report_names.count
          nsc_obj.reports.each do |report|
            report_names.each do |requested_report|
              this_report_name = requested_report.to_s.strip.chomp.delete('"')
              next unless report.name == this_report_name

              @@logger.info("Generating Recurring Report: #{report.name} @ #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}..Current Report Status: #{report.status}")
              if report.status == 'Failed'
                @@logger.info("Report Generation for #{report.name} failed...re-generating now...")
                # Re-generate report from pre-existing config.
                nsc_obj = generate_report_via_existing_config(nsc_obj: nsc_obj, config_id: report.config_id)
              end

              report_hash = {}
              report_hash[:report_name] = report.name
              report_hash[:report_status] = report.status
              report_hash[:report_uri] = report.uri
              report_arr.push(report_hash)
              report_status_arr = report_arr.uniq.select { |this_report| this_report[:report_status] == 'Generated' }
            end
          end
          # TODO: Ensure report_names are available within nsc_obj.reports (thus making it worthwhile to loop vs saying report !found).
          @@logger.info("Total Reports Generated So Far: #{report_status_arr.count}...")
          sleep poll_interval # Sleep and check the status again...
        end

        # @@logger.info(report_arr.inspect)
        # @@logger.info(report_status_arr.inspect)
        report_status_arr.each do |report_hash|
          this_file_extention = File.extname(report_hash[:report_uri])
          @@logger.info("\nDownloading #{report_hash[:report_name]}#{this_file_extention} from #{report_hash[:report_uri]}...")
          nsc_obj.download(report_hash[:report_uri], "#{report_hash[:report_name]}#{this_file_extention}")
        end
        @@logger.info('complete.')

        nsc_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NexposeVulnScan.logout(
      #   nsc_obj: 'required nsc_obj returned from login method'
      # )

      public_class_method def self.logout(opts = {})
        nsc_obj = opts[:nsc_obj]

        # config = Nexpose::Console.load(nsc_obj)
        # config.session_timeout = 600 # This is the default session timeout in the console
        # config.save(nsc_obj) # This will change the global sesion timeout config in the console
        nsc_obj.logout
        'logged out'
      rescue StandardError => e
        raise e
      end

      # Author(s):: Jacob Hoopes <jake.hoopes@gmail.com>

      public_class_method def self.authors
        "AUTHOR(S):
          Jacob Hoopes <jake.hoopes@gmail.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          nsc_obj = #{self}.login(
            console_ip: 'required host/ip of Nexpose Console (server)',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )
          puts nsc_obj.public_methods

          all_individual_site_assets_arr = #{self}.list_all_individual_site_assets(
            nsc_obj: 'required nsc_obj returned from login method',
            site_name: 'required Nexpose site name to update (case-sensitive)'
          )

          nsc_obj = #{self}.update_site_assets(
            nsc_obj: 'required nsc_obj returned from login method',
            site_name: 'required Nexpose site name to update (case-sensitive),
            assets: 'required array of hashes containing called :ip => values being IP address (All IPs not included in the :assets parameter will be removed from Nexpose)'
          )

          nsc_obj = #{self}.delete_site_assets_older_than(
            nsc_obj: 'required nsc_obj returned from login method',
            site_name: 'required Nexpose site name to update (case-sensitive),
            days: 'required assets to remove older than number of days in this parameter'
          )

          nsc_obj = #{self}.scan_site_by_name(
            nsc_obj: 'required nsc_obj returned from login method',
            site_name: 'required Nexpose site name to scan (case-sensitive),
            poll_interval: 'optional poll interval to check the completion status of the scan (defaults to 60 seconds)
          )

          #{self}.download_recurring_report(
            nsc_obj: 'required nsc_obj returned from login method',
            report_names: 'required array of report name/types to generate e.g. ['report.html', 'report.pdf', 'report.xml']',
            poll_interval: 'optional poll interval to check the completion status of report generation (defaults to 60 seconds)
          )

          #{self}.logout(nsc_obj: 'required nsc_obj returned from login method')

          #{self}.authors
        "
      end
    end
  end
end
