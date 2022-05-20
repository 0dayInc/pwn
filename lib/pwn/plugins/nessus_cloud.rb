# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # This plugin is used for interacting w/ the Tenable.io REST API (i.e. Nessus Cloud)
    module NessusCloud
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # nessus_cloud_rest_call(
      #   nessus_obj: 'required nessus_obj returned from #start method',
      #   rest_call: 'required rest call to make per the schema',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.nessus_cloud_rest_call(opts = {})
        nessus_obj = opts[:nessus_obj]
        rest_call = opts[:rest_call].to_s.scrub
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        access_key = nessus_obj[:access_key]
        secret_key = nessus_obj[:secret_key]
        base_nessus_cloud_api_uri = 'https://cloud.tenable.com'

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_nessus_cloud_api_uri}/#{rest_call}",
            headers: {
              x_apikeys: "accessKey=#{access_key}; secretKey=#{secret_key}",
              accept: 'application/json',
              content_type: 'application/json; charset=UTF-8',
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_nessus_cloud_api_uri}/#{rest_call}",
            headers: {
              x_apikeys: "accessKey=#{access_key}; secretKey=#{secret_key}",
              accept: 'application/json',
              content_type: 'application/json; charset=UTF-8'
            },
            payload: http_body,
            verify_ssl: false
          )

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end

        sleep 3

        response
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.login(
      #   access_key: 'required - API access key (will prompt if blank)',
      #   secret_key: 'required - API secret key (will prompt if blank)'
      # )

      public_class_method def self.login(opts = {})
        access_key = opts[:access_key]
        access_key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Access Key') if opts[:access_key].nil?

        secret_key = opts[:secret_key]
        secret_key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Secret Key') if opts[:secret_key].nil?

        nessus_obj = {}
        nessus_obj[:access_key] = access_key
        nessus_obj[:secret_key] = secret_key

        nessus_obj
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_canned_scan_templates(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of scan template'
      # )

      public_class_method def self.get_canned_scan_templates(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        scan_templates_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'editor/scan/templates'
        ).body

        scan_templates = JSON.parse(scan_templates_resp, symbolize_names: true)

        if name
          selected_scan_template = scan_templates[:templates].select do |sc|
            sc[:title] == name
          end
          scan_templates = selected_scan_template.first if selected_scan_template.any?
          scan_templates ||= {}
        end

        scan_templates
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_policies(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of policy (i.e. user-defined template)'
      # )

      public_class_method def self.get_policies(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        policies_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'policies'
        ).body

        policies = JSON.parse(policies_resp, symbolize_names: true)

        if name
          selected_policy = policies[:policies].select do |p|
            p[:name] == name
          end
          policies = selected_policy.first if selected_policy.any?
          policies ||= {}
        end

        policies
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_folders(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of folder'
      # )

      public_class_method def self.get_folders(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        folders_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'folders'
        ).body

        folders = JSON.parse(folders_resp, symbolize_names: true)

        if name
          selected_folder = folders[:folders].select do |f|
            f[:name] == name
          end
          folders = selected_folder.first if selected_folder.any?
          folders ||= {}
        end

        folders
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_scanners(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of scanner'
      # )

      public_class_method def self.get_scanners(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        scanners_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'scanners'
        ).body

        scanners = JSON.parse(scanners_resp, symbolize_names: true)

        if name
          selected_scanner = scanners[:scanners].select do |s|
            s[:name] == name
          end
          scanners = selected_scanner.first if selected_scanner.any?
          scanners ||= {}
        end

        scanners
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_target_networks(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of target network'
      # )

      public_class_method def self.get_target_networks(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        target_networks_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'networks'
        ).body

        target_networks = JSON.parse(target_networks_resp, symbolize_names: true)

        if name
          selected_network = target_networks[:networks].select do |tn|
            tn[:name] == name
          end
          target_networks = selected_network.first if selected_network.any?
          target_networks ||= {}
        end

        target_networks
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_timezones(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of timezone'
      # )

      public_class_method def self.get_timezones(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        timezones_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'scans/timezones'
        ).body

        timezones = JSON.parse(timezones_resp, symbolize_names: true)

        if name
          selected_timezone = timezones[:networks].select do |tz|
            tz[:name] == name
          end
          timezones = selected_timezone.first if selected_timezone.any?
          timezones ||= {}
        end

        timezones
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_target_groups(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of timezone'
      # )
      # )

      public_class_method def self.get_target_groups(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        target_groups_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'target-groups'
        ).body

        timezones = JSON.parse(target_groups_resp, symbolize_names: true)

        if name
          selected_timezone = timezones[:networks].select do |tz|
            tz[:name] == name
          end
          timezones = selected_timezone.first if selected_timezone.any?
          timezones ||= {}
        end

        timezones
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_credential_types(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   category: 'optional - category of credential type (Defaults to "Host")',
      #   name: 'optional - name of credential type (Defaults to "SSH")'
      # )
      # )

      public_class_method def self.get_credential_types(opts = {})
        nessus_obj = opts[:nessus_obj]
        category = opts[:category].to_s.downcase
        name = opts[:name].to_s.downcase

        raise 'ERROR: name parameter requires category parameter.' if category.empty? && !name.empty?

        credential_types_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'credentials/types'
        ).body

        credential_types = JSON.parse(credential_types_resp, symbolize_names: true)

        if category
          selected_credential_category = credential_types[:credentials].select do |cc|
            cc[:category].downcase == category
          end
          credential_types = selected_credential_category.first if selected_credential_category.any?
          credential_types ||= {}

          if name
            selected_credential_type = credential_types[:types].select do |ct|
              ct[:name].downcase == name
            end
            credential_types = selected_credential_type.first if selected_credential_type.any?
            credential_types ||= {}
          end

        end

        credential_types
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.create_scan(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   scan_template_uuid: 'required - the UUID for the Tenable-provided scan template to use.  Run #get_canned_scan_templates for a list of UUIDs',
      #   settings: 'required - settings object as defined by https://developer.tenable.com/reference/scans-create',
      #   credentials: 'required - credentials object as defined by https://developer.tenable.com/reference/scans-create',
      #   plugins: 'optional - plugins object as defined by https://developer.tenable.com/reference/scans-create (Defaults to {})'
      # )

      public_class_method def self.create_scan(opts = {})
        nessus_obj = opts[:nessus_obj]

        http_body = {}
        http_body[:uuid] = opts[:scan_template_uuid]
        http_body[:settings] = opts[:settings]
        http_body[:credentials] = opts[:credentials]
        http_body[:plugins] = opts[:plugins]

        create_scan_resp = nessus_cloud_rest_call(
          http_method: :post,
          nessus_obj: nessus_obj,
          rest_call: 'scans',
          http_body: http_body
        ).body

        JSON.parse(create_scan_resp, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_scans(
      #   nessus_obj: 'required - nessus_obj returned from #login method'
      # )

      public_class_method def self.get_scans(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        scans_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'scans'
        ).body

        scans = JSON.parse(scans_resp, symbolize_names: true)

        if name
          selected_scan = scans[:scans].select do |s|
            s[:name] == name
          end
          scans = selected_scan.first if selected_scan.any?
          scans ||= {}
        end

        scans
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.launch_scan(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   scan_id: 'required - scan id to launch'
      # )

      public_class_method def self.launch_scan(opts = {})
        nessus_obj = opts[:nessus_obj]
        scan_id = opts[:scan_id]

        launch_scan_resp = nessus_cloud_rest_call(
          http_method: :post,
          nessus_obj: nessus_obj,
          rest_call: "scans/#{scan_id}/launch"
        ).body

        JSON.parse(launch_scan_resp, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_scan_status(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   scan_id: 'required - scan id to retrieve status'
      # )

      public_class_method def self.get_scan_status(opts = {})
        nessus_obj = opts[:nessus_obj]
        scan_id = opts[:scan_id]

        scan_status_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: "scans/#{scan_id}/latest-status"
        ).body

        JSON.parse(scan_status_resp, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.tag(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   category: 'required - category name to create or use',
      #   value: 'required - value name to create or use',
      #   desc: 'optional - _value_ description'
      # )

      public_class_method def self.tag(opts = {})
        nessus_obj = opts[:nessus_obj]
        category = opts[:category]
        value = opts[:value]
        desc = opts[:desc]

        http_body = {
          category_name: category,
          value: value
        }.to_json

        tag_resp = nessus_cloud_rest_call(
          http_method: :post,
          nessus_obj: nessus_obj,
          rest_call: 'tags/values',
          http_body: http_body
        ).body

        JSON.parse(tag_resp, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_scan_history(
      #   nessus_obj: 'required - nessus_obj returned from #login method'
      #   scan_id: 'required - scan id to launch'
      # )

      public_class_method def self.get_scan_history(opts = {})
        nessus_obj = opts[:nessus_obj]
        scan_id = opts[:scan_id]

        scan_hist_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: "scans/#{scan_id}/history"
        ).body

        JSON.parse(scan_hist_resp, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.export_scan_results(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   scan_id: 'required - scan id to export',
      #   path_to_export: 'required - filename to export results',
      #   history_id: 'optional - defaults to last scan',
      #   format: 'optional - :csv|:db|:html|:nessus|:pdf (defaults to :csv')
      # )

      public_class_method def self.export_scan_results(opts = {})
        nessus_obj = opts[:nessus_obj]
        scan_id = opts[:scan_id]
        path_to_export = opts[:path_to_export]
        if opts[:history_id]
          history_id = opts[:history_id]
        else
          scan_history_resp = get_scan_history(
            nessus_obj: nessus_obj,
            scan_id: scan_id
          )

          if scan_history_resp[:history].empty?
            puts 'No scan history found.'
            raise 'Has at least one scan completed?'
          else
            history_id = scan_history_resp[:history].last[:id]
          end
        end

        format = :csv
        format = opts[:format].to_s.to_sym if opts[:format]

        http_body = {
          scan_id: scan_id,
          history_id: history_id,
          format: format
        }.to_json

        export_scan_resp = nessus_cloud_rest_call(
          http_method: :post,
          nessus_obj: nessus_obj,
          rest_call: "scans/#{scan_id}/export",
          http_body: http_body
        ).body

        file_id = JSON.parse(
          export_scan_resp,
          symbolize_names: true
        )[:file]

        download_export_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: "scans/#{scan_id}/export/#{file_id}/download"
        ).body

        File.open(path_to_export, 'wb') do |f|
          f.puts download_export_resp
        end

        path_to_export
      rescue StandardError, SystemExit, Interrupt => e
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
          nessus_obj = #{self}.login(
            access_key: 'required - API access key (will prompt if blank)',
            secret_key: 'required - API secret key (will prompt if blank)'
          )

          #{self}.get_canned_scan_templates(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of scan template'
          )

          #{self}.get_policies(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of policy (i.e. user-defined template)'
          )

          #{self}.get_folders(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of folder'
          )

          #{self}.get_scanners(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of scanner'
          )

          #{self}.get_target_networks(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of target network'
          )

          #{self}.get_timezones(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of timezone'
          )

          #{self}.get_scans(
            nessus_obj: 'required - nessus_obj returned from #login method'
          )

          #{self}.launch_scan(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_id: 'required - scan id to launch'
          )

          #{self}.get_scan_status(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_id: 'required - scan id to retrieve status'
          )

          #{self}.tag(
            nessus_obj: 'required - nessus_obj returned from #login method',
            category: 'required - category name to create or use',
            value: 'required - value name to create or use',
            desc: 'optional - _value_ description'
          )

          #{self}.get_scan_history(
            nessus_obj: 'required - nessus_obj returned from #login method'
            scan_id: 'required - scan id to launch'
          )

          #{self}.export_scan_results(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_id: 'required - scan id to export',
            path_to_export: 'required - filename to export results',
            history_id: 'optional - defaults to last scan',
            format: 'optional - :csv|:db|:html|:nessus|:pdf (defaults to :csv')
          )

          #{self}.authors
        "
      end
    end
  end
end
