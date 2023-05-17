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

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

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

        when :put
          response = rest_client.execute(
            method: :put,
            url: "#{base_nessus_cloud_api_uri}/#{rest_call}",
            headers: {
              x_apikeys: "accessKey=#{access_key}; secretKey=#{secret_key}",
              accept: 'application/json',
              content_type: 'application/json; charset=UTF-8'
            },
            payload: http_body,
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
      rescue RestClient::ExceptionWithResponse => e
        puts "URI: #{base_nessus_cloud_api_uri}/#{rest_call}"
        puts "Params: #{params.inspect}"
        puts "HTTP POST Body: #{http_body}"

        raise e
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
          scan_templates = selected_scan_template.first
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
          policies = selected_policy.first
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
          folders = selected_folder.first
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
          scanners = selected_scanner.first
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
          target_networks = selected_network.first
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
          timezones = selected_timezone.first
          timezones ||= {}
        end

        timezones
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_target_groups(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of target group'
      # )
      # )

      public_class_method def self.get_target_groups(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        target_groups_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'target-groups'
        ).body

        target_groups = JSON.parse(target_groups_resp, symbolize_names: true)

        if name
          selected_target_group = target_groups[:target_groups].select do |tg|
            tg[:name] == name
          end
          target_groups = selected_target_group.first
          target_groups ||= {}
        end

        target_groups
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_tag_values(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of tag value'
      # )
      # )

      public_class_method def self.get_tag_values(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        tag_values_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'tags/values'
        ).body

        tag_values = JSON.parse(tag_values_resp, symbolize_names: true)

        if name
          selected_tag = tag_values[:values].select do |tag|
            tag[:value] == name
          end
          tag_values = selected_tag.first
          tag_values ||= {}
        end

        tag_values
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.get_assets(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   name: 'optional - name of asset'
      # )
      # )

      public_class_method def self.get_assets(opts = {})
        nessus_obj = opts[:nessus_obj]
        name = opts[:name]

        assets_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'assets'
        ).body

        assets = JSON.parse(assets_resp, symbolize_names: true)

        if name
          selected_asset = assets[:assets].select do |asset|
            asset[:fqdn] == name
          end
          assets = selected_asset.first
          assets ||= {}
        end

        assets
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.add_tag_to_assets(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   targets: 'required - comma-delimited list of targets to tag',
      #   tag_uuids: 'required - array of tag UUIDS to tag against targets'
      # )
      # )

      public_class_method def self.add_tag_to_assets(opts = {})
        nessus_obj = opts[:nessus_obj]
        targets = opts[:targets].to_s.split(',')
        tag_uuids = opts[:tag_uuids]

        all_assets = get_assets(nessus_obj: nessus_obj)

        asset_uuids_arr = []
        targets.each do |target|
          selected_asset = all_assets[:assets].select do |asset|
            asset[:fqdn] == [target]
          end
          this_asset = selected_asset.first
          target_uuid = this_asset[:id]

          asset_uuids_arr.push(target_uuid)
        end

        http_body = {
          action: 'add',
          assets: asset_uuids_arr,
          tags: tag_uuids
        }.to_json

        tag_assets_resp = nessus_cloud_rest_call(
          http_method: :post,
          nessus_obj: nessus_obj,
          rest_call: 'tags/assets/assignments',
          http_body: http_body
        ).body

        JSON.parse(tag_assets_resp, symbolize_names: true)
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
          credential_types = selected_credential_category.first
          credential_types ||= {}

          if name
            selected_credential_type = credential_types[:types].select do |ct|
              ct[:name].downcase == name
            end
            credential_types = selected_credential_type.first
            credential_types ||= {}
          end

        end

        credential_types
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
          scans = selected_scan.first
          scans ||= {}
        end

        scans
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
        scan_template_uuid = opts[:scan_template_uuid]
        settings = opts[:settings]
        credentials = opts[:credentials]
        plugins = opts[:plugins]

        http_body = {
          uuid: scan_template_uuid,
          settings: settings,
          credentials: credentials,
          plugins: plugins
        }.to_json

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
      # PWN::Plugins::NessusCloud.update_scan(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   scan_id: 'required - the scan id to update.  Run #get_scans for a list',
      #   scan_template_uuid: 'required - the UUID for the Tenable-provided scan template to use.  Run #get_canned_scan_templates for a list of UUIDs',
      #   settings: 'required - settings object as defined by https://developer.tenable.com/reference/scans-create',
      #   credentials: 'required - credentials object as defined by https://developer.tenable.com/reference/scans-create',
      #   plugins: 'optional - plugins object as defined by https://developer.tenable.com/reference/scans-create (Defaults to {})'
      # )

      public_class_method def self.update_scan(opts = {})
        nessus_obj = opts[:nessus_obj]
        scan_id = opts[:scan_id]
        scan_template_uuid = opts[:scan_template_uuid]
        settings = opts[:settings]
        credentials = opts[:credentials]
        plugins = opts[:plugins]

        http_body = {
          uuid: scan_template_uuid,
          settings: settings,
          credentials: credentials,
          plugins: plugins
        }.to_json

        update_scan_resp = nessus_cloud_rest_call(
          http_method: :put,
          nessus_obj: nessus_obj,
          rest_call: "scans/#{scan_id}",
          http_body: http_body
        ).body

        JSON.parse(update_scan_resp, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::NessusCloud.launch_scan(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   scan_id: 'required - scan uuid to launch'
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
      #   scan_id: 'required - scan uuid to retrieve status'
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
      # PWN::Plugins::NessusCloud.create_tag(
      #   nessus_obj: 'required - nessus_obj returned from #login method',
      #   category: 'required - category name to create or use',
      #   value: 'required - tag value name to create or use',
      #   desc: 'optional - tag value description'
      # )

      public_class_method def self.create_tag(opts = {})
        nessus_obj = opts[:nessus_obj]
        category = opts[:category]
        value = opts[:value]
        desc = opts[:desc]

        http_body = {
          category_name: category,
          value: value,
          description: desc
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
      #   scan_id: 'required - scan uuid to launch'
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
      #   scan_id: 'required - scan uuid to export',
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

          #{self}.get_target_groups(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of target group'
          )

          #{self}.get_tag_values(
            nessus_obj: 'required - nessus_obj returned from #login method',
            name: 'optional - name of tag value'
          )

          #{self}.get_scans(
            nessus_obj: 'required - nessus_obj returned from #login method'
          )

          #{self}.create_scan(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_template_uuid: 'required - the UUID for the Tenable-provided scan template to use.  Run #get_canned_scan_templates for a list of UUIDs',
            settings: 'required - settings object as defined by https://developer.tenable.com/reference/scans-create',
            credentials: 'required - credentials object as defined by https://developer.tenable.com/reference/scans-create',
            plugins: 'optional - plugins object as defined by https://developer.tenable.com/reference/scans-create (Defaults to {})'
          )

          #{self}.update_scan(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_id: 'required - the scan id to update.  Run #get_scans for a list',
            scan_template_uuid: 'required - the UUID for the Tenable-provided scan template to use.  Run #get_canned_scan_templates for a list of UUIDs',
            settings: 'required - settings object as defined by https://developer.tenable.com/reference/scans-create',
            credentials: 'required - credentials object as defined by https://developer.tenable.com/reference/scans-create',
            plugins: 'optional - plugins object as defined by https://developer.tenable.com/reference/scans-create (Defaults to {})'
          )

          #{self}.launch_scan(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_id: 'required - scan uuid to launch'
          )

          #{self}.get_scan_status(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_id: 'required - scan uuid to retrieve status'
          )

          #{self}.create_tag(
            nessus_obj: 'required - nessus_obj returned from #login method',
            category: 'required - category name to create or use',
            value: 'required - tag value name to create or use',
            desc: 'optional - tag value description'
          )

          #{self}.get_scan_history(
            nessus_obj: 'required - nessus_obj returned from #login method'
            scan_id: 'required - scan uuid to launch'
          )

          #{self}.export_scan_results(
            nessus_obj: 'required - nessus_obj returned from #login method',
            scan_id: 'required - scan uuid to export',
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
