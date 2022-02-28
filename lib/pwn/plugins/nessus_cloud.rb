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
      # PWN::Plugins::NessusCloud.list_scans(
      #   nessus_obj: 'required - nessus_obj returned from #login method'
      # )

      public_class_method def self.list_scans(opts = {})
        nessus_obj = opts[:nessus_obj]

        scans_resp = nessus_cloud_rest_call(
          nessus_obj: nessus_obj,
          rest_call: 'scans'
        ).body

        JSON.parse(scans_resp, symbolize_names: true)
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

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          nessus_obj = #{self}.login(
            access_key: 'required - API access key (will prompt if blank)',
            secret_key: 'required - API secret key (will prompt if blank)'
          )

          #{self}.list_scans(
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
