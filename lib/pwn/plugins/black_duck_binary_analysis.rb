# frozen_string_literal: true

require 'cgi'
require 'json'
require 'securerandom'
require 'tty-spinner'

module PWN
  module Plugins
    # This plugin is used for interacting w/ the Black Duck Binary Analysis
    # REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    # This is based on the following Black Duck Binary Analysis API Specification:
    # https://protecode-sc.com/help/api
    module BlackDuckBinaryAnalysis
      # Supported Method Parameters::
      # bd_bin_analysis_rest_call(
      #   token: 'required - Black Duck Binary Analysis API token',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_headers: 'optional HTTP headers sent in HTTP methods that support it e.g. POST'
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.bd_bin_analysis_rest_call(opts = {})
        token = opts[:token]
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]

        headers = opts[:http_headers]
        headers ||= {
          content_type: 'application/json; charset=UTF-8',
          authorization: "Bearer #{token}"
        }

        http_body = opts[:http_body]
        base_bd_bin_analysis_api_uri = 'https://protecode-sc.com/api'

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        spinner = TTY::Spinner.new
        spinner.auto_spin

        max_request_attempts = 3
        tot_request_attempts ||= 1

        case http_method
        when :delete, :get
          headers[:params] = params
          response = rest_client.execute(
            method: http_method,
            url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
            headers: headers,
            verify_ssl: false,
            timeout: 5400
          )

        when :post, :put
          if http_body.is_a?(Hash)
            if http_body.key?(:raw)
              headers[:content_type] = nil
              http_body = http_body[:file]
            elsif http_body.key?(:multipart)
              headers[:content_type] = 'multipart/form-data'
            else
              http_body = http_body.to_json
            end
          end

          response = rest_client.execute(
            method: http_method,
            url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
            headers: headers,
            payload: http_body,
            verify_ssl: false,
            timeout: 5400
          )
        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
        response
      rescue RestClient::ExceptionWithResponse => e
        if e.response
          puts "HTTP RESPONSE CODE: #{e.response.code}"
          puts "HTTP RESPONSE HEADERS:\n#{e.response.headers}"
          puts "HTTP RESPONSE BODY:\n#{e.response.body.inspect}\n\n\n"
        end

        raise e
      rescue IO::TimeoutError => e
        raise e if tot_request_attempts == max_request_attempts

        puts "\nTCP Connection Unavailable."
        puts "Attempt (#{tot_request_attempts} of #{max_request_attempts}) in 60s"
        60.downto(1) do
          print '.'
          sleep 1
        end
        tot_request_attempts += 1

        retry
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      ensure
        spinner.stop unless spinner.nil?
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_apps(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_apps(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'apps'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_apps_by_group(
      #   token: 'required - Bearer token',
      #   group_id: 'required - group id'
      # )

      public_class_method def self.get_apps_by_group(opts = {})
        token = opts[:token]
        group_id = opts[:group_id]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: "apps/#{group_id}"
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.upload_file(
      #   token: 'required - Bearer token',
      #   file: 'required - path of file to upload',
      #   group_id: 'optional - group id',
      #   delete_binary: 'optional - delete binary after upload (defaults to false)',
      #   force_scan: 'optional - force scan (defaults to false)',
      #   callback_url: 'optional - callback url',
      #   scan_infoleak: 'optional - scan infoleak (defaults to true)',
      #   code_analysis: 'optional - code analysis (defaults to true)',
      #   scan_code_familiarity: 'optional - scan code familiarity (defaults to false)',
      #   version: 'optional - version',
      #   product_id: 'optional - product id'
      # )

      public_class_method def self.upload_file(opts = {})
        token = opts[:token]
        file = opts[:file]
        raise "ERROR: #{file} not found." unless File.exist?(file)

        file_name = File.basename(file)

        group_id = opts[:group_id]
        delete_binary = true if opts[:delete_binary] ||= false
        force_scan = true if opts[:force_scan] ||= false
        callback_url = opts[:callback_url]
        scan_infoleak = false if opts[:scan_infoleak] ||= true
        code_analysis = false if opts[:code_analysis] ||= true
        scan_code_familiarity = false if opts[:scan_code_familiarity] ||= false
        version = opts[:version]
        product_id = opts[:product_id]

        http_headers = {
          authorization: "Bearer #{token}",
          delete_binary: delete_binary,
          force_scan: force_scan,
          group: group_id,
          callback: callback_url,
          scan_infoleak: scan_infoleak,
          code_analysis: code_analysis,
          scan_code_familiarity: scan_code_familiarity,
          version: version,
          replace: product_id
        }

        # http_body = {
        #   multipart: true,
        #   file: File.new(file, 'rb')
        # }

        http_body = {
          raw: true,
          file: File.binread(file)
        }

        response = bd_bin_analysis_rest_call(
          http_method: :put,
          token: token,
          rest_call: "upload/#{CGI.escape_uri_component(file_name)}",
          http_headers: http_headers,
          http_body: http_body
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_product(
      #   token: 'required - Bearer token',
      #   product_id: 'required - product id'
      # )

      public_class_method def self.get_product(opts = {})
        token = opts[:token]
        product_id = opts[:product_id]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: "product/#{product_id}"
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.abort_product_scan(
      #   token: 'required - Bearer token',
      #   product_id: 'required - product id'
      # )

      public_class_method def self.abort_product_scan(opts = {})
        token = opts[:token]
        product_id = opts[:product_id]

        response = bd_bin_analysis_rest_call(
          http_method: :post,
          token: token,
          rest_call: "product/#{product_id}/abort"
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.generate_product_report(
      #   token: 'required - Bearer token',
      #   product_id: 'required - product id',
      #   output_path: 'required - path to output file',
      #   type: 'optional - report type csv_libs||csv_vulns|pdf (Defaults to csv_vulns)'
      # )

      public_class_method def self.generate_product_report(opts = {})
        token = opts[:token]
        product_id = opts[:product_id]
        output_path = opts[:output_path]
        type = opts[:type] ||= :csv_vulns

        case type.to_s.downcase.to_sym
        when :csv_libs
          rest_call = "product/#{product_id}/csv-libs"
        when :csv_vulns
          rest_call = "product/#{product_id}/csv-vulns"
        when :pdf
          rest_call = "product/#{product_id}/pdf-report"
        else
          raise "ERROR: Invalid report type #{type}"
        end

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: rest_call
        )

        File.write(output_path, response.body)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_tasks(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_tasks(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'tasks'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_groups(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_groups(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'groups'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.create_group(
      #   token: 'required - Bearer token',
      #   name: 'required - group name',
      #   desc: 'optional - group description',
      #   parent_id: 'optional - parent group id',
      #   delete_binary: 'optional - delete binary after analysis C|Y|N (Default: C== company default)',
      #   binary_cleanup_age: 'optional - after how long the binary will be deleted in seconds (Default: 2_592_000 / 30 days)',
      #   product_cleanup_age: 'optional - after how long the product will be deleted in seconds (Default: 2_592_000 / 30 days)',
      #   file_download_enabled: 'optional - allow download of uploaded binaries from group (Default: false),
      #   low_risk_tolerance: 'optional - low risk tolerance nil|true|false (Default: nil == company default)',
      #   include_historical_vulns: 'optional - include historical vulns nil|true|false (Default: nil == company default)',
      #   cvss3_fallback: 'optional - cvss3 fallback nil|true|false (Default: nil == company default)',
      #   assume_unknown_version_as_latest: 'optional - assume unknown version as latest nil|true|false (Default: nil == company default)',
      #   custom_data: 'optional - custom data hash (Default: {}, see group metadata for details)',
      #   scan_infoleak: 'optional - scan infoleak nil|true|false (Default: nil == company default)',
      #   code_analysis: 'optional - code analysis nil|true|false (Default: nil == company default)',
      #   scan_code_similarity: 'optional - scan code similarity nil|true|false (Default: nil == company default)'
      # )

      public_class_method def self.create_group(opts = {})
        token = opts[:token]
        name = opts[:name]
        desc = opts[:desc]
        parent_id = opts[:parent_id]
        delete_binary = opts[:delete_binary] ||= 'C'
        binary_cleanup_age = opts[:binary_cleanup_age] ||= 2_592_000
        product_cleanup_age = opts[:product_cleanup_age] ||= 2_592_000
        file_download_enabled = opts[:file_download_enabled] ||= false
        low_risk_tolerance = opts[:low_risk_tolerance]
        include_historical_vulns = opts[:include_historical_vulns]
        cvss3_fallback = opts[:cvss3_fallback]
        assume_unknown_version_as_latest = opts[:assume_unknown_version_as_latest]
        custom_data = opts[:custom_data] ||= {}
        scan_infoleak = opts[:scan_infoleak]
        code_analysis = opts[:code_analysis]
        scan_code_similarity = opts[:scan_code_similarity]

        http_headers = {
          authorization: "Bearer #{token}",
          name: name,
          description: desc,
          parent: parent_id,
          delete_binary_after_scan: delete_binary,
          binary_cleanup_age: binary_cleanup_age,
          product_cleanup_age: product_cleanup_age,
          file_download_enabled: file_download_enabled,
          low_risk_tolerance: low_risk_tolerance,
          include_historical_vulnerabilities: include_historical_vulns,
          cvss3_fallback: cvss3_fallback,
          assume_unknown_version_as_latest: assume_unknown_version_as_latest,
          custom_data: custom_data,
          scan_infoleak: scan_infoleak,
          code_analysis: code_analysis,
          scan_code_similarity: scan_code_similarity
        }

        response = bd_bin_analysis_rest_call(
          http_method: :post,
          token: token,
          rest_call: 'groups',
          http_headers: http_headers
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_group_details(
      #   token: 'required - Bearer token',
      #   group_id: 'required - group id'
      # )

      public_class_method def self.get_group_details(opts = {})
        token = opts[:token]
        group_id = opts[:group_id]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: "groups/#{group_id}"
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_group_statistics(
      #   token: 'required - Bearer token',
      #   group_id: 'required - group id'
      # )

      public_class_method def self.get_group_statistics(opts = {})
        token = opts[:token]
        group_id = opts[:group_id]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: "groups/#{group_id}/statistics"
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.delete_group(
      #   token: 'required - Bearer token',
      #   group_id: 'required - group id'
      # )

      public_class_method def self.delete_group(opts = {})
        token = opts[:token]
        group_id = opts[:group_id]

        response = bd_bin_analysis_rest_call(
          http_method: :delete,
          token: token,
          rest_call: "groups/#{group_id}"
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_licenses(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_licenses(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'licenses'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_component_licenses(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_component_licenses(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'component-licenses'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_tags(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_tags(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'tags'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_vulnerabilities(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_vulnerabilities(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'vulnerabilities'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_components(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_components(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'components'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_vendor_vulns(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_vendor_vulns(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'teacher/api/vulns'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_audit_trail(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_audit_trail(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'audit-trail'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_status(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_status(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'status'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_service_info(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_service_info(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'service/info'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_service_version(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_service_version(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'service/version'
        )

        JSON.parse(response, symbolize_names: true)
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
          response = #{self}.get_apps(
            token: 'required - Bearer token'
          )

          response = PWN::Plugins::BlackDuckBinaryAnalysis.upload_file(
            token: 'required - Bearer token',
            file: 'required - path of file to upload',
            group_id: 'optional - group id',
            delete_binary: 'optional - delete binary after upload (defaults to false)',
            force_scan: 'optional - force scan (defaults to false)',
            callback_url: 'optional - callback url',
            scan_infoleak: 'optional - scan infoleak (defaults to true)',
            code_analysis: 'optional - code analysis (defaults to true)',
            scan_code_familiarity: 'optional - scan code familiarity (defaults to true)',
            version: 'optional - version',
            product_id: 'optional - product id'
          )

          response = #{self}.get_product(
            token: 'required - Bearer token',
            product_id: 'required - product id'
          )

          response = #{self}.abort_product_scan(
            token: 'required - Bearer token',
            product_id: 'required - product id'
          )

          response = #{self}.generate_product_report(
            token: 'required - Bearer token',
            product_id: 'required - product id',
            output_path: 'required - path to output file',
            type: 'optional - report type csv_libs||csv_vulns|pdf (Defaults to csv_vulns)'
          )

          response = #{self}.get_tasks(
            token: 'required - Bearer token'
          )

          response = #{self}.get_apps_by_group(
            token: 'required - Bearer token',
            group_id: 'required - group id'
          )

          response = #{self}.get_groups(
            token: 'required - Bearer token'
          )

          response = #{self}.create_group(
            token: 'required - Bearer token',
            name: 'required - group name',
            desc: 'optional - group description',
            parent_id: 'optional - parent_id group id',
            delete_binary: 'optional - delete binary after analysis C|Y|N (Default: C== company default)',
            binary_cleanup_age: 'optional - after how long the binary will be deleted in seconds (Default: 2_592_000 / 30 days)',
            product_cleanup_age: 'optional - after how long the product will be deleted in seconds (Default: 2_592_000 / 30 days)',
            file_download_enabled: 'optional - allow download of uploaded binaries from group (Default: false),
            low_risk_tolerance: 'optional - low risk tolerance nil|true|false (Default: nil == company default)',
            include_historical_vulns: 'optional - include historical vulns nil|true|false (Default: nil == company default)',
            cvss3_fallback: 'optional - cvss3 fallback nil|true|false (Default: nil == company default)',
            assume_unknown_version_as_latest: 'optional - assume unknown version as latest nil|true|false (Default: nil == company default)',
            custom_data: 'optional - custom data hash (Default: {}, see group metadata for details)',
            scan_infoleak: 'optional - scan infoleak nil|true|false (Default: nil == company default)',
            code_analysis: 'optional - code analysis nil|true|false (Default: nil == company default)',
            scan_code_similarity: 'optional - scan code similarity nil|true|false (Default: nil == company default)'
          )

          response = #{self}.get_group_details(
            token: 'required - Bearer token',
            group_id: 'required - group id'
          )

          response = #{self}.get_group_statistics(
            token: 'required - Bearer token',
            group_id: 'required - group id'
          )

          response = #{self}.delete_group(
            token: 'required - Bearer token',
            group_id: 'required - group id'
          )

          response = #{self}.get_licenses(
            token: 'required - Bearer token'
          )

          response = #{self}.get_component_licenses(
            token: 'required - Bearer token'
          )

          response = #{self}.get_tags(
            token: 'required - Bearer token'
          )

          response = #{self}.get_vulnerabilities(
            token: 'required - Bearer token'
          )

          response = #{self}.get_components(
            token: 'required - Bearer token'
          )

          response = #{self}.get_vendor_vulns(
            token: 'required - Bearer token'
          )

          response = #{self}.get_audit_trail(
            token: 'required - Bearer token'
          )

          response = #{self}.get_status(
            token: 'required - Bearer token'
          )

          response = #{self}.get_service_info(
            token: 'required - Bearer token'
          )

          response = #{self}.get_service_version(
            token: 'required - Bearer token'
          )

          #{self}.authors
        "
      end
    end
  end
end
