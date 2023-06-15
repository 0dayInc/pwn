# frozen_string_literal: true

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
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body]
        http_body ||= {}
        base_bd_bin_analysis_api_uri = 'https://protecode-sc.com/api'
        token = opts[:token]

        content_type = 'application/json; charset=UTF-8'

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        spinner = TTY::Spinner.new
        spinner.auto_spin

        case http_method
        when :delete, :get
          headers = opts[:http_headers]
          headers ||= {
            content_type: content_type,
            authorization: "Bearer #{token}",
            params: params
          }
          response = rest_client.execute(
            method: http_method,
            url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
            headers: headers,
            verify_ssl: false
          )

        when :post, :put
          headers = opts[:http_headers]
          if http_body.key?(:multipart)
            headers ||= {
              authorization: "Bearer #{token}"
            }
            response = rest_client.execute(
              method: :post,
              url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
              headers: headers,
              payload: http_body,
              verify_ssl: false
            )
          else
            headers ||= {
              content_type: content_type,
              authorization: "Bearer #{token}"
            }
            response = rest_client.execute(
              method: http_method,
              url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
              headers: headers,
              payload: http_body.to_json,
              verify_ssl: false
            )
          end
        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
        response
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      ensure
        spinner.stop
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
      #   file: 'required - file to upload'
      # )

      public_class_method def self.upload_file(opts = {})
        token = opts[:token]
        file = opts[:file]
        raise "ERROR: #{file} not found." unless File.exist?(file)

        http_headers = {
          authorization: "Bearer #{token}"
        }

        http_body = {
          multipart: true,
          file: File.new(file, 'rb')
        }

        response = bd_bin_analysis_rest_call(
          http_method: :post,
          token: token,
          rest_call: 'files',
          http_headers: http_headers,
          http_body: http_body
        )

        JSON.parse(response, symbolize_names: true)
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
      #   parent: 'optional - parent group id',
      #   delete_binary: 'optional - delete binary after analysis C|Y|N (Default: C== company default)',
      #   binary_cleanup_age: 'optional - after how long the binary will be deleted in seconds (Default: 604_800 / 1 week)',
      #   product_cleanup_age: 'optional - after how long the product will be deleted in seconds (Default: 604_800 / 1 week)',
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
        parent = opts[:parent]
        delete_binary = opts[:delete_binary] ||= 'C'
        binary_cleanup_age = opts[:binary_cleanup_age] ||= 604_800
        product_cleanup_age = opts[:product_cleanup_age] ||= 604_800
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
          parent: parent,
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

          response = #{self}.upload_file(
            token: 'required - Black Duck Binary Analysis API token',
            file: 'required - file to upload'
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
            parent: 'optional - parent group id',
            delete_binary: 'optional - delete binary after analysis C|Y|N (Default: C== company default)',
            binary_cleanup_age: 'optional - after how long the binary will be deleted in seconds (Default: 604_800 / 1 week)',
            product_cleanup_age: 'optional - after how long the product will be deleted in seconds (Default: 604_800 / 1 week)',
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