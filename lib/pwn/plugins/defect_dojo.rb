# frozen_string_literal: true

require 'json'
require 'securerandom'

module PWN
  module Plugins
    # This plugin converts images to readable text
    # TODO: Convert all rest requests to POST instead of GET
    module DefectDojo
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # dd_obj = PWN::Plugins::DefectDojo.login(
      #   url: 'required - url of DefectDojo Server',
      #   api_version: 'required - api version to use v1 || v2',
      #   username: 'required - username to AuthN w/ api v1)',
      #   api_key: 'optional - defect dojo api key (will prompt if nil)',
      #   proxy: 'optional - proxy all traffic through MITM proxy (defaults to nil)'
      # )

      public_class_method def self.login(opts = {})
        url = opts[:url]
        opts[:api_version] ? (api_version = opts[:api_version]) : (api_version = 'v2')
        username = opts[:username].to_s.scrub

        api_key = opts[:api_key].to_s.scrub
        api_key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'API Key') if opts[:api_key].nil?

        proxy = opts[:proxy]

        dd_obj = {}
        dd_obj[:url] = url
        dd_obj[:authz_header] = "Token #{api_key}"
        dd_obj[:authz_header] = "ApiKey #{username}:#{api_key}" if api_version == 'v1'
        dd_obj[:proxy] = proxy
        dd_obj[:api_version] = api_version
        dd_obj[:api_version] = 'v1' if api_version == 'v1'

        dd_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # rest_call(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   rest_call: 'required rest call to make per the schema',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.rest_call(opts = {})
        # Some scan reports are huge and require long timeouts...defaulting to 9 mins.
        request_timeout = 540

        dd_obj = opts[:dd_obj]
        rest_call = opts[:rest_call].to_s.scrub

        opts[:http_method] ? (http_method = opts[:http_method].to_s.scrub.to_sym) : (http_method = :get)

        params = opts[:params]
        http_body = opts[:http_body]

        content_type = 'application/json; charset=UTF-8'

        url = dd_obj[:url]
        api_version = dd_obj[:api_version]
        base_dd_api_uri = "#{url}/api/#{api_version}".to_s.scrub

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)

        if dd_obj[:proxy]
          browser_obj = PWN::Plugins::TransparentBrowser.open(
            browser_type: :rest,
            proxy: dd_obj[:proxy]
          )
        end

        rest_client = browser_obj[:browser]
        rest_request = rest_client::Request

        case http_method
        when :get
          response = rest_request.execute(
            method: :get,
            url: "#{base_dd_api_uri}/#{rest_call}",
            headers: {
              content_type: content_type,
              authorization: dd_obj[:authz_header],
              params: params
            },
            verify_ssl: false,
            timeout: request_timeout,
            open_timeout: request_timeout
          )

        when :post
          if http_body.key?(:multipart)
            # Hack to fix name="tags[]" to name="tags" to allow for multi-tag submission
            # otherwise we could just used payload = http_body
            multipart = rest_client::Payload::Multipart.new(http_body)
            content_type = multipart.headers['Content-Type']
            multipart_massaged = multipart.to_s.gsub(
              'Content-Disposition: form-data; name="tags[]"',
              'Content-Disposition: form-data; name="tags"'
            )
            base = rest_client::Payload::Base.new(multipart_massaged)
            payload = base.to_s
          else
            payload = http_body.to_json
          end

          response = rest_request.execute(
            method: :post,
            url: "#{base_dd_api_uri}/#{rest_call}",
            headers: {
              content_type: content_type,
              authorization: dd_obj[:authz_header]
            },
            payload: payload,
            verify_ssl: false,
            timeout: request_timeout,
            open_timeout: request_timeout
          )
        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end

        sleep 3

        response
      rescue RestClient::ExceptionWithResponse => e
        puts Time.now.strftime('%Y-%m-%d %H:%M:%S.%N %z')
        puts "Module: #{self}"
        puts "URL: #{base_dd_api_uri}/#{rest_call}"
        puts "PARAMS: #{params.inspect}"
        puts "HTTP POST BODY: #{http_body.inspect}" if http_body
        puts "#{e}\n#{e.response}\n\n\n"
      rescue StandardError, SystemExit, Interrupt => e
        dd_obj = logout(dd_obj) unless dd_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # tool_configuration_resource_uri_by_name(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   tool_config_name: 'required tool configuration name'
      # )

      private_class_method def self.tool_configuration_resource_uri_by_name(opts = {})
        dd_obj = opts[:dd_obj]
        api_version = dd_obj[:api_version]
        tool_config_name = opts[:tool_config_name].to_s.scrub

        tool_configuration_list = self.tool_configuration_list(dd_obj: dd_obj)
        if api_version == 'v1'
          tool_configuration_by_name_object = tool_configuration_list[:objects].select do |tool_configuration|
            tool_configuration[:name] == tool_config_name
          end
        end

        if api_version == 'v2'
          tool_configuration_by_name_object = tool_configuration_list[:results].select do |tool_configuration|
            tool_configuration[:name] == tool_config_name
          end
        end

        tool_configuration_by_name_object.first[:resource_uri] if api_version == 'v1'
        tool_configuration_by_name_object.first[:id] if api_version == 'v2'
      rescue StandardError, SystemExit, Interrupt => e
        dd_obj = logout(dd_obj) unless dd_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # product_list = PWN::Plugins::DefectDojo.product_list(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   id: 'optional - retrieve single product by id, otherwise return all'
      # )

      public_class_method def self.product_list(opts = {})
        dd_obj = opts[:dd_obj]
        opts[:id] ? (rest_call = "products/#{opts[:id].to_i}") : (rest_call = 'products')

        response = rest_call(
          dd_obj: dd_obj,
          rest_call: rest_call
        )

        # Return array containing the post-authenticated DefectDojo REST API token
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # engagement_list = PWN::Plugins::DefectDojo.engagement_list(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   id: 'optional - retrieve single engagement by id, otherwise return all'
      # )

      public_class_method def self.engagement_list(opts = {})
        dd_obj = opts[:dd_obj]
        opts[:id] ? (rest_call = "engagements/#{opts[:id].to_i}") : (rest_call = 'engagements')

        response = rest_call(
          dd_obj: dd_obj,
          rest_call: rest_call
        )

        # Return array containing the post-authenticated DefectDojo REST API token
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # engagement_create_response = PWN::Plugins::DefectDojo.engagement_create(
      #   dd_obj: 'required - dd_obj returned from #login method',
      #   name: 'required - name of the engagement',
      #   description: 'optional - description of engagement',
      #   engagement_type: 'optional - type of engagement Interactive||CI/CD (defaults to CI/CD)',
      #   status: 'optional - status of the engagement In Progress || On Hold (defaults to In Progress)',
      #   lead_username: 'required - username of lead to tie to engagement',
      #   product_name: 'required - product name in which to create engagement',
      #   test_strategy: 'required - URL of test strategy documentation (e.g. OWASP ASVS URL)',
      #   orchestration_engine: 'optional - name of orchestration engine tied to CI/CD engagement',
      #   build_server: 'optional - name of build server tied to CI/CD engagement',
      #   scm_server: 'optional - name of SCM server tied to CI/CD engagement',
      #   api_test: 'optional - boolean to set an engagement as an api assessment (defaults to false)',
      #   pen_test: 'optional - boolean to set an engagement as a manual penetration test (defaults to false)',
      #   threat_model: 'optional - boolean to set an engagement as a threat model (defaults to false)',
      #   check_list: 'optional - boolean to set an engagement as a checkbox assessment (defaults to false)',
      #   first_contacted: 'optional - date of engagement request e.g. 2018-06-18 (Defaults to current day)',
      #   target_start: 'optional - date to start enagement e.g. 2018-06-19 (Defaults to current day)',
      #   target_end: 'optional - date of engagement completion e.g. 2018-06-20 (Defaults to current day)'
      # )

      public_class_method def self.engagement_create(opts = {})
        http_body = {}

        dd_obj = opts[:dd_obj]
        api_version = dd_obj[:api_version]

        # HTTP POST body options w/ optional params set to default values
        # Defaults to true
        http_body[:active] = true

        http_body[:name] = opts[:name]

        http_body[:description] = opts[:description]

        opts[:engagment_type] ? (http_body[:engagement_type] = opts[:engagement_type]) : (http_body[:engagement_type] = 'CI/CD')

        status = opts[:status].to_s.strip.chomp.scrub

        case status
        when 'In Progress', 'On Hold', ''
          # Defaults to 'In Progress'
          status == '' ? (http_body[:status] = 'In Progress') : (http_body[:status] = status)
        when 'Completed'
          raise 'Completed status not implemented for #engagement_create - use #engagement_update instead'
        else
          raise "Unknown engagement status: #{opts[:status]}.  Options for this method are 'In Progress' || 'On Hold'"
        end

        # Ok lets determine the resource_uri for the lead username
        lead_username = opts[:lead_username].to_s.strip.chomp.scrub
        user_list = self.user_list(dd_obj: dd_obj)
        if api_version == 'v1'
          user_by_username_object = user_list[:objects].select do |user|
            user[:username] == lead_username
          end
          http_body[:lead] = user_by_username_object.first[:resource_uri]
        end

        if api_version == 'v2'
          user_by_username_object = user_list[:results].select do |user|
            user[:username] == lead_username
          end
          # Should only ever return 1 result so we should be good here
          http_body[:lead] = user_by_username_object.first[:id]
        end

        # Ok lets determine the resource_uri for the product name
        product_name = opts[:product_name].to_s.strip.chomp.scrub
        product_list = self.product_list(dd_obj: dd_obj)

        if api_version == 'v1'
          product_by_name_object = product_list[:objects].select do |prod|
            prod[:name] == product_name
          end
          # Should only ever return 1 result so we should be good here
          http_body[:product] = product_by_name_object.first[:resource_uri]
        end

        if api_version == 'v2'
          product_by_name_object = product_list[:results].select do |prod|
            prod[:name] == product_name
          end
          # Should only ever return 1 result so we should be good here
          http_body[:product] = product_by_name_object.first[:id]
        end

        http_body[:test_strategy] = opts[:test_strategy]

        # Ok lets determine the resource_uri orchestration, build_server, and scm_server
        orchestration_engine = opts[:orchestration_engine].to_s.strip.chomp.scrub
        http_body[:orchestration_engine] = tool_configuration_resource_uri_by_name(
          dd_obj: dd_obj,
          tool_config_name: orchestration_engine
        )

        build_server = opts[:build_server].to_s.strip.chomp.scrub
        http_body[:build_server] = tool_configuration_resource_uri_by_name(
          dd_obj: dd_obj,
          tool_config_name: build_server
        )

        scm_server = opts[:scm_server].to_s.strip.chomp.scrub
        http_body[:source_code_management_server] = tool_configuration_resource_uri_by_name(
          dd_obj: dd_obj,
          tool_config_name: scm_server
        )

        # Defaults to false
        opts[:api_test] ? (http_body[:api_test] = true) : (http_body[:api_test] = false)

        # Defaults to false
        opts[:pen_test] ? (http_body[:pen_test] = true) : (http_body[:pen_test] = false)

        # Defaults to false
        opts[:threat_model] ? (http_body[:threat_model] = true) : (http_body[:threat_model] = false)

        # Defaults to false
        opts[:check_list] ? (http_body[:check_list] = true) : (http_body[:check_list] = false)

        # Defaults to Time.now.strftime('%Y-%m-%d')
        opts[:first_contacted] ? (http_body[:first_contacted] = opts[:first_contacted]) : (http_body[:first_contacted] = Time.now.strftime('%Y-%m-%d'))

        # Defaults to Time.now.strftime('%Y-%m-%d')
        opts[:target_start] ? (http_body[:target_start] = opts[:target_start]) : (http_body[:target_start] = Time.now.strftime('%Y-%m-%d'))

        # Defaults to Time.now.strftime('%Y-%m-%d')
        opts[:target_end] ? (http_body[:target_end] = opts[:target_end]) : (http_body[:target_end] = Time.now.strftime('%Y-%m-%d'))

        # Defaults to false
        http_body[:done_testing] = false

        rest_call(
          dd_obj: dd_obj,
          rest_call: 'engagements/',
          http_method: :post,
          http_body: http_body
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # test_list = PWN::Plugins::DefectDojo.test_list(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   id: 'optional - retrieve single test by id, otherwise return all'
      # )

      public_class_method def self.test_list(opts = {})
        dd_obj = opts[:dd_obj]
        opts[:id] ? (rest_call = "tests/#{opts[:id].to_i}") : (rest_call = 'tests')

        response = rest_call(
          dd_obj: dd_obj,
          rest_call: rest_call
        )

        # Return array containing the post-authenticated DefectDojo REST API token
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # importscan_response = PWN::Plugins::DefectDojo.importscan(
      #   dd_obj: 'required - dd_obj returned from #login method',
      #   engagement_name: 'required - name of engagement to associate w/ scan',
      #   scan_type: 'required - type of scan importing (see <DEFECTDOJO_URL>/admin/dojo/test_type/ for listing)',
      #   file: 'required - path of scan results file',
      #   lead_username: 'required - username of lead to tie to scan',
      #   tags: 'optional - comma-delimited list of tag names to tie to scan',
      #   minimum_severity: 'optional - minimum finding severity Info||Low||Medium||High||Critical (Defaults to Info)',
      #   scan_date: 'optional - date in which scan was kicked off (defaults to now)',
      #   verified: 'optional - flag finding as verified by a tester (defaults to false)',
      #   create_finding_groups: 'optional - flag to create finding groups (defaults to false)'
      #   close_old_findings_product_scope: 'optional - flag to close old findings from engagement (defaults to false)',
      #   close_old_findings: 'optional - flag to close old findings, regardless of engagement (defaults to false)',
      #   push_to_jira: 'optional - flag to push findings to JIRA (defaults to false)'
      # )

      public_class_method def self.importscan(opts = {})
        http_body = {}

        dd_obj = opts[:dd_obj]
        api_version = dd_obj[:api_version]

        # HTTP POST body options w/ optional params set to default values
        # Defaults to true
        http_body[:active] = true

        # Ok lets determine the resource_uri for the engagement name
        engagement_name = opts[:engagement_name].to_s.strip.chomp.scrub
        engagement_list = self.engagement_list(dd_obj: dd_obj)

        if api_version == 'v1'
          engagement_by_name_object = engagement_list[:objects].select do |engagement|
            engagement[:name] == engagement_name
          end
          # Should only ever return 1 result so we should be good here
          http_body[:engagement] = engagement_by_name_object.first[:resource_uri]
        end

        if api_version == 'v2'
          engagement_by_name_object = engagement_list[:results].select do |engagement|
            engagement[:name] == engagement_name
          end
          # Should only ever return 1 result so we should be good here
          http_body[:engagement] = engagement_by_name_object.first[:id]
        end

        http_body[:scan_type] = opts[:scan_type].to_s.strip.chomp.scrub

        # Necessary to upload file to remote host
        http_body[:multipart] = true
        http_body[:file] = File.new(opts[:file].to_s.strip.chomp.scrub, 'rb') if File.exist?(opts[:file].to_s.strip.chomp.scrub)

        # Ok lets determine the resource_uri for the lead username
        lead_username = opts[:lead_username].to_s.strip.chomp.scrub
        user_list = self.user_list(dd_obj: dd_obj)

        if api_version == 'v1'
          user_by_username_object = user_list[:objects].select do |user|
            user[:username] == lead_username
          end
          # Should only ever return 1 result so we should be good here
          http_body[:lead] = user_by_username_object.first[:resource_uri]
        end

        if api_version == 'v2'
          user_by_username_object = user_list[:results].select do |user|
            user[:username] == lead_username
          end
          # Should only ever return 1 result so we should be good here
          http_body[:lead] = user_by_username_object.first[:id]
        end

        http_body[:tags] = opts[:tags].to_s.strip.chomp.scrub.delete("\s").split(',') if opts[:tags]

        minimum_severity = opts[:minimum_severity].to_s.strip.chomp.scrub.downcase.capitalize
        case minimum_severity
        when '', 'Info', 'Low', 'Medium', 'High', 'Critical'
          # Defaults to 'Info'
          minimum_severity == '' ? (http_body[:minimum_severity] = 'Info') : (http_body[:minimum_severity] = minimum_severity)
        else
          raise "Unknown minimum severity: #{opts[:minimum_severity]}.  Options are Info||Low||Medium||High||Critical'"
        end

        # Defaults to Time.now.strftime('%Y-%m-%d')
        opts[:scan_date] ? (http_body[:scan_date] = opts[:scan_date]) : (http_body[:scan_date] = Time.now.strftime('%Y-%m-%d'))

        # Defaults to false
        opts[:verified] ? (http_body[:verified] = true) : (http_body[:verified] = false)

        opts[:create_finding_groups] ? (http_body[:create_finding_groups_for_all_findings] = true) : (http_body[:create_finding_groups_for_all_findings] = false)

        opts[:close_old_findings_product_scope] ? (http_body[:close_old_findings_product_scope] = true) : (http_body[:close_old_findings_product_scope] = false)

        opts[:close_old_findings] ? (http_body[:close_old_findings] = true) : (http_body[:close_old_findings] = false)

        opts[:push_to_jira] ? (http_body[:push_to_jira] = true) : (http_body[:push_to_jira] = false)

        api_path = 'import-scan/'
        api_path = 'importscan/' if api_version == 'v1'

        rest_call(
          dd_obj: dd_obj,
          rest_call: api_path,
          http_method: :post,
          http_body: http_body
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # reimportscan_response = PWN::Plugins::DefectDojo.reimportscan(
      #   dd_obj: 'required - dd_obj returned from #login method',
      #   engagement_name: 'required - name of engagement to associate w/ scan',
      #   scan_type: 'required - type of scan importing (see <DEFECTDOJO_URL>/admin/dojo/test_type/ for listing)',
      #   file: 'required - path of scan results file',
      #   tags: 'optional - comma-delimited list of tag names to tie to scan for unique test resource_uri retrival',
      #   test_resource_uri: 'optional - alternative to tag names to know which test to reimport',
      #   minimum_severity: 'optional - minimum finding severity Info||Low||Medium||High||Critical (Defaults to Info)',
      #   scan_date: 'optional - date in which scan was kicked off (defaults to now)',
      #   verified: 'optional - flag finding as verified by a tester (defaults to false)',
      #   create_finding_groups: 'optional - flag to create finding groups (defaults to false)',
      #   close_old_findings_product_scope: 'optional - flag to close old findings from engagement (defaults to false)',
      #   close_old_findings: 'optional - flag to close old findings, regardless of engagement (defaults to false)',
      #   push_to_jira: 'optional - flag to push findings to JIRA (defaults to false)'
      # )

      public_class_method def self.reimportscan(opts = {})
        http_body = {}

        dd_obj = opts[:dd_obj]
        api_version = dd_obj[:api_version]

        # HTTP POST body options w/ optional params set to default values
        # Defaults to true
        http_body[:active] = true

        # Ok lets determine the resource_uri for the engagement name
        engagement_name = opts[:engagement_name].to_s.strip.chomp.scrub
        engagement_list = self.engagement_list(dd_obj: dd_obj)
        if api_version == 'v1'
          engagement_by_name_object = engagement_list[:objects].select do |engagement|
            engagement[:name] == engagement_name
          end
          # Should only ever return 1 result so we should be good here
          engagement_resource_uri = engagement_by_name_object.first[:resource_uri]
        end

        if api_version == 'v2'
          engagement_by_name_object = engagement_list[:results].select do |engagement|
            engagement[:name] == engagement_name
          end
          # Should only ever return 1 result so we should be good here
          engagement_resource_uri = engagement_by_name_object.first[:id]
        end

        # TODO: lookup scan_type for test resource_uri since the scan_type should never change
        http_body[:scan_type] = opts[:scan_type].to_s.strip.chomp.scrub

        # Necessary to upload file to remote host
        http_body[:multipart] = true
        http_body[:file] = File.new(opts[:file].to_s.strip.chomp.scrub, 'rb') if File.exist?(opts[:file].to_s.strip.chomp.scrub)

        # Ok lets determine the resource_uri for the test we're looking to remimport
        test_list = self.test_list(dd_obj: dd_obj)

        if api_version == 'v1'
          tests_by_engagement_object = test_list[:objects].select do |test|
            test[:engagement] == engagement_resource_uri
          end
        end

        if api_version == 'v2'
          tests_by_engagement_object = test_list[:results].select do |test|
            test[:engagement] == engagement_resource_uri
          end
        end

        http_body[:tags] = opts[:tags].to_s.strip.chomp.scrub.delete("\s").split(',') if opts[:tags]

        http_body[:test] = opts[:test_resource_uri] if opts[:test_resource_uri]

        minimum_severity = opts[:minimum_severity].to_s.strip.chomp.scrub.downcase.capitalize
        case minimum_severity
        when '', 'Info', 'Low', 'Medium', 'High', 'Critical'
          # Defaults to 'Info'
          minimum_severity == '' ? (http_body[:minimum_severity] = 'Info') : (http_body[:minimum_severity] = minimum_severity)
        else
          raise "Unknown minimum severity: #{opts[:minimum_severity]}.  Options are Info||Low||Medium||High||Critical'"
        end

        # Defaults to Time.now.strftime('%Y-%m-%d')
        opts[:scan_date] ? (http_body[:scan_date] = opts[:scan_date]) : (http_body[:scan_date] = Time.now.strftime('%Y/%m/%d'))

        # Defaults to false
        opts[:verified] ? (http_body[:verified] = true) : (http_body[:verified] = false)

        opts[:create_finding_groups] ? (http_body[:create_finding_groups_for_all_findings] = true) : (http_body[:create_finding_groups_for_all_findings] = false)

        opts[:close_old_findings_product_scope] ? (http_body[:close_old_findings_product_scope] = true) : (http_body[:close_old_findings_product_scope] = false)

        opts[:close_old_findings] ? (http_body[:close_old_findings] = true) : (http_body[:close_old_findings] = false)

        opts[:push_to_jira] ? (http_body[:push_to_jira] = true) : (http_body[:push_to_jira] = false)

        api_path = 'reimport-scan/'
        api_path = 'reimportscan/' if api_version == 'v1'

        rest_call(
          dd_obj: dd_obj,
          rest_call: api_path,
          http_method: :post,
          http_body: http_body
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # finding_list = PWN::Plugins::DefectDojo.finding_list(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   id: 'optional - retrieve single finding by id, otherwise return all'
      # )

      public_class_method def self.finding_list(opts = {})
        dd_obj = opts[:dd_obj]
        opts[:id] ? (rest_call = "findings/#{opts[:id].to_i}") : (rest_call = 'findings')

        response = rest_call(
          dd_obj: dd_obj,
          rest_call: rest_call
        )

        # Return array containing the post-authenticated DefectDojo REST API token
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # user_list = PWN::Plugins::DefectDojo.user_list(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   id: 'optional - retrieve single user by id, otherwise return all'
      # )

      public_class_method def self.user_list(opts = {})
        dd_obj = opts[:dd_obj]
        opts[:id] ? (rest_call = "users/#{opts[:id].to_i}") : (rest_call = 'users')

        response = rest_call(
          dd_obj: dd_obj,
          rest_call: rest_call
        )

        # Return array containing the post-authenticated DefectDojo REST API token
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # tool_configuration_list = PWN::Plugins::DefectDojo.tool_configuration_list(
      #   dd_obj: 'required dd_obj returned from #login method',
      #   id: 'optional - retrieve single test by id, otherwise return all'
      # )

      public_class_method def self.tool_configuration_list(opts = {})
        dd_obj = opts[:dd_obj]
        opts[:id] ? (rest_call = "tool_configurations/#{opts[:id].to_i}") : (rest_call = 'tool_configurations')

        response = rest_call(
          dd_obj: dd_obj,
          rest_call: rest_call
        )

        # Return array containing the post-authenticated DefectDojo REST API token
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DefectDojo.logout(
      #   dd_obj: 'required dd_obj returned from #login method'
      # )

      public_class_method def self.logout(opts = {})
        dd_obj = opts[:dd_obj]
        @@logger.info('Logging out...')
        # TODO: Terminate Session if Possible via API Call
        dd_obj = nil
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
          dd_obj = #{self}.login(
            url: 'required - url of DefectDojo Server',
            api_version: 'required - api version to use v1 || v2',
            username: 'required - username to AuthN w/ api v1)',
            api_key: 'optional - defect dojo api key (will prompt if nil)',
            proxy: 'optional - proxy all traffic through MITM proxy (defaults to nil)'
          )

          product_list = #{self}.product_list(
            dd_obj: 'required dd_obj returned from #login_v1 method',
            id: 'optional - retrieve single product by id, otherwise return all'
          )

          engagement_list = #{self}.engagement_list(
            dd_obj: 'required dd_obj returned from #login_v1 method',
            id: 'optional - retrieve single engagement by id, otherwise return all'
          )

          engagement_create_response = #{self}.engagement_create(
            dd_obj: 'required - dd_obj returned from #login_v1 method',
            name: 'required - name of the engagement',
            description: 'optional - description of engagement',
            engagement_type: 'optional - type of engagement Interactive||CI/CD (defaults to CI/CD)',
            status: 'optional - status of the engagement In Progress || On Hold (defaults to In Progress)',
            lead_username: 'required - username of lead to tie to engagement',
            product_name: 'required - product name in which to create engagement',
            test_strategy: 'required - URL of test strategy documentation (e.g. OWASP ASVS URL)',
            orchestration_engine: 'optional - name of orchestration engine tied to CI/CD engagement',
            build_server: 'optional - name of build server tied to CI/CD engagement',
            scm_server: 'optional - name of SCM server tied to CI/CD engagement',
            api_test: 'optional - boolean to set an engagement as an api assessment (defaults to false)',
            pen_test: 'optional - boolean to set an engagement as a manual penetration test (defaults to false)',
            threat_model: 'optional - boolean to set an engagement as a threat model (defaults to false)',
            check_list: 'optional - boolean to set an engagement as a checkbox assessment (defaults to false)',
            first_contacted: 'optional - date of engagement request e.g. 2018-06-18 (Defaults to current day)',
            target_start: 'optional - date to start enagement e.g. 2018-06-19 (Defaults to current day)',
            target_end: 'optional - date of engagement completion e.g. 2018-06-20 (Defaults to current day)'
          )

          test_list = #{self}.test_list(
            dd_obj: 'required dd_obj returned from #login_v1 method',
            id: 'optional - retrieve single test by id, otherwise return all'
          )

          importscan_response = #{self}.importscan(
            dd_obj: 'required - dd_obj returned from #login_v1 method',
            engagement_name: 'required - name of engagement to associate w/ scan',
            scan_type: 'required - type of scan importing (see <DEFECTDOJO_URL>/admin/dojo/test_type/ for listing)',
            file: 'required - path of scan results file',
            lead_username: 'required - username of lead to tie to scan',
            tags: 'optional - comma-delimited list of tag names to tie to scan',
            minimum_severity: 'optional - minimum finding severity Info||Low||Medium||High||Critical (Defaults to Info)',
            scan_date: 'optional - date in which scan was kicked off (defaults to now)',
            verified: 'optional - flag finding as verified by a tester (defaults to false)',
            create_finding_groups: 'optional - flag to create finding groups (defaults to false)',
            close_old_findings_product_scope: 'optional - flag to close old findings from engagement (defaults to false)',
            close_old_findings: 'optional - flag to close old findings, regardless of engagement (defaults to false)',
            push_to_jira: 'optional - flag to push findings to JIRA (defaults to false)'
          )

          reimportscan_response = #{self}.reimportscan(
            dd_obj: 'required - dd_obj returned from #login_v1 method',
            engagement_name: 'required - name of engagement to associate w/ scan',
            scan_type: 'required - type of scan importing (see <DEFECTDOJO_URL>/admin/dojo/test_type/ for listing)',
            file: 'required - path of scan results file',
            tags: 'optional - comma-delimited list of tag names to tie to scan for unique test resource_uri retrival',
            test_resource_uri: 'optional - alternative to tag names to know which test to reimport',
            minimum_severity: 'optional - minimum finding severity Info||Low||Medium||High||Critical (Defaults to Info)',
            scan_date: 'optional - date in which scan was kicked off (defaults to now)',
            verified: 'optional - flag finding as verified by a tester (defaults to false)',
            create_finding_groups: 'optional - flag to create finding groups (defaults to false)',
            close_old_findings_product_scope: 'optional - flag to close old findings from engagement (defaults to false)',
            close_old_findings: 'optional - flag to close old findings, regardless of engagement (defaults to false)',
            push_to_jira: 'optional - flag to push findings to JIRA (defaults to false)'
          )

          finding_list = #{self}.finding_list(
            dd_obj: 'required dd_obj returned from #login_v1 method',
            id: 'optional - retrieve single finding by id, otherwise return all'
          )

          user_list = #{self}.user_list(
            dd_obj: 'required dd_obj returned from #login_v1 method',
            id: 'optional - retrieve single user by id, otherwise return all'
          )

          tool_configuration_list = #{self}.tool_configuration_list(
            dd_obj: 'required dd_obj returned from #login_v1 method',
            id: 'optional - retrieve single test by id, otherwise return all'
          )

          #{self}.logout(
            dd_obj: 'required dd_obj returned from #login_v1 or #login_v2 method'
          )

          #{self}.authors
        "
      end
    end
  end
end
