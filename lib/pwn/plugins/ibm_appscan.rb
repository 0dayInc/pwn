# frozen_string_literal: true

require 'nokogiri'
require 'wicked_pdf'
require 'fileutils'
require 'uri'

module PWN
  module Plugins
    # This plugin is used for interacting w/ IBM Appscan Enterprise using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    # The IBM Appscan Spec in which this PWN module is based is located here:
    # http://www-01.ibm.com/support/knowledgecenter/SSW2NF_9.0.0/com.ibm.ase.help.doc/topics/c_web_services.html?lang=en
    module IBMAppscan
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.login(
      #   appscan_ip: 'required host/ip of IBM Appscan Server',
      #   username: 'required username',
      #   password: 'optional password (will prompt if nil)'
      # )

      public_class_method def self.login(opts = {})
        appscan_ip = opts[:appscan_ip]
        username = opts[:username].to_s.scrub
        base_appscan_api_uri = "https://#{appscan_ip}/ase/services".to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        @@logger.info("Logging into IBM Appscan Enterprise Server: #{appscan_ip}")
        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        response = rest_client.execute(
          method: :post,
          url: "#{base_appscan_api_uri}/login",
          payload: "userid=#{username}&password=#{password}",
          verify_ssl: false
        )

        # Return array containing the Appscan Server host/ip & post-authenticated Appscan REST cookie
        appscan_ip = URI.parse(response.args[:url]).host
        appscan_cookie = "asc_session_id=#{response.cookies['asc_session_id']}; ASP.NET_SessionId=#{response.cookies['ASP.NET_SessionId']}"
        appscan_obj = {}
        appscan_obj[:appscan_ip] = appscan_ip
        appscan_obj[:cookie] = appscan_cookie
        appscan_obj[:raw_response] = response
        appscan_obj[:xml_response] = Nokogiri::XML(response)
        appscan_obj[:build] = appscan_obj[:xml_response].xpath(
          '/xmlns:version/xmlns:build'
        ).text
        appscan_obj[:dbversion] = appscan_obj[:xml_response].xpath(
          '/xmlns:version/xmlns:dbversion'
        ).text
        appscan_obj[:rules_version] = appscan_obj[:xml_response].xpath(
          '/xmlns:version/xmlns:rules-version'
        ).text
        appscan_obj[:username] = appscan_obj[:xml_response].xpath(
          '/xmlns:version/xmlns:user-name'
        ).text
        appscan_obj[:password] = Base64.strict_encode64(password)
        appscan_obj[:logged_in] = true

        appscan_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # appscan_rest_call(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.appscan_rest_call(opts = {})
        appscan_obj = opts[:appscan_obj]
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        http_body = opts[:http_body].to_s.scrub
        appscan_ip = appscan_obj[:appscan_ip].to_s.scrub
        appscan_cookie = appscan_obj[:cookie]
        base_appscan_api_uri = "https://#{appscan_ip}/ase/services".to_s.scrub
        retry_count = 3

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_appscan_api_uri}/#{rest_call}",
            headers: { cookie: appscan_cookie },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_appscan_api_uri}/#{rest_call}",
            headers: { cookie: appscan_cookie },
            payload: http_body,
            verify_ssl: false
          )

        else
          return @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
        response
      rescue StandardError => e
        if (e.message == '401 Unauthorized') && retry_count.positive? && appscan_obj[:logged_in]
          # Try logging back in to refresh the connection
          @@logger.warn("Got Response: #{e}...Attempting to Re-Authenticate; Retries left #{retry_count}")
          n_appscan_obj = login(
            appscan_ip: appscan_obj[:appscan_ip],
            username: appscan_obj[:username],
            password: Base64.decode64(appscan_obj[:password])
          )
          appscan_cookie = n_appscan_obj[:cookie]
          # "copy" the new app obj over the old app obj
          appscan_obj.each_key do |k|
            appscan_obj[k] = n_appscan_obj[k]
          end
          retry_count -= 1
          retry
        end
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.schema(
      #   appscan_obj: 'required appscan_obj returned from login method'
      # )

      public_class_method def self.schema(opts = {})
        appscan_obj = opts[:appscan_obj]
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: 'schema')
        schema = {}
        schema[:raw_response] = response
        schema[:xml_response] = Nokogiri::XML(response)
        schema
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.version(
      #   appscan_obj: 'required appscan_obj returned from login method'
      # )

      public_class_method def self.version(opts = {})
        appscan_obj = opts[:appscan_obj]
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: 'version')
        version = {}
        version[:raw_response] = response
        version[:xml_response] = Nokogiri::XML(response)
        version[:build] = version[:xml_response].xpath(
          '/xmlns:version/xmlns:build'
        ).text
        version[:dbversion] = version[:xml_response].xpath(
          '/xmlns:version/xmlns:dbversion'
        ).text
        version[:rules_version] = version[:xml_response].xpath(
          '/xmlns:version/xmlns:rules-version'
        ).text
        version[:username] = version[:xml_response].xpath(
          '/xmlns:version/xmlns:user-name'
        ).text
        version
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_folders(
      #   appscan_obj: 'required appscan_obj returned from login method'
      # )

      public_class_method def self.get_folders(opts = {})
        appscan_obj = opts[:appscan_obj]
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: 'folders')
        folders = {}
        folders[:raw_response] = response
        folders[:xml_response] = Nokogiri::XML(response)
        folders
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_subfolders_of_folder(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   folder_id: 'required folder to retrieve'
      # )

      public_class_method def self.get_subfolders_of_folder(opts = {})
        appscan_obj = opts[:appscan_obj]
        folder_id = opts[:folder_id].to_i
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: "folders/#{folder_id}/folders")
        subfolders = {}
        subfolders[:raw_response] = response
        subfolders[:xml_response] = Nokogiri::XML(response)
        subfolders
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_folder_by_id(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   folder_id: 'required folder to retrieve'
      # )

      public_class_method def self.get_folder_by_id(opts = {})
        appscan_obj = opts[:appscan_obj]
        folder_id = opts[:folder_id].to_i
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: "folders/#{folder_id}")
        folder = {}
        folder[:raw_response] = response
        folder[:xml_response] = Nokogiri::XML(response)
        folder
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_folder_items(
      #   appscan_obj: 'required appscan_obj returned from login method'
      # )

      public_class_method def self.get_folder_items(opts = {})
        appscan_obj = opts[:appscan_obj]
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: 'folderitems')
        folder_items = {}
        folder_items[:raw_response] = response
        folder_items[:xml_response] = Nokogiri::XML(response)
        folder_items
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_folder_item_by_id(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   folder_item_id: 'required folder item to retrieve'
      # )

      public_class_method def self.get_folder_item_by_id(opts = {})
        appscan_obj = opts[:appscan_obj]
        folder_item_id = opts[:folder_item_id].to_i
        retry_count = 3

        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: "folderitems/#{folder_item_id}")
        folder_item = {}
        folder_item[:raw_response] = response
        folder_item[:xml_response] = Nokogiri::XML(response)
        # Get Current Status of a Scan
        # Available states:
        # READY = 1;
        # STARTING = 2;
        # RUNNING = 3;
        # RESUMING = 6;
        # CANCELING = 7;
        # SUSPENDING = 8;
        # SUSPENDED = 9;
        # POSTPROCESSING = 10;
        # ENDING = 12;
        folder_item[:state] = folder_item[:xml_response].xpath('//xmlns:state/xmlns:name').text
        folder_item
      rescue StandardError => e
        @@logger.error("Error: #{e} | #{e.class}\nResponse Returned: #{folder_item[:raw_response]}")
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_a_folders_folder_items(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   folder_id: 'required folder to retrieve'
      # )

      public_class_method def self.get_a_folders_folder_items(opts = {})
        appscan_obj = opts[:appscan_obj]
        folder_id = opts[:folder_item_id].to_i
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: "folders/#{folder_id}/folderitems")
        a_folders_folder_items = {}
        a_folders_folder_items[:raw_response] = response
        a_folders_folder_items[:xml_response] = Nokogiri::XML(response)
        a_folders_folder_items
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_folder_item_options(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   folder_item_id: 'required folder item to retrieve'
      # )

      public_class_method def self.get_folder_item_options(opts = {})
        appscan_obj = opts[:appscan_obj]
        folder_item_id = opts[:folder_item_id].to_i
        # TODO: Discover why not all options are returned
        # (e.g. esCOTAutoFormFillUserNameValue & esCOTAutoFormFillPasswordValue)
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: "folderitems/#{folder_item_id}/options")
        folder_item_options = {}
        folder_item_options[:raw_response] = response
        folder_item_options[:xml_response] = Nokogiri::XML(response)
        folder_item_options[:options] = folder_item_options[:xml_response].xpath(
          '//xmlns:available-option/@href'
        )
        folder_item_options
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_scan_templates(
      #   appscan_obj: 'required appscan_obj returned from login method'
      # )

      public_class_method def self.get_scan_templates(opts = {})
        appscan_obj = opts[:appscan_obj]
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: 'templates')
        templates = {}
        templates[:raw_response] = response
        templates[:xml_response] = Nokogiri::XML(response)
        templates
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.create_scan_based_on_template(
      #   appscan_obj: 'required appscan_obj returned from login method'
      #   template_id: 'required template id returned from get_scan_templates method'
      #   scan_name: 'required name of scan'
      #   scan_desc: 'required description of scan'
      # )

      public_class_method def self.create_scan_based_on_template(opts = {})
        appscan_obj = opts[:appscan_obj]
        template_id = opts[:template_id].to_i
        scan_name = opts[:scan_name].to_s.scrub
        scan_desc = opts[:scan_desc].to_s.scrub
        response = appscan_rest_call(
          appscan_obj: appscan_obj,
          http_method: :post,
          rest_call: "folderitems?templateId=#{template_id}",
          http_body: "name=#{scan_name}&description=#{scan_desc}"
        )

        # Return an Easy to Use Data Structure
        # Instead of Leaving it to the End User
        # To Parse Out the XML on their own.
        scan = {}
        scan[:raw_response] = response
        scan[:xml_response] = Nokogiri::XML(response)
        scan[:folder_url] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/@href'
        ).text
        scan[:folder_item_id] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:id'
        ).text
        scan[:scan_name] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:name'
        ).text
        scan[:scan_desc] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:description'
        ).text
        scan[:parent_folder_url] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:parent/@href'
        ).text
        scan[:parent_folder_id] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:parent/xmlns:id'
        ).text
        scan[:contact] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:contact'
        ).text
        scan[:state_id] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:state/xmlns:id'
        ).text
        scan[:state_name] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:state/xmlns:name'
        ).text
        scan[:action_id] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:action/xmlns:id'
        ).text
        scan[:action_name] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:action/xmlns:name'
        ).text
        scan[:options_url] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:content-scan-job/xmlns:options/@href'
        ).text
        scan[:report_pack_url] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:report-pack/@href'
        ).text
        scan[:report_pack_id] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:report-pack/xmlns:id'
        ).text
        scan[:reports_url] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:report-pack/xmlns:reports/@href'
        ).text
        scan[:reports_count] = scan[:xml_response].xpath(
          '/xmlns:folder-items/xmlns:report-pack/xmlns:reports/xmlns:count'
        ).text.to_i

        scan
      rescue StandardError => e
        @@logger.error("Error #{e}:\nREST response returned:\n#{response}")
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.configure_scan_options(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   folder_item_id: 'required folder item id',
      #   option: 'required option to change within the scan (folder item)',
      #   value: 'required option value(s)'
      # )

      public_class_method def self.configure_scan_options(opts = {})
        appscan_obj = opts[:appscan_obj]
        folder_item_id = opts[:folder_item_id].to_i
        option = opts[:option].to_s.scrub
        value = opts[:value]

        case option.to_sym
        when :epcsCOTListOfStartingUrls
          post_body = ''
          value.to_s.scrub.split(',').each_with_index do |url, index|
            post_body << '&' unless index.zero?
            post_body << "value=#{URI.encode_www_form(url.strip.chomp)}"
          end
        when :ebCOTHttpAuthentication
          post_body = if value == false
                        'value=0' # Don't require authentication
                      else
                        'value=1' # Require authentication
                      end
        when :esCOTHttpUser, :esCOTHttpPassword, :elCOTScanLimit
          post_body = "value=#{value.to_s.scrub}"
        when :help
          available_options = ''
          get_folder_item_options(
            appscan_obj: appscan_obj,
            folder_item_id: folder_item_id
          )[:options].each { |url| available_options << "#{File.basename(url)}\n" }

          return @@logger.info("Valid Options are:\n\n#{available_options}")
        else
          available_options = ''
          get_folder_item_options(
            appscan_obj: appscan_obj,
            folder_item_id: folder_item_id
          )[:options].each { |url| available_options << "#{File.basename(url)}\n" }

          return @@logger.error("Invalid option '#{option}' parameter passed.\nValid Options are:\n\n#{available_options}")
        end

        # Always Overwrite Existing Option Values
        response = appscan_rest_call(
          appscan_obj: appscan_obj,
          http_method: :post,
          rest_call: "folderitems/#{folder_item_id}/options/#{option}?put=1",
          http_body: post_body.to_s
        )

        scan_config = {}
        scan_config[:raw_response] = response
        scan_config[:xml_response] = Nokogiri::XML(response)
        scan_config[:options] = scan_config[:xml_response].xpath('//xmlns:option/@value')

        scan_config
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.folder_item_scan_action(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   folder_item_id: 'required folder item id',
      #   action: 'required action for scan to follow. Available actions are: :run, :suspend, :cancel, & :end',
      #   poll_interval: 'optional setting to determine length in seconds to poll for scan state (defaults to 60)'
      # )

      public_class_method def self.folder_item_scan_action(opts = {})
        appscan_obj = opts[:appscan_obj]
        folder_item_id = opts[:folder_item_id].to_i
        action = opts[:action].to_s.scrub.to_sym
        poll_interval = if opts[:poll_interval].nil?
                          60
                        else
                          opts[:poll_interval].to_i
                        end

        case action
        when :run
          # Make sure scan is in a Ready state
          this_folder_item = PWN::Plugins::IBMAppscan.get_folder_item_by_id(
            appscan_obj: appscan_obj,
            folder_item_id: folder_item_id
          )
          state = this_folder_item[:state]
          return @@logger.error("Scan isn't in a Ready state.  Current state: #{state}, abort.") if state != 'Ready'

          @@logger.info("Kicking Off Scan for Folder Item: #{folder_item_id}")
          response = appscan_rest_call(
            appscan_obj: appscan_obj,
            http_method: :post,
            rest_call: "folderitems/#{folder_item_id}",
            http_body: 'action=2'
          )
          # Obtain Status to Monitor Scan Completion
          state = nil
          until state == 'Ready'
            sleep poll_interval
            this_folder_item = PWN::Plugins::IBMAppscan.get_folder_item_by_id(
              appscan_obj: appscan_obj,
              folder_item_id: folder_item_id
            )
            state = this_folder_item[:state]
            @@logger.info("Current Scan State: #{state}...")
          end
          @@logger.info("Scan Completed @ #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}")
        when :suspend
          response = appscan_rest_call(
            appscan_obj: appscan_obj,
            http_method: :post,
            rest_call: "folderitems/#{folder_item_id}",
            http_body: 'action=3'
          )
        when :cancel
          response = appscan_rest_call(
            appscan_obj: appscan_obj,
            http_method: :post,
            rest_call: "folderitems/#{folder_item_id}",
            http_body: 'action=4'
          )
        when :end
          response = appscan_rest_call(
            appscan_obj: appscan_obj,
            http_method: :post,
            rest_call: "folderitems/#{folder_item_id}",
            http_body: 'action=5'
          )
        else
          return @@logger.error("Invalid action.  Valid actions are:\n:run\n:suspend\n:cancel\n:end\n")
        end

        scan_action = {}
        scan_action[:raw_response] = response
        scan_action[:xml_response] = Nokogiri::XML(response)

        scan_action
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_report_collection(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   report_folder_item_id: 'required report folder item id'
      # )

      public_class_method def self.get_report_collection(opts = {})
        appscan_obj = opts[:appscan_obj]
        report_folder_item_id = opts[:report_folder_item_id].to_i

        @@logger.info("Retrieving Report Collection ID: #{report_folder_item_id} - Available Report Pack Collection:")
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: "folderitems/#{report_folder_item_id}/reports")

        report_collection = {}
        report_collection[:raw_response] = response
        report_collection[:xml_response] = Nokogiri::XML(response)
        # Output full report pack collection
        report_collection[:xml_response].xpath('//xmlns:report').each do |r|
          @@logger.info("  - #{r.xpath('xmlns:name').text}")
        end

        report_collection
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_single_report(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   report_id: 'required report id'
      # )

      public_class_method def self.get_single_report(opts = {})
        appscan_obj = opts[:appscan_obj]
        report_id = opts[:report_id].to_i
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: "reports/#{report_id}")

        report = {}
        report[:raw_response] = response
        report[:xml_response] = Nokogiri::XML(response)
        @@logger.info("Retrieved Report ID/Name: #{report_id}/#{report[:xml_response].xpath('//xmlns:report/xmlns:name').text}")

        report
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_single_report_data(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   report_id: 'required report id'
      # )

      public_class_method def self.get_single_report_data(opts = {})
        appscan_obj = opts[:appscan_obj]
        report_id = opts[:report_id].to_i
        response = appscan_rest_call(
          appscan_obj: appscan_obj,
          rest_call: "reports/#{report_id}/data?mode=all"
        )

        report_data = {}
        report_data[:raw_response] = response
        report_data[:xml_response] = Nokogiri::XML(response)
        @@logger.info("Retrieved Report Data for Report ID: #{report_id}")

        report_data
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_single_report_schema(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   report_id: 'required report id'
      # )

      public_class_method def self.get_single_report_schema(opts = {})
        appscan_obj = opts[:appscan_obj]
        report_id = opts[:report_id].to_i
        response = appscan_rest_call(
          appscan_obj: appscan_obj,
          rest_call: "reports/#{report_id}/data?metadata=schema"
        )

        report_schema = {}
        report_schema[:raw_response] = response
        report_schema[:xml_response] = Nokogiri::XML(response)
        @@logger.info("Retrieved Report Schema for Report ID: #{report_id}")

        report_schema
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_issue_collection(
      #   appscan_obj: 'required appscan_obj returned from login method',
      #   report_id: 'required report id'
      # )

      public_class_method def self.get_issue_collection(opts = {})
        appscan_obj = opts[:appscan_obj]
        report_id = opts[:report_id].to_i
        response = appscan_rest_call(
          appscan_obj: appscan_obj,
          rest_call: "reports/#{report_id}/issues?mode=all"
        )

        issue_collection = {}
        issue_collection[:raw_response] = response
        issue_collection[:xml_response] = Nokogiri::XML(response)
        @@logger.info("Retrieved Issue Collection for Report ID: #{report_id}")

        issue_collection
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.get_report_data
      #   appscan_obj: 'required appscan_obj returned from login method'
      #   report_link: 'required report link to start report generation
      #   output_name: 'required name to save generated report'

      private_class_method def self.get_report_data(opts = {})
        appscan_obj = opts[:appscan_obj]
        report_link = opts[:report_link]
        output_name = opts[:output_name]

        # First Get request
        uri = URI.parse(report_link)
        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rb = browser_obj[:browser]

        res = rb.get(report_link, 'Cookie' => appscan_obj[:cookie], :verify_ssl => OpenSSL::SSL::VERIFY_NONE)
        location = "https://#{uri.host}#{res.headers['location']}"

        puts "Location: #{location}"
        # Generate the report on the server side
        res = rb.get(location, 'Cookie' => appscan_obj[:cookie], :verify_ssl => OpenSSL::SSL::VERIFY_NONE)

        # Now get the file
        f = File.open(output_name, 'wb')
        location['Export'] = 'Stream'
        begin
          rb.get(location, 'Cookie' => appscan_obj[:cookie], :verify_ssl => OpenSSL::SSL::VERIFY_NONE) do |resp|
            resp.read_body do |seg|
              f.write(seg)
            end
          end
        ensure
          f.close
        end
      rescue StandardError => e
        @@logger.error("Could not get report data: #{e}")
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.generate_scan_report
      #   appscan_obj: 'required appscan_obj returned from login method'
      #   scan_name: 'required name of scan for which to generate a report'
      #   output_path: 'required path to save generated report'

      public_class_method def self.generate_scan_report(opts = {})
        appscan_obj = opts[:appscan_obj]
        scan_name = opts[:scan_name]
        output_path = opts[:output_path]
        appscan_ip = appscan_obj[:appscan_ip].to_s.scrub
        login_uri = "https://#{appscan_ip}:9443/ase/pages/Login.jsp"
        base_appscan_uri = "https://#{appscan_ip}/ase/FolderExplorer.aspx"
        logout_uri = "https://#{appscan_ip}/ase/LogOut.aspx"

        # verify the output path actually exists
        return @@logger.error("Output directory does not exist: #{output_path}") unless File.directory?(output_path)

        browser_obj = PWN::Plugins::TransparentBrowser.open(
          browser_type: :headless,
          proxy: 'http://127.0.0.1:8080'
        )
        h_browser = browser_obj[:browser]

        # log into the system
        h_browser.goto login_uri.to_s.to_s.scrub
        h_browser.text_field(name: 'j_username').when_present.set(appscan_obj[:username])
        h_browser.text_field(name: 'j_password').when_present.set(Base64.decode64(appscan_obj[:password]))
        h_browser.button(name: 'login').when_present.click

        # head over to the reports page and click on the report link
        h_browser.goto base_appscan_uri.to_s.to_s.scrub
        h_browser.link(:text, 'ASE').when_present.click

        # Search for the report link with a matching name and click it
        clicked = false
        h_browser.links.each do |link|
          next unless (link.text == scan_name.to_s) && link.href =~ /^https:.+XReports.+/

          link.when_present.click
          clicked = true
          break
        end
        return @@logger.error("Could not find matching scan name for name #{scan_name}") unless clicked

        output_path = "#{output_path}/#{scan_name.gsub(/[^\w.-]/, '_')}/"
        FileUtils.rm_rf output_path if File.directory?(output_path)
        FileUtils.mkpath output_path

        # Download the top level report
        report_link = "#{h_browser.url}&exportformat=pdf&exportdelivery=download"
        output_name = "#{output_path}Top_Level.pdf"
        get_report_data(
          appscan_obj: appscan_obj,
          report_link: report_link,
          output_name: output_name
        )
      rescue StandardError => e
        @@logger.error("Error retrieving report for '#{scan_name}': #{e}")
      ensure
        # make sure we always logout
        h_browser.goto logout_uri.to_s.to_s.scrub
        h_browser.close
      end

      # Supported Method Parameters::
      # PWN::Plugins::IBMAppscan.logout(
      #   appscan_obj: 'required appscan_obj returned from login method'
      # )

      public_class_method def self.logout(opts = {})
        appscan_obj = opts[:appscan_obj]
        @@logger.info('Logging out...')
        response = appscan_rest_call(appscan_obj: appscan_obj, rest_call: 'logout')
        if response == ''
          appscan_obj[:logged_in] = false
          'logout successful'
        else
          response
        end
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
          appscan_obj = #{self}.login(
            appscan_ip: 'required host/ip of Nexpose Console (server)',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          schema = #{self}.schema(
            appscan_obj: 'required appscan_obj returned from login method'
          )

          version = #{self}.version(
            appscan_obj: 'required appscan_obj returned from login method'
          )

          folders = #{self}.get_folders(
            appscan_obj: 'required appscan_obj returned from login method'
          )

          subfolders = #{self}.get_subfolders_of_folder(
            appscan_obj: 'required appscan_obj returned from login method',
            folder_id: 'required folder to retrieve'
          )

          folder = #{self}.get_folder_by_id(
            appscan_obj: 'required appscan_obj returned from login method',
            folder_id: 'required folder to retrieve'
          )

          folder_items = #{self}.get_folder_items(
            appscan_obj: 'required appscan_obj returned from login method'
          )

          folder_item = #{self}.get_folder_item_by_id(
            appscan_obj: 'required appscan_obj returned from login method',
            folder_item_id: 'required folder item to retrieve'
          )

          a_folders_folder_items = #{self}.get_a_folders_folder_items(
            appscan_obj: 'required appscan_obj returned from login method',
            folder_id: 'required folder to retrieve'
          )

          folder_item_options = #{self}.get_folder_item_options(
            appscan_obj: 'required appscan_obj returned from login method',
            folder_item_id: 'required folder item to retrieve'
          )

          scan = #{self}.create_scan_based_on_template(
            appscan_obj: 'required appscan_obj returned from login method'
            template_id: 'required template id returned from get_scan_templates method'
            scan_name: 'required name of scan'
            scan_desc: 'required description of scan'
          )

          templates = #{self}.get_scan_templates(
            appscan_obj: 'required appscan_obj returned from login method'
          )

          scan_config = #{self}.configure_scan_options(
            appscan_obj: 'required appscan_obj returned from login method',
            folder_item_id: 'required folder item id',
            option: 'required option to change within the scan (folder item).  Pass :help for a list of options.',
            value: 'required option value(s)'
          )

          scan_action = #{self}.folder_item_scan_action(
            appscan_obj: 'required appscan_obj returned from login method',
            folder_item_id: 'required folder item id',
            action: 'required action for scan to follow. Available actions are: :run, :suspend, :cancel, & :end',
            poll_interval: 'optional setting to determine length in seconds to poll for scan state (defaults to 60)'
          )

          report_collection = #{self}.get_report_collection(
            appscan_obj: 'required appscan_obj returned from login method',
            report_folder_item_id: 'required report folder item id'
          )

          report = #{self}.get_single_report(
            appscan_obj: 'required appscan_obj returned from login method',
            report_id: 'required report id'
          )

          report_data = #{self}.get_single_report_data(
            appscan_obj: 'required appscan_obj returned from login method',
            report_id: 'required report id'
          )

          report_schema = #{self}.get_single_report_schema(
            appscan_obj: 'required appscan_obj returned from login method',
            report_id: 'required report id'
          )

          issue_collection = #{self}.get_issue_collection(
            appscan_obj: 'required appscan_obj returned from login method',
            report_id: 'required report id'
          )

          #{self}.generate_scan_report(
            appscan_obj: 'required appscan_obj returned from login',
            scan_name: 'required name of scan for which to generate a report',
            output_path: 'required path to save generated report'
          )

          #{self}.logout(
            appscan_obj: 'required appscan_obj returned from login method'
          )

          #{self}.authors
        "
      end
    end
  end
end
