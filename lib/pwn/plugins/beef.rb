# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # This plugin is used for interacting w/ BeEF's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    module BeEF
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # beef_obj = PWN::Plugins::BeEF.login(
      #   beef_ip: 'required - host/ip of BeEF Server',
      #   beef_port: 'optional - port of BeEF server (defaults to 3000)',
      #   username: 'required - username',
      #   password: 'optional - password (will prompt if nil)'
      # )

      public_class_method def self.login(opts = {})
        beef_ip = opts[:beef_ip]
        beef_port = if opts[:beef_port]
                      opts[:beef_port].to_i
                    else
                      3000
                    end

        username = opts[:username].to_s.scrub
        base_beef_api_uri = "http://#{beef_ip}:#{beef_port}/api".to_s.scrub

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end

        auth_payload = {}
        auth_payload[:username] = username
        auth_payload[:password] = password

        @@logger.info("Logging into BeEF REST API: #{beef_ip}")
        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request
        response = rest_client.execute(
          method: :post,
          url: "#{base_beef_api_uri}/admin/login",
          payload: auth_payload.to_json
        )

        # Return array containing the post-authenticated BeEF REST API token
        json_response = JSON.parse(response)
        beef_success = json_response['success']
        api_token = json_response['token']
        beef_obj = {}
        beef_obj[:beef_ip] = beef_ip
        beef_obj[:beef_port] = beef_port
        beef_obj[:beef_success] = beef_success
        beef_obj[:api_token] = api_token
        beef_obj[:raw_response] = response

        beef_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # beef_rest_call(
      #   beef_obj: 'required beef_obj returned from #login method',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.beef_rest_call(opts = {})
        beef_obj = opts[:beef_obj]
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        http_body = opts[:http_body].to_s.scrub
        beef_success = beef_obj[:beef_success].to_s.scrub
        beef_ip = beef_obj[:beef_ip].to_s.scrub
        beef_port = beef_obj[:beef_port].to_i
        base_beef_api_uri = "http://#{beef_ip}:#{beef_port}/api".to_s.scrub
        api_token = beef_obj[:api_token]

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_beef_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              params: { token: api_token }
            }
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_beef_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8'
            },
            payload: http_body
          )

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # hooks = PWN::Plugins::BeEF.hooks(
      #   beef_obj: 'required beef_obj returned from #login method'
      # )

      public_class_method def self.hooks(opts = {})
        beef_obj = opts[:beef_obj]
        @@logger.info('Retrieving BeEF Hooks...')

        response = beef_rest_call(
          beef_obj: beef_obj,
          rest_call: 'hooks'
        )

        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # hooked_browser_info = PWN::Plugins::BeEF.hooked_browser_info(
      #   beef_obj: 'required beef_obj returned from #login method',
      #   browser_session: 'required - browser session id returned from #hooks method'
      # )

      public_class_method def self.hooked_browser_info(opts = {})
        beef_obj = opts[:beef_obj]
        browser_session = opts[:browser_session].to_s.scrub

        @@logger.info('Retrieving Browser Info...')

        response = beef_rest_call(
          beef_obj: beef_obj,
          rest_call: "hooks/#{browser_session}"
        )

        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # logs = PWN::Plugins::BeEF.logs(
      #   beef_obj: 'required beef_obj returned from #login method'
      # )

      public_class_method def self.logs(opts = {})
        beef_obj = opts[:beef_obj]
        @@logger.info('Retrieving BeEF Logs...')

        response = beef_rest_call(
          beef_obj: beef_obj,
          rest_call: 'logs'
        )

        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # hooked_browser_logs = PWN::Plugins::BeEF.hooked_browser_logs(
      #   beef_obj: 'required beef_obj returned from #login method',
      #   browser_session: 'required - browser session id returned from #hooks method'
      # )

      public_class_method def self.hooked_browser_logs(opts = {})
        beef_obj = opts[:beef_obj]
        browser_session = opts[:browser_session].to_s.scrub

        @@logger.info('Retrieving Browser Logs...')

        response = beef_rest_call(
          beef_obj: beef_obj,
          rest_call: "logs/#{browser_session}"
        )

        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # modules = PWN::Plugins::BeEF.modules(
      #   beef_obj: 'required beef_obj returned from #login method'
      # )

      public_class_method def self.modules(opts = {})
        beef_obj = opts[:beef_obj]
        @@logger.info('Retrieving BeEF Modules...')

        response = beef_rest_call(
          beef_obj: beef_obj,
          rest_call: 'modules'
        )

        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # module_info = PWN::Plugins::BeEF.module_info(
      #   beef_obj: 'required beef_obj returned from #login method',
      #   module_id: 'required - module id returned from #modules method'
      # )

      public_class_method def self.module_info(opts = {})
        beef_obj = opts[:beef_obj]
        module_id = opts[:module_id].to_i

        @@logger.info('Retrieving Module Info...')

        response = beef_rest_call(
          beef_obj: beef_obj,
          rest_call: "modules/#{module_id}"
        )

        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BeEF.logout(
      #   beef_obj: 'required beef_obj returned from #login method'
      # )

      public_class_method def self.logout(opts = {})
        beef_obj = opts[:beef_obj]
        @@logger.info('Logging out...')
        beef_obj = nil
      rescue StandardError => e
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
          beef_obj = #{self}.login(
            beef_ip: 'required host/ip of Nexpose Console (server)',
            beef_port: 'optional - port of BeEF server (defaults to 3000)',
            username: 'required username',
            password: 'optional password (will prompt if nil)'
          )

          hooks = #{self}.hooks(
            beef_obj: 'required beef_obj returned from #login method'
          )

          hooked_browser_info = #{self}.hooked_browser_info(
            beef_obj: 'required beef_obj returned from #login method',
            browser_session: 'required - browser session id returned from #hooks method'
          )

          logs = #{self}.logs(
            beef_obj: 'required beef_obj returned from #login method'
          )

          hooked_browser_logs = #{self}.hooked_browser_logs(
            beef_obj: 'required beef_obj returned from #login method',
            browser_session: 'required - browser session id returned from #hooks method'
          )

          modules = #{self}.modules(
            beef_obj: 'required beef_obj returned from #login method'
          )

          module_info = #{self}.module_info(
            beef_obj: 'required beef_obj returned from #login method',
            module_id: 'required - module id returned from #modules method'
          )

          beef_obj = #{self}.logout(
            beef_obj: 'required beef_obj returned from #login method'
          )

          #{self}.authors
        "
      end
    end
  end
end
