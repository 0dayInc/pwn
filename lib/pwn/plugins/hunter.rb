# frozen_string_literal: true

require 'base64'
require 'json'

module PWN
  module Plugins
    # This plugin is used for interacting w/ Hunter's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    #  This is based on the following Hunter API Specification:
    # https://hunter.how/search-api
    module Hunter
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # hunter_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.hunter_rest_call(opts = {})
        hunter_obj = opts[:hunter_obj]
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        base_hunter_api_uri = 'https://api.hunter.how'

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_hunter_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_hunter_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              params: params
            },
            payload: http_body,
            verify_ssl: false
          )

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
        JSON.parse(response.scrub, symbolize_names: true)
      rescue JSON::ParserError => e
        {
          total: 0,
          matches: [],
          error: "JSON::ParserError #{e.message}",
          rest_call: rest_call,
          params: params
        }
      rescue RestClient::TooManyRequests
        print 'Too many requests.  Sleeping 10s...'
        sleep 10
        retry
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      end

      # Supported Method Parameters::
      # search_results = PWN::Plugins::Hunter.search(
      #   api_key: 'required hunter api key',
      #   query: 'required - hunter search query',
      #   start_time: 'required - start date for the search (format is yyyy-mm-dd)',
      #   end_time: 'required - end date for the search (format is yyyy-mm-dd)',
      #   start_page: 'optional - starting page number for pagination (default is 1)',
      #   page_size: 'optional - number of results per page (default is 10)',
      #   fields: 'optional - comma-separated list of fields 'product,transport_protocol,protocol,banner,country,province,city,asn,org,web,updated_at' (default is nil)'
      # )

      public_class_method def self.search(opts = {})
        api_key = opts[:api_key].to_s.scrub
        raise "ERROR: #{self} requires a valid Hunter API Key" if api_key.empty?

        query = opts[:query].to_s.scrub
        raise "ERROR: #{self} requires a valid query" if query.empty?

        start_time = opts[:start_time]
        raise "ERROR: #{self} requires a valid start time" if start_time.nil?

        end_time = opts[:end_time]
        raise "ERROR: #{self} requires a valid end time" if end_time.nil?

        start_page = opts[:start_page] ||= 1
        page_size = opts[:page_size] ||= 10
        fields = opts[:fields]

        params = {}
        params[:'api-key'] = api_key
        base64_query = Base64.urlsafe_encode64(query)
        params[:query] = base64_query
        params[:page] = start_page
        params[:page_size] = page_size
        params[:start_time] = start_time
        params[:end_time] = end_time
        params[:fields] = fields

        hunter_rest_call(
          rest_call: 'search',
          params: params
        )
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
          search_results = #{self}.query(
            api_key: 'required hunter api key',
            query: 'required - hunter search query',
            start_time: 'required - start date for the search (format is yyyy-mm-dd)',
            end_time: 'required - end date for the search (format is yyyy-mm-dd)',
            start_page: 'optional - starting page number for pagination (default is 1)',
            page_size: 'optional - number of results per page (default is 10)',
            fields: 'optional - comma-separated list of fields 'product,transport_protocol,protocol,banner,country,province,city,asn,org,web,updated_at' (default is nil)'
          )

          #{self}.authors
        "
      end
    end
  end
end
