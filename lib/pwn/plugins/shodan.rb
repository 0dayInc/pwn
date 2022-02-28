# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # This plugin is used for interacting w/ Shodan's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    #  This is based on the following Shodan API Specification:
    # https://developer.shodan.io/api
    module Shodan
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # shodan_rest_call(
      #   api_key: 'required - shodan api key',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.shodan_rest_call(opts = {})
        shodan_obj = opts[:shodan_obj]
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        base_shodan_api_uri = 'https://api.shodan.io'
        api_key = opts[:api_key]

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_shodan_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_shodan_api_uri}/#{rest_call}",
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
        response
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      end

      # Supported Method Parameters::
      # services_by_ips = PWN::Plugins::Shodan.services_by_ips(
      #   api_key: 'required shodan api key',
      #   target_ips: 'required - comma-delimited list of ip addresses to target'
      # )

      public_class_method def self.services_by_ips(opts = {})
        api_key = opts[:api_key].to_s.scrub
        target_ips = opts[:target_ips].to_s.scrub.gsub(/\s/, '').split(',')

        services_by_ips = []
        params = { key: api_key }
        target_ips.each do |target_ip|
          response = shodan_rest_call(
            api_key: api_key,
            rest_call: "shodan/host/#{target_ip}",
            params: params
          )
          services_by_ips.push(JSON.parse(response))
        rescue StandardError => e
          services_by_ips.push(error: e.message)
          next
        end
        services_by_ips
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # query_result_totals = PWN::Plugins::Shodan.query_result_totals(
      #   api_key: 'required shodan api key',
      #   query: 'required - shodan search query',
      #   facets: 'optional - comma-separated list of properties to get summary information'
      # )

      public_class_method def self.query_result_totals(opts = {})
        api_key = opts[:api_key].to_s.scrub
        query = opts[:query].to_s.scrub
        facets = opts[:facets].to_s.scrub

        if facets
          params = {
            key: api_key,
            query: query,
            facets: facets
          }

        else
          params = {
            key: api_key,
            query: query
          }
        end

        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/host/count',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # search_results = PWN::Plugins::Shodan.search(
      #   api_key: 'required shodan api key',
      #   query: 'required - shodan search query',
      #   facets: 'optional - comma-separated list of properties to get summary information'
      # )

      public_class_method def self.search(opts = {})
        api_key = opts[:api_key].to_s.scrub
        query = opts[:query].to_s.scrub
        facets = opts[:facets].to_s.scrub

        if facets
          params = {
            key: api_key,
            query: query,
            facets: facets
          }
        else
          params = {
            key: api_key,
            query: query
          }
        end

        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/host/search',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # tokens_result = PWN::Plugins::Shodan.tokens(
      #   api_key: 'required shodan api key',
      #   query: 'required - shodan search query',
      # )

      public_class_method def self.tokens(opts = {})
        api_key = opts[:api_key].to_s.scrub
        query = opts[:query].to_s.scrub

        params = {
          key: api_key,
          query: query
        }

        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/host/search/tokens',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # ports_shodan_crawls = PWN::Plugins::Shodan.ports_shodan_crawls(
      #   api_key: 'required shodan api key'
      # )

      public_class_method def self.ports_shodan_crawls(opts = {})
        api_key = opts[:api_key].to_s.scrub

        params = { key: api_key }
        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/ports',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # protocols = PWN::Plugins::Shodan.list_on_demand_scan_protocols(
      #   api_key: 'required shodan api key'
      # )

      public_class_method def self.list_on_demand_scan_protocols(opts = {})
        api_key = opts[:api_key].to_s.scrub

        params = { key: api_key }
        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/protocols',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # scan__networkresponse = PWN::Plugins::Shodan.scan_network(
      #   api_key: 'required shodan api key',
      #   target_ips: 'required - comma-delimited list of ip addresses to target'
      # )

      public_class_method def self.scan_network(opts = {})
        api_key = opts[:api_key].to_s.scrub
        target_ips = opts[:target_ips].to_s.scrub.gsub(/\s/, '')

        params = { key: api_key }
        http_body = "ips=#{target_ips}"
        response = shodan_rest_call(
          http_method: :post,
          api_key: api_key,
          rest_call: 'shodan/scan',
          params: params,
          http_body: http_body
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # scan_internet_response = PWN::Plugins::Shodan.scan_internet(
      #   api_key: 'required shodan api key',
      #   port: 'required - port to scan (see #ports_shodan_crawls for list)',
      #   protocol: 'required - supported shodan protocol (see #list_on_demand_scan_protocols for list)'
      # )

      public_class_method def self.scan_internet(opts = {})
        api_key = opts[:api_key].to_s.scrub
        port = opts[:port].to_i
        protocol = opts[:protocol].to_s.scrub

        params = { key: api_key }
        http_body = "port=#{port}&protocol=#{protocol}"
        response = shodan_rest_call(
          http_method: :post,
          api_key: api_key,
          rest_call: 'shodan/scan/internet',
          params: params,
          http_body: http_body
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # scan_status_result = PWN::Plugins::Shodan.scan_status(
      #   api_key: 'required shodan api key',
      #   scan_id: 'required - unique ID returned by #scan_network',
      # )

      public_class_method def self.scan_status(opts = {})
        api_key = opts[:api_key].to_s.scrub
        scan_id = opts[:scan_id].to_s.scrub

        params = {
          key: api_key
        }

        response = shodan_rest_call(
          api_key: api_key,
          rest_call: "shodan/scan/status/#{scan_id}",
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # services_shodan_crawls = PWN::Plugins::Shodan.services_shodan_crawls(
      #   api_key: 'required shodan api key'
      # )

      public_class_method def self.services_shodan_crawls(opts = {})
        api_key = opts[:api_key].to_s.scrub

        params = { key: api_key }
        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/services',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # saved_search_queries_result = PWN::Plugins::Shodan.saved_search_queries(
      #   api_key: 'required shodan api key',
      #   page: 'optional - page number to iterate over results (each page contains 10 items)',
      #   sort: 'optional - sort results by available parameters :votes|:timestamp',
      #   order: 'optional - sort :asc|:desc (ascending or descending)'
      # )

      public_class_method def self.saved_search_queries(opts = {})
        api_key = opts[:api_key].to_s.scrub
        page = opts[:page].to_i
        sort = opts[:sort].to_sym
        order = opts[:order].to_sym

        params = {
          key: api_key,
          page: page,
          sort: sort.to_s,
          order: order.to_s
        }
        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/query',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # most_popular_tags_result = PWN::Plugins::Shodan.most_popular_tags(
      #   api_key: 'required shodan api key',
      #   result_count: 'optional - number of results to return (defaults to 10)'
      # )

      public_class_method def self.most_popular_tags(opts = {})
        api_key = opts[:api_key].to_s.scrub
        result_count = opts[:result_count].to_i

        if result_count
          params = {
            key: api_key,
            size: result_count
          }
        else
          params = { key: api_key }
        end

        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'shodan/query/tags',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # my_profile = PWN::Plugins::Shodan.my_profile(
      #   api_key: 'required shodan api key'
      # )

      public_class_method def self.my_profile(opts = {})
        api_key = opts[:api_key].to_s.scrub

        params = { key: api_key }
        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'account/profile',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # my_pub_ip = PWN::Plugins::Shodan.my_pub_ip(
      #   api_key: 'required shodan api key'
      # )

      public_class_method def self.my_pub_ip(opts = {})
        api_key = opts[:api_key].to_s.scrub

        params = { key: api_key }
        shodan_rest_call(
          api_key: api_key,
          rest_call: 'tools/myip',
          params: params
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # api_info = PWN::Plugins::Shodan.api_info(
      #   api_key: 'required shodan api key'
      # )

      public_class_method def self.api_info(opts = {})
        api_key = opts[:api_key].to_s.scrub

        params = { key: api_key }
        response = shodan_rest_call(
          api_key: api_key,
          rest_call: 'api-info',
          params: params
        )
        JSON.parse(response)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # honeypot_probability_scores = PWN::Plugins::Shodan.honeypot_probability_scores(
      #   api_key: 'required shodan api key',
      #   target_ips: 'required - comma-delimited list of ip addresses to target'
      # )

      public_class_method def self.honeypot_probability_scores(opts = {})
        api_key = opts[:api_key].to_s.scrub
        target_ips = opts[:target_ips].to_s.scrub.gsub(/\s/, '').split(',')

        honeypot_probability_scores = []
        params = { key: api_key }
        target_ips.each do |target_ip|
          response = shodan_rest_call(
            api_key: api_key,
            rest_call: "labs/honeyscore/#{target_ip}",
            params: params
          )
          honeypot_probability_scores.push("#{target_ip} => #{response}")
        end
        honeypot_probability_scores
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
          services_by_ips = #{self}.services_by_ips(
            api_key: 'required - shodan api key',
            target_ips: 'required - comma-delimited list of ip addresses to target'
          )

          query_result_totals = PWN::Plugins::Shodan.query_result_totals(
            api_key: 'required shodan api key',
            query: 'required - shodan search query',
            facets: 'optional - comma-separated list of properties to get summary information'
          )

          search_results = #{self}.search(
            api_key: 'required shodan api key',
            query: 'required - shodan search query',
            facets: 'optional - comma-separated list of properties to get summary information'
          )

          tokens_result = #{self}.tokens(
            api_key: 'required shodan api key',
            query: 'required - shodan search query',
          )

          ports_shodan_crawls = #{self}.ports_shodan_crawls(
            api_key: 'required shodan api key'
          )

          protocols = #{self}.list_on_demand_scan_protocols(
            api_key: 'required shodan api key'
          )

          scan_network_response = #{self}.scan_network(
            api_key: 'required shodan api key',
            target_ips: 'required - comma-delimited list of ip addresses to target'
          )

          scan_internet_response = #{self}.scan_internet(
            api_key: 'required shodan api key',
            port: 'required - port to scan (see #ports_shodan_crawls for list)',
            protocol: 'required - supported shodan protocol (see #list_on_demand_scan_protocols for list)'
          )

          scan_status_result = #{self}.scan_status(
            api_key: 'required shodan api key',
            scan_id: 'required - unique ID returned by #scan_network',
          )

          services_shodan_crawls = #{self}.services_shodan_crawls(
            api_key: 'required shodan api key'
          )

          saved_search_queries_result = #{self}.saved_search_queries(
            api_key: 'required shodan api key',
            page: 'optional - page number to iterate over results (each page contains 10 items)',
            sort: 'optional - sort results by available parameters :votes|:timestamp',
            order: 'optional - sort :asc|:desc (ascending or descending)'
          )

          most_popular_tags_result = #{self}.most_popular_tags(
            api_key: 'required shodan api key',
            result_count: 'optional - number of results to return (defaults to 10)'
          )

          my_profile = #{self}.my_profile(
            api_key: 'required shodan api key'
          )

          my_pub_ip = #{self}.my_pub_ip(
            api_key: 'required shodan api key'
          )

          api_info = #{self}.api_info(
            api_key: 'required shodan api key'
          )

          honeypot_probability_scores = #{self}.honeypot_probability_scores(
            api_key: 'required shodan api key',
            target_ips: 'required - comma-delimited list of ip addresses to target'
          )

          #{self}.authors
        "
      end
    end
  end
end
