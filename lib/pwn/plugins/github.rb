# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # This plugin is used for interacting w/ Github's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    module Github
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # github_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.github_rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub
        base_gist_api_uri = 'https://api.github.com'

        rest_client = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)::Request

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_gist_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8',
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_gist_api_uri}/#{rest_call}",
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
      rescue RestClient::Forbidden
        raise response
      rescue RestClient::BadRequest, RestClient::NotFound, StandardError => e
        raise
      end

      # Supported Method Parameters::
      # response_json = PWN::Plugins::Github.download_all_gists(
      #   username: 'required - username of gists to backup',
      #   target_dir: 'required - target directory to save respective gists'
      # )

      public_class_method def self.download_all_gists(opts = {})
        username = opts[:username].to_s.scrub
        target_dir = opts[:target_dir].to_s.scrub

        raise "ERROR: #{target_dir} Does Not Exist." unless Dir.exist?(target_dir)

        params = {}
        page = 1
        response_json = [{}]
        while response_json.any?
          params[:page] = page
          response_body = github_rest_call(
            rest_call: "users/#{username}/gists",
            params: params
          ).body

          Dir.chdir(target_dir)
          response_json = JSON.parse(response_body, symbolize_names: true)
          response_json.each do |gist_hash|
            clone_dir = gist_hash[:id]
            clone_uri = gist_hash[:git_pull_url]
            next if Dir.exist?(clone_dir)

            print "Cloning: #{clone_uri}..."
            system(
              'git',
              'clone',
              clone_uri
            )
            puts 'complete.'
          end

          page += 1
        end

        response_json
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
          response_json = #{self}.download_all_gists(
            username: 'required - username of gists to download',
            target_dir: 'required - target directory to save respective gists'
          )

          #{self}.authors
        "
      end
    end
  end
end
