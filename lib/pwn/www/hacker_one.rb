# frozen_string_literal: true

require 'json'
require 'uri'
require 'yaml'

module PWN
  module WWW
    # This plugin supports hackerone.com actions.
    module HackerOne
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::HackerOne.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://www.hackerone.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # programs_arr = PWN::WWW::HackerOne.get_bounty_programs(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   proxy: 'optional - scheme://proxy_host:port || tor',
      #   min_payouts_enabled: 'optional - only display programs where payouts are > $0.00 (defaults to false)'
      # )

      public_class_method def self.get_bounty_programs(opts = {})
        browser_obj = opts[:browser_obj]
        browser = browser_obj[:browser]
        min_payouts_enabled = true if opts[:min_payouts_enabled]
        min_payouts_enabled ||= false

        browser.goto('https://hackerone.com/bug-bounty-programs')
        # Wait for JavaScript to load the DOM

        programs_arr = []
        browser.ul(class: 'program__meta-data').wait_until(&:present?)
        browser.uls(class: 'program__meta-data').each do |ul|
          min_payout = ul.text.split('$').last.split.first.to_f

          next if min_payouts_enabled && min_payout.zero?

          print '.'
          link = "https://#{ul.first.text}"
          min_payout_fmt = format('$%0.2f', min_payout)
          scheme = URI.parse(link).scheme
          host = URI.parse(link).host
          path = URI.parse(link).path
          burp_target_config = "#{scheme}://#{host}/teams#{path}/assets/download_burp_project_file.json"

          bounty_program_hash = {
            name: link.split('/').last,
            min_payout: min_payout_fmt,
            policy: "#{link}?view_policy=true",
            burp_target_config: burp_target_config,
            scope: "#{link}/policy_scopes",
            hacktivity: "#{link}/hacktivity",
            thanks: "#{link}/thanks",
            updates: "#{link}/updates",
            collaborators: "#{link}/collaborators"
          }
          programs_arr.push(bounty_program_hash)
        end

        programs_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # scope_details = PWN::WWW::HackerOne.get_scope_details(
      #   program_name: 'required - program name from #get_bounty_programs method',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.get_scope_details(opts = {})
        program_name = opts[:program_name]
        proxy = opts[:proxy]

        browser_obj = PWN::Plugins::TransparentBrowser.open(
          browser_type: :rest,
          proxy: proxy
        )
        rest_client = browser_obj[:browser]
        rest_request = rest_client::Request

        graphql_endpoint = 'https://hackerone.com/graphql'
        headers = { content_type: 'application/json' }
        # NOTE: If you copy this payload to the pwn REPL
        # the triple dots ... attempt to execute commands
        # <cough>Pry CE</cough>
        payload = {
          operationName: 'PolicySearchStructuredScopesQuery',
          variables: {
            handle: program_name,
            searchString: '',
            eligibleForSubmission: nil,
            eligibleForBounty: nil,
            asmTagIds: [],
            from: 0,
            size: 100,
            sort: {
              field: 'cvss_score',
              direction: 'DESC'
            },
            product_area: 'h1_assets',
            product_feature: 'policy_scopes'
          },
          query: 'query PolicySearchStructuredScopesQuery(
            $handle: String!,
            $searchString: String,
            $eligibleForSubmission: Boolean,
            $eligibleForBounty: Boolean,
            $minSeverityScore: SeverityRatingEnum,
            $asmTagIds: [Int],
            $from: Int, $size: Int, $sort: SortInput) {
              team(handle: $handle) {
                id
                structured_scopes_search(
                  search_string: $searchString
                  eligible_for_submission: $eligibleForSubmission
                  eligible_for_bounty: $eligibleForBounty
                  min_severity_score: $minSeverityScore
                  asm_tag_ids: $asmTagIds
                  from: $from
                  size: $size
                  sort: $sort
                ) {
                  nodes {
                    ... on StructuredScopeDocument {
                      id
                      ...PolicyScopeStructuredScopeDocument
                      __typename
                    }
                    __typename
                  }
                  pageInfo {
                    startCursor
                    hasPreviousPage
                    endCursor
                    hasNextPage
                    __typename
                  }
                  total_count
                  __typename
                }
                __typename
              }
            }

            fragment PolicyScopeStructuredScopeDocument on StructuredScopeDocument {
              id
              identifier
              display_name
              instruction
              cvss_score
              eligible_for_bounty
              eligible_for_submission
              asm_system_tags
              created_at
              updated_at
              attachments {
                id
                file_name
                file_size
                content_type
                expiring_url
                __typename
              }
              __typename
            }
          '
        }

        rest_response = rest_request.execute(
          method: :post,
          url: graphql_endpoint,
          headers: headers,
          payload: payload.to_json.delete("\n"),
          verify_ssl: false
        )

        JSON.parse(rest_response.body, symbolize_names: true)
      rescue RestClient::ExceptionWithResponse => e
        if e.response
          puts "HTTP RESPONSE CODE: #{e.response.code}"
          puts "HTTP RESPONSE HEADERS:\n#{e.response.headers}"
          puts "HTTP RESPONSE BODY:\n#{e.response.body}\n\n\n"
        end

        raise e
      rescue StandardError => e
        raise e
      ensure
        browser_obj = PWN::Plugins::TransparentBrowser.close(browser_obj: browser_obj) if browser_obj
        rest_client = nil if rest_client
        rest_request = nil if rest_request
      end
      # Supported Method Parameters::
      # PWN::WWW::HackerOne.save_burp_target_config_file(
      #   programs_arr: 'required - array of hashes returned from #get_bounty_programs method',
      #   browser_opts: 'optional - opts supported by PWN::Plugins::TransparentBrowser.open method',
      #   name: 'optional - name of burp target config file (defaults to ALL)',
      #   root_dir: 'optional - directory to save burp target config files (defaults to "./"))'
      # )

      public_class_method def self.save_burp_target_config_file(opts = {})
        programs_arr = opts[:programs_arr]
        raise 'ERROR: programs_arr should be data returned from #get_bounty_programs' unless programs_arr.any?

        browser_opts = opts[:browser_opts]
        raise 'ERROR: browser_opts should be a hash' unless browser_opts.nil? ||
                                                            browser_opts.is_a?(Hash)

        browser_opts ||= {}
        browser_opts[:browser_type] = :rest

        name = opts[:name]
        root_dir = opts[:root_dir]

        rest_obj = PWN::Plugins::TransparentBrowser.open(browser_opts)
        rest_client = rest_obj[:browser]::Request
        user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36'

        if name
          path = "./burp_target_config_file-#{name}.json" if opts[:root_dir].nil?
          path = "#{root_dir}/burp_target_config_file-#{name}.json" unless opts[:root_dir].nil?
          burp_download_link = programs_arr.select do |program|
            program[:name] == name
          end.first[:burp_target_config]

          resp = rest_client.execute(
            method: :get,
            headers: { user_agent: user_agent },
            url: burp_download_link
          )
          json_resp = JSON.parse(resp.body)

          puts "Saving to: #{path}"
          File.write(path, JSON.pretty_generate(json_resp))
        else
          programs_arr.each do |program|
            name = program[:name]
            burp_download_link = program[:burp_target_config]
            path = "./burp_target_config_file-#{name}.json" if opts[:root_dir].nil?
            path = "#{root_dir}/burp_target_config_file-#{name}.json" unless opts[:root_dir].nil?

            resp = rest_client.execute(
              method: :get,
              headers: { user_agent: user_agent },
              url: burp_download_link
            )
            json_resp = JSON.parse(resp.body)

            puts "Saving to: #{path}"
            File.write(path, JSON.pretty_generate(json_resp))
          rescue JSON::ParserError,
                 RestClient::NotFound
            puts '-'
            next
          end
        end
        puts 'complete.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::HackerOne.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username',
      #   password: 'optional - passwd (will prompt if blank)'
      # )

      public_class_method def self.login(opts = {})
        browser_obj = opts[:browser_obj]
        username = opts[:username].to_s.scrub.strip.chomp
        password = opts[:password]

        browser = browser_obj[:browser]

        if password.nil?
          password = PWN::Plugins::AuthenticationHelper.mask_password
        else
          password = opts[:password].to_s.scrub.strip.chomp
        end

        browser.goto('https://hackerone.com/users/sign_in')

        browser.text_field(name: 'user[email]').wait_until(&:present?).set(username)
        browser.text_field(name: 'user[password]').wait_until(&:present?).set(password)
        browser.button(name: 'commit').click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::HackerOne.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]

        browser = browser_obj[:browser]
        browser.i(class: 'icon-arrow-closure').click!
        browser.link(index: 16).click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::HackerOne.close(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.close(opts = {})
        browser_obj = opts[:browser_obj]
        PWN::Plugins::TransparentBrowser.close(
          browser_obj: browser_obj
        )
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
          browser_obj = #{self}.open(
            browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port || tor'
          )

          programs_arr = #{self}.get_bounty_programs(
            browser_obj: 'required - browser_obj returned from #open method',
            proxy: 'optional - scheme://proxy_host:port || tor',
            min_payouts_enabled: 'optional - only display programs where payouts are > $0.00 (defaults to false)'
          )

          scope_details = PWN::WWW::HackerOne.get_scope_details(
            program_name: 'required - program name from #get_bounty_programs method',
            proxy: 'optional - scheme://proxy_host:port || tor'
          )

          #{self}.save_burp_target_config_file(
            programs_arr: 'required - array of hashes returned from #get_bounty_programs method',
            browser_opts: 'optional - opts supported by PWN::Plugins::TransparentBrowser.open method',
            name: 'optional - name of burp target config file (defaults to ALL)',
            root_dir: 'optional - directory to save burp target config files (defaults to \"./\"))'
          )

          browser_obj = #{self}.login(
            browser_obj: 'required - browser_obj returned from #open method',
            username: 'required - username',
            password: 'optional - passwd (will prompt if blank),
          )

          browser_obj = #{self}.logout(
            browser_obj: 'required - browser_obj returned from #open method'
          )

          #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method'
          )

          #{self}.authors
        "
      end
    end
  end
end
