# frozen_string_literal: true

require 'anemone'

module PWN
  module Plugins
    # This plugin supports Pastebin actions.
    module Spider
      # Supported Method Parameters::
      # PWN::Plugins::Spider.crawl(
      #   target_fqdn: 'required - target fqdn to spider',
      #   results_path: 'required - path to save spider results',
      #   proxy: 'optional - proxy to spider through e.g. http://127.0.0.1:8080'
      # )

      public_class_method def self.crawl(opts = {})
        # TODO: Add AuthN Support
        # FYI: Anemone very well may have a memory leak.
        # Despite saving results to file, Anemone causes
        # memory exhaustion on large sites
        target_fqdn = opts[:target_fqdn].to_s.scrub.strip.chomp
        results_path = opts[:results_path].to_s.scrub.strip.chomp

        proxy = opts[:proxy].to_s.scrub.strip.chomp unless opts[:proxy].nil?

        # Colors!
        green = "\e[32m"
        yellow = "\e[33m"
        end_of_color = "\e[0m"

        puts "#{green}Spidering Target FQDN: #{target_fqdn}#{end_of_color}"
        File.open(results_path, 'w') do |f|
          if proxy
            proxy_uri = URI.parse(proxy)
            proxy_hash = { proxy_host: proxy_uri.host, proxy_port: proxy_uri.port }
            Anemone.crawl(target_fqdn, proxy_hash) do |anemone|
              anemone.on_every_page do |page|
                puts "#{yellow}Discovered: #{page.url}#{end_of_color}"
                f.puts(page.url)
              end
            end
          else
            Anemone.crawl(target_fqdn) do |anemone|
              anemone.on_every_page do |page|
                puts "#{green}Discovered: #{page.url}#{end_of_color}"
                f.puts(page.url)
              end
            end
          end
        end
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
        puts %{USAGE:
          #{self}.crawl(
            target_fqdn: 'required - target fqdn to spider',
            results_path: 'required - path to save spider results',
            proxy: 'optional - proxy to spider through e.g. http://127.0.0.1:8080'
          )

          #{self}.authors
        }
      end
    end
  end
end
