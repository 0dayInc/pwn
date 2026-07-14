# frozen_string_literal: true

require 'json'
require 'uri'
require 'digest'

module PWN
  module AI
    module Agent
      # Social-network / developer-identity OSINT feeds for
      # PWN::AI::Agent::Extrospection.osint. All methods here reopen the
      # Extrospection singleton so osint_dispatch can route to them exactly
      # like the in-file feeds. Everything is best-effort: unreachable
      # endpoints degrade to {error:} rather than raising.
      #
      # Feeds provided:
      #   :keybase :gravatar :mastodon :bluesky :hackernews :stackexchange
      #   :npm :pypi :rubygems :crates :dockerhub :codeberg :sourcehut
      #   :chesscom :lichess :steam :telegram :social_sweep
      #
      # New kind :social routes to the profile-fetch feeds; :username still
      # returns the legacy 3-platform hash for back-compat but now also
      # includes a truncated :social_sweep hit list.
      module Extrospection
        SOCIAL_SITES_FILE = File.expand_path('../../../../../../etc/osint/social_sites.json', __dir__)

        SOCIAL_FEEDS = %i[
          keybase gravatar mastodon bluesky hackernews stackexchange
          npm pypi rubygems crates dockerhub codeberg sourcehut
          chesscom lichess steam telegram social_sweep
        ].freeze

        # ── config ──────────────────────────────────────────────────

        private_class_method def self.osint_social_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :osint, :social) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          {
            sites_file: (cfg[:sites_file] || SOCIAL_SITES_FILE).to_s,
            max_threads: (cfg[:max_threads] || 16).to_i,
            timeout: (cfg[:timeout] || 6).to_i,
            max_sites: (cfg[:max_sites] || 120).to_i,
            mastodon_instance: (cfg[:mastodon_instance] || 'mastodon.social').to_s
          }
        rescue StandardError
          { sites_file: SOCIAL_SITES_FILE, max_threads: 16, timeout: 6, max_sites: 120, mastodon_instance: 'mastodon.social' }
        end

        private_class_method def self.social_http(opts = {})
          url     = opts[:url].to_s
          method  = (opts[:method] || :get).to_sym
          timeout = (opts[:timeout] || osint_social_config[:timeout]).to_i
          return { error: 'empty url' } if url.empty?

          require 'rest-client'
          resp = RestClient::Request.execute(
            method: method,
            url: url,
            timeout: timeout,
            open_timeout: 4,
            max_redirects: 3,
            headers: {
              user_agent: 'Mozilla/5.0 (X11; Linux x86_64) pwn-ai-extrospection',
              accept_language: 'en-US,en;q=0.9'
            }
          )
          final_url = begin
            resp.request.url
          rescue StandardError
            url
          end
          { code: resp.code, body: resp.body.to_s, url: final_url }
        rescue RestClient::ExceptionWithResponse => e
          code = begin
            e.response&.code
          rescue StandardError
            0
          end
          { code: code, body: e.response&.body.to_s, url: url }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message.to_s[0, 120]}", url: url }
        end

        # ── profile feeds (structured JSON) ─────────────────────────

        private_class_method def self.osint_keybase(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          body = http_get_json(url: "https://keybase.io/_/api/1.0/user/lookup.json?usernames=#{URI.encode_www_form_component(q)}")
          return { source: 'keybase.io', username: q, found: false } unless body.is_a?(Hash)

          them = Array(body[:them]).compact.first
          return { source: 'keybase.io', username: q, found: false, status: body.dig(:status, :name) } unless them

          proofs = Array(them.dig(:proofs_summary, :all)).map do |p|
            { type: p[:proof_type], nametag: p[:nametag], url: p[:service_url], state: p[:state] }
          end
          {
            source: 'keybase.io',
            username: q,
            found: true,
            uid: them[:id],
            full_name: them.dig(:profile, :full_name),
            bio: them.dig(:profile, :bio).to_s[0, 200],
            location: them.dig(:profile, :location),
            proofs: proofs,
            pgp_fingerprints: Array(them.dig(:public_keys, :pgp_public_keys)).map { |k| k.is_a?(Hash) ? k[:key_fingerprint] : nil }.compact,
            pivots: proofs.map { |p| { kind: p[:type], value: p[:nametag] } },
            confidence: 0.99
          }
        end

        private_class_method def self.osint_gravatar(opts = {})
          q = opts[:query].to_s.strip.downcase
          # Email → md5 hash; bare handle → profile slug.
          slug = q.include?('@') ? Digest::MD5.hexdigest(q) : q.sub(/\A@/, '')
          body = http_get_json(url: "https://gravatar.com/#{slug}.json")
          entry = body.is_a?(Hash) ? Array(body[:entry]).first : nil
          return { source: 'gravatar.com', query: q, found: false } unless entry

          accounts = Array(entry[:accounts]).map { |a| { domain: a[:domain], username: a[:username], url: a[:url], verified: a[:verified] } }
          {
            source: 'gravatar.com',
            query: q,
            found: true,
            hash: entry[:hash],
            preferred_username: entry[:preferredUsername],
            display_name: entry[:displayName],
            about: entry[:aboutMe].to_s[0, 200],
            location: entry[:currentLocation],
            urls: Array(entry[:urls]).map { |u| u[:value] },
            accounts: accounts,
            pivots: accounts.map { |a| { kind: :username, value: a[:username], via: a[:domain] } },
            confidence: q.include?('@') ? 0.95 : 0.6
          }
        end

        private_class_method def self.osint_mastodon(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          user, host = q.include?('@') ? q.split('@', 2) : [q, osint_social_config[:mastodon_instance]]
          wf = http_get_json(url: "https://#{host}/.well-known/webfinger?resource=acct:#{URI.encode_www_form_component("#{user}@#{host}")}")
          lookup = http_get_json(url: "https://#{host}/api/v1/accounts/lookup?acct=#{URI.encode_www_form_component(user)}")
          found = lookup.is_a?(Hash) && lookup[:id]
          {
            source: 'mastodon',
            acct: "#{user}@#{host}",
            found: found ? true : false,
            webfinger: wf ? { subject: wf[:subject], aliases: wf[:aliases] } : nil,
            profile: found ? lookup.slice(:id, :username, :acct, :display_name, :url, :note, :followers_count, :following_count, :statuses_count, :created_at, :fields) : lookup,
            confidence: found ? 0.85 : 0.0
          }
        end

        private_class_method def self.osint_bluesky(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          actor = q.include?('.') ? q : "#{q}.bsky.social"
          body = http_get_json(url: "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=#{URI.encode_www_form_component(actor)}")
          found = body.is_a?(Hash) && body[:did]
          {
            source: 'bsky.app',
            actor: actor,
            found: found ? true : false,
            profile: found ? body.slice(:did, :handle, :displayName, :description, :followersCount, :followsCount, :postsCount, :indexedAt) : body,
            confidence: found ? 0.85 : 0.0
          }
        end

        private_class_method def self.osint_hackernews(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          user = http_get_json(url: "https://hn.algolia.com/api/v1/users/#{URI.encode_www_form_component(q)}")
          subs = http_get_json(url: "https://hn.algolia.com/api/v1/search?tags=author_#{URI.encode_www_form_component(q)}&hitsPerPage=#{opts[:limit] || 5}")
          found = user.is_a?(Hash) && user[:username]
          {
            source: 'hn.algolia.com',
            username: q,
            found: found ? true : false,
            profile: found ? user.slice(:username, :karma, :created_at, :about) : nil,
            recent: subs.is_a?(Hash) ? Array(subs[:hits]).first(opts[:limit] || 5).map { |h| { title: h[:title] || h[:story_title], url: h[:url], points: h[:points], created_at: h[:created_at] } } : [],
            confidence: found ? 0.8 : 0.0
          }
        end

        private_class_method def self.osint_stackexchange(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          body = http_get_json(url: "https://api.stackexchange.com/2.3/users?order=desc&sort=reputation&inname=#{URI.encode_www_form_component(q)}&site=stackoverflow&pagesize=#{opts[:limit] || 5}")
          items = body.is_a?(Hash) ? Array(body[:items]) : []
          {
            source: 'api.stackexchange.com',
            query: q,
            found: items.any?,
            users: items.first(opts[:limit] || 5).map { |u| u.slice(:user_id, :display_name, :reputation, :location, :website_url, :link, :creation_date) },
            confidence: items.any? { |u| u[:display_name].to_s.casecmp?(q) } ? 0.7 : 0.3
          }
        end

        private_class_method def self.osint_npm(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          body = http_get_json(url: "https://registry.npmjs.org/-/user/org.couchdb.user:#{URI.encode_www_form_component(q)}")
          pkgs = http_get_json(url: "https://registry.npmjs.org/-/v1/search?text=maintainer:#{URI.encode_www_form_component(q)}&size=#{opts[:limit] || 5}")
          {
            source: 'registry.npmjs.org',
            username: q,
            found: body.is_a?(Hash) && body[:name],
            profile: body.is_a?(Hash) ? body.slice(:name, :email, :github, :twitter, :homepage) : nil,
            packages: pkgs.is_a?(Hash) ? Array(pkgs[:objects]).first(opts[:limit] || 5).map { |o| o.dig(:package, :name) } : [],
            confidence: 0.8
          }
        end

        private_class_method def self.osint_pypi(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          r = social_http(url: "https://pypi.org/user/#{URI.encode_www_form_component(q)}/")
          found = r[:code] == 200
          pkgs = found ? r[:body].to_s.scan(%r{/project/([A-Za-z0-9_.-]+)/}).flatten.uniq.first(opts[:limit] || 5) : []
          { source: 'pypi.org', username: q, found: found, http: r[:code], packages: pkgs, confidence: found ? 0.7 : 0.0 }
        end

        private_class_method def self.osint_rubygems(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          gems = http_get_json(url: "https://rubygems.org/api/v1/owners/#{URI.encode_www_form_component(q)}/gems.json")
          {
            source: 'rubygems.org',
            username: q,
            found: gems.is_a?(Array),
            gems: gems.is_a?(Array) ? gems.first(opts[:limit] || 5).map { |g| { name: g[:name], downloads: g[:downloads], homepage: g[:homepage_uri] } } : gems,
            confidence: gems.is_a?(Array) ? 0.85 : 0.0
          }
        end

        private_class_method def self.osint_crates(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          body = http_get_json(url: "https://crates.io/api/v1/users/#{URI.encode_www_form_component(q)}")
          found = body.is_a?(Hash) && body[:user]
          { source: 'crates.io', username: q, found: found ? true : false, profile: found ? body[:user].slice(:id, :login, :name, :url, :avatar) : body, confidence: found ? 0.8 : 0.0 }
        end

        private_class_method def self.osint_dockerhub(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          user  = http_get_json(url: "https://hub.docker.com/v2/users/#{URI.encode_www_form_component(q)}/")
          repos = http_get_json(url: "https://hub.docker.com/v2/repositories/#{URI.encode_www_form_component(q)}/?page_size=#{opts[:limit] || 5}")
          {
            source: 'hub.docker.com',
            username: q,
            found: user.is_a?(Hash) && user[:id],
            profile: user.is_a?(Hash) ? user.slice(:id, :username, :full_name, :location, :company, :profile_url, :date_joined) : nil,
            repositories: repos.is_a?(Hash) ? Array(repos[:results]).first(opts[:limit] || 5).map { |r| { name: r[:name], pulls: r[:pull_count], stars: r[:star_count] } } : [],
            confidence: 0.8
          }
        end

        private_class_method def self.osint_codeberg(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          body = http_get_json(url: "https://codeberg.org/api/v1/users/#{URI.encode_www_form_component(q)}")
          { source: 'codeberg.org', username: q, found: body.is_a?(Hash) && body[:id], profile: body.is_a?(Hash) ? body.slice(:id, :login, :full_name, :email, :website, :location, :created) : body, confidence: 0.8 }
        end

        private_class_method def self.osint_sourcehut(opts = {})
          q = opts[:query].to_s.sub(/\A[@~]/, '').strip
          r = social_http(url: "https://sr.ht/~#{URI.encode_www_form_component(q)}/")
          { source: 'sr.ht', username: q, found: r[:code] == 200, http: r[:code], url: "https://sr.ht/~#{q}/", confidence: r[:code] == 200 ? 0.6 : 0.0 }
        end

        private_class_method def self.osint_chesscom(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          body = http_get_json(url: "https://api.chess.com/pub/player/#{URI.encode_www_form_component(q)}")
          { source: 'api.chess.com', username: q, found: body.is_a?(Hash) && body[:player_id], profile: body.is_a?(Hash) ? body.slice(:username, :name, :country, :location, :joined, :last_online, :url) : body, confidence: 0.7 }
        end

        private_class_method def self.osint_lichess(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          body = http_get_json(url: "https://lichess.org/api/user/#{URI.encode_www_form_component(q)}")
          { source: 'lichess.org', username: q, found: body.is_a?(Hash) && body[:id], profile: body.is_a?(Hash) ? { id: body[:id], username: body[:username], created_at: body[:createdAt], seen_at: body[:seenAt], profile: body[:profile] } : body, confidence: 0.7 }
        end

        private_class_method def self.osint_steam(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          key = opts[:api_key].to_s
          if key.empty?
            r = social_http(url: "https://steamcommunity.com/id/#{URI.encode_www_form_component(q)}/?xml=1")
            found = r[:code] == 200 && r[:body].to_s.include?('<steamID64>')
            id64 = found ? r[:body].to_s[%r{<steamID64>(\d+)</steamID64>}, 1] : nil
            name = found ? r[:body].to_s[%r{<steamID><!\[CDATA\[(.*?)\]\]></steamID>}, 1] : nil
            return { source: 'steamcommunity.com', vanity: q, found: found, steamid64: id64, persona: name, confidence: found ? 0.7 : 0.0, note: 'unauthenticated XML profile; set STEAM_API_KEY for ISteamUser' }
          end
          body = http_get_json(url: "https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/?key=#{key}&vanityurl=#{URI.encode_www_form_component(q)}")
          { source: 'api.steampowered.com', vanity: q, response: body, confidence: 0.8 }
        end

        private_class_method def self.osint_telegram(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          r = social_http(url: "https://t.me/#{URI.encode_www_form_component(q)}")
          body = r[:body].to_s
          title = body[/<meta property="og:title" content="([^"]+)"/i, 1]
          desc  = body[/<meta property="og:description" content="([^"]+)"/i, 1]
          # t.me returns 200 for both; presence heuristic = has tgme_page_title div.
          found = r[:code] == 200 && body.include?('tgme_page_title')
          { source: 't.me', username: q, found: found, http: r[:code], display_name: title, description: desc.to_s[0, 200], url: "https://t.me/#{q}", confidence: found ? 0.6 : 0.0 }
        end

        # ── Sherlock-mode presence sweep ────────────────────────────
        # Concurrent HEAD/GET across the vendored etc/osint/social_sites.json
        # (or a user-supplied file). Returns only *hits* by default so the
        # tool result stays small; misses/errors are counted.

        private_class_method def self.load_social_sites
          cfg  = osint_social_config
          path = cfg[:sites_file]
          raise "social_sites file not found: #{path}" unless File.exist?(path)

          data = JSON.parse(File.read(path), symbolize_names: true)
          Array((data[:sites] || data).to_a).first(cfg[:max_sites]).map do |name, spec|
            spec = { url: spec } if spec.is_a?(String)
            {
              name: name.to_s,
              url: spec[:url],
              method: spec[:head] ? :head : :get,
              absent_status: Array(spec[:absent_status]).map(&:to_i),
              absent_body: Array(spec[:absent_body])
            }
          end
        end

        private_class_method def self.social_sweep_verdict(opts = {})
          site = opts[:site]
          r    = opts[:resp]
          return :error if r[:error]

          code = r[:code].to_i
          body = r[:body].to_s
          absent = site[:absent_status].include?(code) ||
                   # substring match against page body — NOT a set intersection despite the cop name.
                   site[:absent_body].any? { |s| body.include?(s) } || # rubocop:disable Style/ArrayIntersect
                   !code.between?(200, 399)
          absent ? :absent : :present
        end

        private_class_method def self.osint_social_sweep(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          return { error: 'empty username' } if q.empty?

          cfg   = osint_social_config
          sites = load_social_sites
          limit = (opts[:limit] || sites.length).to_i
          hits    = []
          misses  = []
          errors  = []
          mutex   = Mutex.new
          started = Time.now
          require 'concurrent-ruby' unless defined?(Concurrent::FixedThreadPool)
          pool = Concurrent::FixedThreadPool.new(cfg[:max_threads])
          sites.each do |site|
            pool.post do
              url = site[:url].gsub('{u}', URI.encode_www_form_component(q))
              r = social_http(url: url, method: site[:method], timeout: cfg[:timeout])
              verdict = social_sweep_verdict(site: site, resp: r)
              mutex.synchronize do
                case verdict
                when :present then hits << { platform: site[:name], url: url, http: r[:code], confidence: site[:method] == :head ? 0.3 : 0.5 }
                when :absent  then misses << site[:name]
                else errors << { platform: site[:name], error: r[:error].to_s[0, 80] }
                end
              end
            rescue StandardError => e
              mutex.synchronize { errors << { platform: site[:name], error: e.message.to_s[0, 80] } }
            end
          end
          pool.shutdown
          pool.wait_for_termination(cfg[:timeout] * 4)
          {
            source: 'social_sweep',
            username: q,
            sites_checked: sites.length,
            found: hits.length,
            not_found: misses.length,
            errored: errors.length,
            duration_s: (Time.now - started).round(2),
            hits: hits.sort_by { |h| h[:platform] }.first(limit),
            errors: errors.first(10),
            sites_file: cfg[:sites_file],
            note: 'HEAD/GET presence check only — false positives possible on JS-rendered / soft-404 sites. Confidence caps at 0.5; use profile feeds (keybase/bluesky/...) for confirmed identity.'
          }
        end
        # Marker submodule so this file satisfies PWN module conventions
        # (def self.help / def self.authors per-file) WITHOUT clobbering
        # PWN::AI::Agent::Extrospection.help defined in the parent file.
        module OSINTSocial
          # Author(s):: 0day Inc. <support@0dayinc.com>

          public_class_method def self.authors
            "AUTHOR(S):\n0day Inc. <support@0dayinc.com>\n"
          end

          # Display Usage for this Module

          public_class_method def self.help
            <<~USAGE
              Social / identity OSINT feeds for PWN::AI::Agent::Extrospection.osint.
              Feeds: #{SOCIAL_FEEDS.join(', ')}
              Sites file: #{SOCIAL_SITES_FILE}
              See PWN::AI::Agent::Extrospection.help / documentation/Extrospection.md.
            USAGE
          end
        end
      end
    end
  end
end
