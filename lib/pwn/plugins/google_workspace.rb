# frozen_string_literal: true

require 'base64'
require 'cgi'
require 'digest'
require 'fileutils'
require 'json'
require 'rest-client'
require 'securerandom'
require 'socket'
require 'timeout'
require 'time'
require 'tmpdir'
require 'uri'
require 'yaml'

module PWN
  module Plugins
    # Google Workspace REST client (Gmail, Calendar, Drive, Docs, Sheets).
    # OAuth 2.0 authorization-code + PKCE, same vault/env pattern as
    # PWN::AI::* obtain/refresh_oauth_bearer_token.
    #
    # Credentials live in PWN::Env[:plugins][:google_workspace][:oauth]
    # (seeded by PWN::Config / pwn-vault). Desktop-app client_id +
    # client_secret come from Google Cloud Console. After
    # obtain_oauth_auth_url. When wait is true (default), a loopback
    # listener captures the redirect as soon as the operator authorizes
    # the URL; refresh/bearer are written into PWN::Env and the encrypted
    # ~/.pwn/pwn.yaml the same way PWN::AI::Grok persists OAuth tokens.
    module GoogleWorkspace
      AUTH_URI = 'https://accounts.google.com/o/oauth2/v2/auth'
      TOKEN_URI = 'https://oauth2.googleapis.com/token'
      REVOKE_URI = 'https://oauth2.googleapis.com/revoke'
      REDIRECT_URI = 'http://127.0.0.1:1/'
      GMAIL_API = 'https://gmail.googleapis.com/gmail/v1'
      CAL_API = 'https://www.googleapis.com/calendar/v3'
      DRIVE_API = 'https://www.googleapis.com/drive/v3'
      DRIVE_UPLOAD = 'https://www.googleapis.com/upload/drive/v3'
      DOCS_API = 'https://docs.googleapis.com/v1'
      SHEETS_API = 'https://sheets.googleapis.com/v4'
      PENDING_FILE = File.join(Dir.home, '.pwn', 'google_oauth_pending.json')

      SERVICE_SCOPES = {
        'email' => 'https://www.googleapis.com/auth/gmail.modify',
        'gmail' => 'https://www.googleapis.com/auth/gmail.modify',
        'calendar' => 'https://www.googleapis.com/auth/calendar',
        'drive' => 'https://www.googleapis.com/auth/drive',
        'docs' => 'https://www.googleapis.com/auth/documents',
        'sheets' => 'https://www.googleapis.com/auth/spreadsheets'
      }.freeze

      EXPORT_MIME = {
        'application/vnd.google-apps.document' => 'application/pdf',
        'application/vnd.google-apps.spreadsheet' => 'text/csv',
        'application/vnd.google-apps.presentation' => 'application/pdf',
        'application/vnd.google-apps.drawing' => 'image/png'
      }.freeze

      private_class_method def self.real_config_value?(opts = {})
        s = opts[:value].to_s.strip
        return false if s.empty?
        return false if s.match?(/\A(optional|required)\b/i)

        true
      end

      private_class_method def self.cfg(opts = {})
        live = {}
        if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
          slot = PWN::Env.dig(:plugins, :google_workspace, :oauth)
          live = slot.dup if slot.is_a?(Hash)
        end
        live.merge!(opts) if opts.is_a?(Hash)
        live
      end

      public_class_method def self.scopes(opts = {})
        explicit = opts[:scope].to_s.strip
        return explicit.split(/\s+/) if real_config_value?(value: explicit)

        raw = opts[:services]
        raw = cfg[:services] unless real_config_value?(value: raw)
        names = raw.to_s.split(/[,\s]+/).map(&:downcase).reject(&:empty?)
        names = SERVICE_SCOPES.keys if names.empty? || names.include?('all')
        names.filter_map { |n| SERVICE_SCOPES[n] }.uniq
      end

      public_class_method def self.parse_oauth_code(opts = {})
        raw = opts[:code].to_s.strip
        return '' if raw.empty?
        return raw unless raw.include?('://') || raw.include?('code=')

        uri = URI.parse(raw)
        URI.decode_www_form(uri.query.to_s).to_h['code'].to_s
      rescue URI::InvalidURIError
        raw[/code=([^&\s]+)/, 1].to_s
      end

      private_class_method def self.pkce_pair(opts = {})
        return unless opts.is_a?(Hash)

        verifier = Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false)
        challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
        { verifier: verifier, challenge: challenge }
      end

      private_class_method def self.save_pending!(opts = {})
        data = {
          verifier: opts[:verifier],
          redirect_uri: opts[:redirect_uri],
          client_id: opts[:client_id],
          created_at: Time.now.to_i
        }
        FileUtils.mkdir_p(File.dirname(PENDING_FILE))
        File.write(PENDING_FILE, JSON.pretty_generate(data))
        File.chmod(0o600, PENDING_FILE)
        data
      end

      private_class_method def self.load_pending(opts = {})
        return {} unless opts.is_a?(Hash)
        return {} unless File.file?(PENDING_FILE)

        JSON.parse(File.read(PENDING_FILE), symbolize_names: true)
      rescue StandardError
        {}
      end

      public_class_method def self.obtain_oauth_auth_url(opts = {})
        c = cfg(opts)
        client_id = c[:client_id]
        raise 'client_id is required (Google Cloud Desktop OAuth client)' unless real_config_value?(value: client_id)

        wait = opts.key?(:wait) ? opts[:wait] : true
        timeout_s = (opts[:timeout] || 300).to_i
        redirect = real_config_value?(value: c[:redirect_uri]) ? c[:redirect_uri] : REDIRECT_URI
        wanted = scopes(opts.merge(services: c[:services], scope: c[:scope]))
        raise 'no Google scopes selected' if wanted.empty?

        server = nil
        if wait && !opts[:probe].respond_to?(:call)
          server = open_oauth_listener(redirect_uri: redirect)
          redirect = listener_redirect(server: server, fallback: redirect)
        end

        pkce = pkce_pair
        save_pending!(verifier: pkce[:verifier], redirect_uri: redirect, client_id: client_id)

        params = {
          client_id: client_id,
          redirect_uri: redirect,
          response_type: 'code',
          scope: wanted.join(' '),
          access_type: 'offline',
          prompt: 'consent',
          include_granted_scopes: 'true',
          code_challenge: pkce[:challenge],
          code_challenge_method: 'S256'
        }
        url = "#{AUTH_URI}?#{URI.encode_www_form(params)}"
        return { auth_url: url, scope: wanted, redirect_uri: redirect } unless wait

        puts "\n[*] Google Workspace OAuth — authorize this URL, then tokens persist automatically:"
        puts "            #{url}"
        puts "    Waiting for authorization on #{redirect} (timeout #{timeout_s}s)..."
        code = await_oauth_redirect(
          redirect_uri: redirect,
          timeout: timeout_s,
          probe: opts[:probe],
          server: server
        )
        exchange_oauth_code(
          opts.merge(
            code: code,
            redirect_uri: redirect,
            code_verifier: pkce[:verifier],
            client_id: client_id,
            client_secret: c[:client_secret]
          )
        )
      ensure
        begin
          server&.close
        rescue StandardError
          nil
        end
      end

      private_class_method def self.open_oauth_listener(opts = {})
        redirect = opts[:redirect_uri].to_s
        uri = URI.parse(redirect.empty? ? REDIRECT_URI : redirect)
        host = uri.host.to_s
        host = '127.0.0.1' if host.empty?
        port = uri.port.to_i
        port = 0 if port <= 1
        TCPServer.new(host, port)
      end

      private_class_method def self.listener_redirect(opts = {})
        server = opts[:server]
        fallback = opts[:fallback].to_s
        return fallback unless server

        addr = server.addr
        host = addr[3].to_s
        host = '127.0.0.1' if host.empty? || host == '0.0.0.0'
        "http://#{host}:#{addr[1]}/"
      end

      private_class_method def self.await_oauth_redirect(opts = {})
        redirect = opts[:redirect_uri].to_s
        timeout_s = (opts[:timeout] || 300).to_i
        probe = opts[:probe]
        return probe.call(redirect) if probe.respond_to?(:call)

        server = opts[:server]
        owned = false
        unless server
          server = open_oauth_listener(redirect_uri: redirect)
          owned = true
        end
        code = nil
        Timeout.timeout(timeout_s) do
          client = server.accept
          request_line = client.gets.to_s
          loop do
            line = client.gets
            break if line.nil? || line.strip.empty?
          end
          path = request_line.split[1].to_s
          path = '/' if path.empty?
          uri = URI.parse(path.start_with?('http') ? path : "http://127.0.0.1#{path}")
          code = URI.decode_www_form(uri.query.to_s).to_h['code'].to_s
          body = "PWN Google Workspace authorized. You can close this tab.\n"
          client.print "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
          client.close
        end
        raise 'Google OAuth redirect contained no code' if code.to_s.empty?

        code
      rescue Timeout::Error
        raise 'Google OAuth timed out waiting for authorization'
      ensure
        if owned
          begin
            server&.close
          rescue StandardError
            nil
          end
        end
      end

      public_class_method def self.exchange_oauth_code(opts = {})
        c = cfg(opts)
        code = parse_oauth_code(code: opts[:code])
        raise 'code is required (paste the redirect URL or the code= value)' if code.empty?

        pending = load_pending
        client_id = real_config_value?(value: c[:client_id]) ? c[:client_id] : pending[:client_id]
        secret = c[:client_secret]
        redirect = real_config_value?(value: c[:redirect_uri]) ? c[:redirect_uri] : (pending[:redirect_uri] || REDIRECT_URI)
        verifier = opts[:code_verifier] || pending[:verifier]
        raise 'client_id is required' unless real_config_value?(value: client_id)
        raise 'client_secret is required' unless real_config_value?(value: secret)
        raise 'missing PKCE verifier — call obtain_oauth_auth_url first' unless real_config_value?(value: verifier)

        resp = RestClient.post(
          TOKEN_URI,
          {
            grant_type: 'authorization_code',
            code: code,
            client_id: client_id,
            client_secret: secret,
            redirect_uri: redirect,
            code_verifier: verifier
          },
          content_type: 'application/x-www-form-urlencoded',
          accept: 'application/json'
        )
        data = JSON.parse(resp.body)
        raise "Google OAuth error: #{data['error']} - #{data['error_description']}" if data['error']

        oauth = {
          bearer_token: data['access_token'],
          refresh_token: data['refresh_token'] || c[:refresh_token],
          expires_at: data['expires_in'] ? Time.now.to_i + data['expires_in'].to_i : nil,
          client_id: client_id,
          client_secret: secret,
          redirect_uri: redirect
        }
        oauth[:scope] = data['scope'] if data['scope']
        sync_oauth_into_env(oauth: oauth)
        persist_oauth_to_vault(oauth: oauth)
        FileUtils.rm_f(PENDING_FILE)
        oauth
      rescue RestClient::ExceptionWithResponse => e
        raise "Google OAuth code exchange failed (HTTP #{e.http_code}): #{e.response&.body}"
      end

      public_class_method def self.refresh_oauth_bearer_token(opts = {})
        c = cfg(opts)
        refresh = opts[:refresh_token] || c[:refresh_token]
        raise 'refresh_token is required' unless real_config_value?(value: refresh)

        client_id = opts[:client_id] || c[:client_id]
        secret = opts[:client_secret] || c[:client_secret]
        raise 'client_id is required' unless real_config_value?(value: client_id)
        raise 'client_secret is required' unless real_config_value?(value: secret)

        resp = RestClient.post(
          TOKEN_URI,
          {
            grant_type: 'refresh_token',
            refresh_token: refresh,
            client_id: client_id,
            client_secret: secret
          },
          content_type: 'application/x-www-form-urlencoded',
          accept: 'application/json'
        )
        data = JSON.parse(resp.body)
        raise "Google OAuth refresh error: #{data['error']} - #{data['error_description']}" if data['error']

        oauth = c.merge(
          bearer_token: data['access_token'],
          refresh_token: data['refresh_token'] || refresh,
          expires_at: data['expires_in'] ? Time.now.to_i + data['expires_in'].to_i : c[:expires_at]
        )
        sync_oauth_into_env(oauth: oauth)
        persist_oauth_to_vault(oauth: oauth)
        data['access_token']
      rescue RestClient::ExceptionWithResponse => e
        raise "Google OAuth refresh failed (HTTP #{e.http_code}): #{e.response&.body}"
      end

      public_class_method def self.bearer_token(opts = {})
        c = cfg(opts)
        token = c[:bearer_token]
        exp = c[:expires_at].to_i
        stale = !real_config_value?(value: token) || (exp.positive? && Time.now.to_i >= (exp - 120))
        return refresh_oauth_bearer_token(opts.merge(refresh_token: c[:refresh_token])) if stale && real_config_value?(value: c[:refresh_token])
        raise 'not authenticated — run obtain_oauth_auth_url (tokens persist on authorize)' unless real_config_value?(value: token)

        token
      end

      public_class_method def self.authenticated?(opts = {})
        c = cfg(opts)
        real_config_value?(value: c[:refresh_token]) || real_config_value?(value: c[:bearer_token])
      end

      public_class_method def self.revoke(opts = {})
        c = cfg(opts)
        tok = c[:refresh_token] || c[:bearer_token]
        RestClient.post(REVOKE_URI, { token: tok }, content_type: 'application/x-www-form-urlencoded') if real_config_value?(value: tok)
        blank = { bearer_token: nil, refresh_token: nil, expires_at: nil }
        sync_oauth_into_env(oauth: c.merge(blank))
        persist_oauth_to_vault(oauth: c.merge(blank.merge(bearer_token: '')))
        FileUtils.rm_f(PENDING_FILE)
        true
      rescue RestClient::ExceptionWithResponse
        true
      end

      private_class_method def self.sync_oauth_into_env(opts = {})
        oauth = opts[:oauth]
        return false unless oauth.is_a?(Hash)
        return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

        plugins = PWN::Env[:plugins]
        return false unless plugins.is_a?(Hash)

        gw = plugins[:google_workspace]
        gw = plugins[:google_workspace] = {} unless gw.is_a?(Hash)
        live = gw[:oauth]
        live = gw[:oauth] = {} unless live.is_a?(Hash)
        %i[bearer_token refresh_token expires_at client_id client_secret redirect_uri scope].each do |k|
          live[k] = oauth[k] if oauth.key?(k)
        end
        true
      rescue StandardError
        false
      end

      private_class_method def self.persist_oauth_to_vault(opts = {})
        oauth = opts[:oauth]
        return false unless oauth.is_a?(Hash)

        env_path = nil
        dec_path = nil
        if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
          env_path = PWN::Env.dig(:driver_opts, :pwn_env_path)
          dec_path = PWN::Env.dig(:driver_opts, :pwn_dec_path)
        end
        env_path = env_path.to_s.strip
        env_path = File.join(Dir.home, '.pwn', 'pwn.yaml') if env_path.empty?
        dec_path = dec_path.to_s.strip
        dec_path = "#{env_path}.decryptor" if dec_path.empty?

        unless File.exist?(env_path) && File.exist?(dec_path) && File.readable?(dec_path)
          puts '[*] INFO: Google Workspace OAuth tokens updated in this session only; ' \
               "persistence to #{env_path} skipped (missing decryption artifacts)."
          return false
        end

        decryptor = YAML.load_file(dec_path, symbolize_names: true)
        key = decryptor.is_a?(Hash) ? decryptor[:key] : nil
        iv = decryptor.is_a?(Hash) ? decryptor[:iv] : nil
        unless real_config_value?(value: key) && real_config_value?(value: iv)
          puts '[*] INFO: Google Workspace OAuth tokens updated in this session only; ' \
               'decryptor has no usable key/iv.'
          return false
        end

        PWN::Plugins::Vault.decrypt(file: env_path, key: key, iv: iv)
        begin
          vault = YAML.load_file(env_path, symbolize_names: true)
          vault = {} unless vault.is_a?(Hash)
          vault[:plugins] = {} unless vault[:plugins].is_a?(Hash)
          vault[:plugins][:google_workspace] = {} unless vault[:plugins][:google_workspace].is_a?(Hash)
          slot = vault[:plugins][:google_workspace][:oauth]
          slot = vault[:plugins][:google_workspace][:oauth] = {} unless slot.is_a?(Hash)
          %i[bearer_token refresh_token expires_at client_id client_secret redirect_uri scope].each do |k|
            slot[k] = oauth[k] if oauth.key?(k) && !oauth[k].nil?
          end
          yaml_env = YAML.dump(vault).gsub(/^(\s*):/, '\1')
          File.write(env_path, yaml_env)
          File.chmod(0o600, env_path)
        ensure
          PWN::Plugins::Vault.encrypt(file: env_path, key: key, iv: iv)
        end
        true
      rescue StandardError => e
        warn "[!] Google Workspace OAuth vault persistence failed (session tokens still updated): #{e.class}: #{e.message}"
        false
      end

      private_class_method def self.api(opts = {})
        method = (opts[:http_method] || :get).to_s.to_sym
        url = opts[:url].to_s
        headers = {
          authorization: "Bearer #{bearer_token(opts)}",
          accept: 'application/json'
        }
        headers[:content_type] = opts[:content_type] || 'application/json' if %i[post put patch].include?(method)
        headers[:params] = opts[:params] if opts[:params]
        payload = opts[:http_body]
        payload = payload.to_json if payload.is_a?(Hash) || payload.is_a?(Array)
        raw = opts[:raw]
        tries = 0
        begin
          resp = RestClient::Request.execute(
            method: method,
            url: url,
            headers: headers,
            payload: payload,
            raw_response: raw == true
          )
          return resp if raw

          return {} if resp.to_s.strip.empty?

          JSON.parse(resp.body, symbolize_names: true)
        rescue RestClient::Unauthorized
          tries += 1
          raise if tries > 1

          refresh_oauth_bearer_token(opts)
          headers[:authorization] = "Bearer #{bearer_token(opts)}"
          retry
        rescue RestClient::ExceptionWithResponse => e
          raise "Google API #{method.upcase} #{url} failed (HTTP #{e.http_code}): #{e.response&.body}"
        end
      end

      # ── Gmail ──────────────────────────────────────────────────────────

      public_class_method def self.gmail_search(opts = {})
        q = opts[:query].to_s
        max = (opts[:max] || 10).to_i
        listed = api(url: "#{GMAIL_API}/users/me/messages", params: { q: q, maxResults: max }.compact)
        ids = Array(listed[:messages]).map { |m| m[:id] }
        ids.map { |id| gmail_get(id: id, format: 'metadata') }
      end

      public_class_method def self.gmail_get(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        fmt = opts[:format] || 'full'
        msg = api(url: "#{GMAIL_API}/users/me/messages/#{id}", params: { format: fmt })
        headers = {}
        Array(msg.dig(:payload, :headers)).each { |h| headers[h[:name].to_s.downcase] = h[:value] }
        {
          id: msg[:id],
          threadId: msg[:threadId],
          from: headers['from'],
          to: headers['to'],
          subject: headers['subject'],
          date: headers['date'],
          snippet: msg[:snippet],
          labels: msg[:labelIds],
          body: gmail_body(payload: msg[:payload])
        }
      end

      private_class_method def self.gmail_body(opts = {})
        payload = opts[:payload]
        return '' unless payload.is_a?(Hash)

        return Base64.urlsafe_decode64(payload[:body][:data].to_s.tr('-_', '+/')) if payload[:body].is_a?(Hash) && payload[:body][:data]

        Array(payload[:parts]).each do |part|
          text = gmail_body(payload: part)
          return text unless text.to_s.empty?
        end
        ''
      rescue ArgumentError
        ''
      end

      public_class_method def self.gmail_send(opts = {})
        to = opts[:to].to_s
        raise 'to is required' if to.empty?

        raw = gmail_rfc822(opts)
        sent = api(http_method: :post, url: "#{GMAIL_API}/users/me/messages/send", http_body: { raw: raw })
        { status: 'sent', id: sent[:id], threadId: sent[:threadId] }
      end

      public_class_method def self.gmail_reply(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        orig = gmail_get(id: id)
        subj = orig[:subject].to_s
        subj = "Re: #{subj}" unless subj.downcase.start_with?('re:')
        raw = gmail_rfc822(opts.merge(to: orig[:from], subject: subj, in_reply_to: orig[:id]))
        sent = api(
          http_method: :post,
          url: "#{GMAIL_API}/users/me/messages/send",
          http_body: { raw: raw, threadId: orig[:threadId] }
        )
        { status: 'sent', id: sent[:id], threadId: sent[:threadId] }
      end

      private_class_method def self.gmail_rfc822(opts = {})
        ctype = opts[:html] ? 'text/html' : 'text/plain'
        from = opts[:from].to_s
        from = 'me' if from.empty?
        lines = [
          "From: #{from}",
          "To: #{opts[:to]}",
          "Subject: #{opts[:subject]}",
          'MIME-Version: 1.0',
          "Content-Type: #{ctype}; charset=UTF-8"
        ]
        lines << "In-Reply-To: #{opts[:in_reply_to]}" if opts[:in_reply_to]
        lines << ''
        lines << opts[:body].to_s
        Base64.urlsafe_encode64(lines.join("\r\n"), padding: false)
      end

      public_class_method def self.gmail_labels(opts = {})
        api(opts.merge(url: "#{GMAIL_API}/users/me/labels"))
      end

      public_class_method def self.gmail_modify(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        body = {}
        add = Array(opts[:add_labels] || opts[:add]).map(&:to_s).reject(&:empty?)
        rem = Array(opts[:remove_labels] || opts[:remove]).map(&:to_s).reject(&:empty?)
        body[:addLabelIds] = add unless add.empty?
        body[:removeLabelIds] = rem unless rem.empty?
        api(http_method: :post, url: "#{GMAIL_API}/users/me/messages/#{id}/modify", http_body: body)
      end

      # ── Calendar ───────────────────────────────────────────────────────

      public_class_method def self.calendar_list(opts = {})
        cal = opts[:calendar_id].to_s
        cal = 'primary' if cal.empty?
        params = { singleEvents: true, orderBy: 'startTime' }
        params[:timeMin] = opts[:start] if opts[:start]
        params[:timeMax] = opts[:end] if opts[:end]
        params[:timeMin] ||= Time.now.utc.iso8601
        params[:maxResults] = (opts[:max] || 25).to_i
        data = api(url: "#{CAL_API}/calendars/#{CGI.escape(cal)}/events", params: params)
        Array(data[:items]).map do |ev|
          {
            id: ev[:id],
            summary: ev[:summary],
            start: ev.dig(:start, :dateTime) || ev.dig(:start, :date),
            end: ev.dig(:end, :dateTime) || ev.dig(:end, :date),
            location: ev[:location],
            description: ev[:description],
            htmlLink: ev[:htmlLink]
          }
        end
      end

      public_class_method def self.calendar_create(opts = {})
        cal = opts[:calendar_id].to_s
        cal = 'primary' if cal.empty?
        ev = calendar_event_body(opts)
        created = api(http_method: :post, url: "#{CAL_API}/calendars/#{CGI.escape(cal)}/events", http_body: ev)
        { status: 'created', id: created[:id], summary: created[:summary], htmlLink: created[:htmlLink] }
      end

      public_class_method def self.calendar_update(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        cal = opts[:calendar_id].to_s
        cal = 'primary' if cal.empty?
        ev = calendar_event_body(opts)
        updated = api(http_method: :patch, url: "#{CAL_API}/calendars/#{CGI.escape(cal)}/events/#{id}", http_body: ev)
        { status: 'updated', id: updated[:id], summary: updated[:summary], htmlLink: updated[:htmlLink] }
      end

      public_class_method def self.calendar_delete(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        cal = opts[:calendar_id].to_s
        cal = 'primary' if cal.empty?
        api(http_method: :delete, url: "#{CAL_API}/calendars/#{CGI.escape(cal)}/events/#{id}")
        { status: 'deleted', id: id }
      end

      private_class_method def self.calendar_event_body(opts = {})
        body = {}
        body[:summary] = opts[:summary] if opts[:summary]
        body[:location] = opts[:location] if opts[:location]
        body[:description] = opts[:description] if opts[:description]
        body[:start] = cal_when(value: opts[:start]) if opts[:start]
        body[:end] = cal_when(value: opts[:end]) if opts[:end]
        atts = opts[:attendees]
        atts = atts.split(',') if atts.is_a?(String)
        body[:attendees] = Array(atts).map { |e| { email: e.to_s.strip } }.reject { |h| h[:email].empty? } if atts
        body
      end

      private_class_method def self.cal_when(opts = {})
        s = opts[:value].to_s
        s.match?(/\A\d{4}-\d{2}-\d{2}\z/) ? { date: s } : { dateTime: s }
      end

      # ── Drive ──────────────────────────────────────────────────────────

      public_class_method def self.drive_search(opts = {})
        q = opts[:query].to_s
        q = "fullText contains '#{q.gsub("'", "\\'")}'" unless opts[:raw_query]
        data = api(
          url: "#{DRIVE_API}/files",
          params: {
            q: q,
            pageSize: (opts[:max] || 10).to_i,
            fields: 'files(id,name,mimeType,modifiedTime,webViewLink,size,parents)'
          }
        )
        Array(data[:files])
      end

      public_class_method def self.drive_get(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        api(
          url: "#{DRIVE_API}/files/#{id}",
          params: { fields: 'id,name,mimeType,modifiedTime,size,webViewLink,parents,owners' }
        )
      end

      public_class_method def self.drive_upload(opts = {})
        path = opts[:path].to_s
        raise 'path is required' unless File.file?(path)

        name = opts[:name].to_s
        name = File.basename(path) if name.empty?
        meta = { name: name }
        meta[:parents] = [opts[:parent]] if opts[:parent]
        mime = opts[:mime] || drive_mime(path: path)
        uploaded = drive_multipart_upload(meta: meta, path: path, mime: mime)
        { status: 'uploaded', id: uploaded[:id], name: uploaded[:name], mimeType: uploaded[:mimeType], webViewLink: uploaded[:webViewLink] }
      end

      private_class_method def self.drive_mime(opts = {})
        ext = File.extname(opts[:path].to_s).downcase
        {
          '.txt' => 'text/plain', '.md' => 'text/markdown', '.html' => 'text/html',
          '.json' => 'application/json', '.pdf' => 'application/pdf',
          '.png' => 'image/png', '.jpg' => 'image/jpeg', '.jpeg' => 'image/jpeg',
          '.csv' => 'text/csv', '.zip' => 'application/zip'
        }[ext] || 'application/octet-stream'
      end

      private_class_method def self.drive_multipart_upload(opts = {})
        boundary = "pwn#{SecureRandom.hex(8)}"
        meta = opts[:meta].to_json
        body = +''
        body << "--#{boundary}\r\n"
        body << "Content-Type: application/json; charset=UTF-8\r\n\r\n"
        body << "#{meta}\r\n"
        body << "--#{boundary}\r\n"
        body << "Content-Type: #{opts[:mime]}\r\n\r\n"
        body << File.binread(opts[:path])
        body << "\r\n--#{boundary}--\r\n"
        api(
          http_method: :post,
          url: "#{DRIVE_UPLOAD}/files?uploadType=multipart&fields=id,name,mimeType,webViewLink",
          http_body: body,
          content_type: "multipart/related; boundary=#{boundary}"
        )
      end

      public_class_method def self.drive_download(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        meta = drive_get(id: id)
        export = opts[:export_mime] || EXPORT_MIME[meta[:mimeType].to_s]
        raw = if export
                api(url: "#{DRIVE_API}/files/#{id}/export", params: { mimeType: export }, raw: true)
              else
                api(url: "#{DRIVE_API}/files/#{id}", params: { alt: 'media' }, raw: true)
              end
        out = opts[:output].to_s
        out = File.join(Dir.tmpdir, meta[:name].to_s.tr('/', '_')) if out.empty?
        File.binwrite(out, raw.respond_to?(:file) ? File.binread(raw.file) : raw.to_s)
        { status: 'downloaded', id: id, name: meta[:name], path: out, mimeType: export || meta[:mimeType] }
      end

      public_class_method def self.drive_create_folder(opts = {})
        name = opts[:name].to_s
        raise 'name is required' if name.empty?

        meta = { name: name, mimeType: 'application/vnd.google-apps.folder' }
        meta[:parents] = [opts[:parent]] if opts[:parent]
        created = api(http_method: :post, url: "#{DRIVE_API}/files", http_body: meta)
        { status: 'created', id: created[:id], name: created[:name], webViewLink: created[:webViewLink] }
      end

      public_class_method def self.drive_share(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        perm = {
          role: (opts[:role] || 'reader').to_s,
          type: (opts[:type] || (opts[:email] ? 'user' : 'anyone')).to_s
        }
        perm[:emailAddress] = opts[:email] if opts[:email]
        perm[:domain] = opts[:domain] if opts[:domain]
        params = {}
        params[:sendNotificationEmail] = true if opts[:notify]
        created = api(
          http_method: :post,
          url: "#{DRIVE_API}/files/#{id}/permissions",
          params: params,
          http_body: perm
        )
        { status: 'shared', permissionId: created[:id], fileId: id, role: perm[:role], type: perm[:type] }
      end

      public_class_method def self.drive_delete(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        if opts[:permanent]
          api(http_method: :delete, url: "#{DRIVE_API}/files/#{id}")
          { status: 'deleted', fileId: id, permanent: true }
        else
          api(http_method: :patch, url: "#{DRIVE_API}/files/#{id}", http_body: { trashed: true })
          { status: 'trashed', fileId: id, permanent: false }
        end
      end

      # ── Docs ───────────────────────────────────────────────────────────

      public_class_method def self.docs_get(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        api(url: "#{DOCS_API}/documents/#{id}")
      end

      public_class_method def self.docs_create(opts = {})
        title = opts[:title].to_s
        title = 'Untitled' if title.empty?
        created = api(http_method: :post, url: "#{DOCS_API}/documents", http_body: { title: title })
        docs_append(id: created[:documentId], text: opts[:body]) if opts[:body].to_s != ''
        {
          status: 'created',
          documentId: created[:documentId],
          title: created[:title],
          url: "https://docs.google.com/document/d/#{created[:documentId]}/edit"
        }
      end

      public_class_method def self.docs_append(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        text = opts[:text].to_s
        doc = docs_get(id: id)
        end_idx = doc.dig(:body, :content)&.last&.dig(:endIndex).to_i
        end_idx = 1 if end_idx <= 1
        api(
          http_method: :post,
          url: "#{DOCS_API}/documents/#{id}:batchUpdate",
          http_body: {
            requests: [{ insertText: { location: { index: end_idx - 1 }, text: text } }]
          }
        )
        { status: 'appended', documentId: id, inserted_at: end_idx - 1, characters: text.length }
      end

      # ── Sheets ─────────────────────────────────────────────────────────

      public_class_method def self.sheets_create(opts = {})
        title = opts[:title].to_s
        title = 'Untitled spreadsheet' if title.empty?
        body = { properties: { title: title } }
        sheet = opts[:sheet_name].to_s
        body[:sheets] = [{ properties: { title: sheet } }] unless sheet.empty?
        created = api(http_method: :post, url: "#{SHEETS_API}/spreadsheets", http_body: body)
        {
          status: 'created',
          spreadsheetId: created[:spreadsheetId],
          title: created.dig(:properties, :title),
          spreadsheetUrl: created[:spreadsheetUrl]
        }
      end

      public_class_method def self.sheets_get(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        range = opts[:range].to_s
        range = 'Sheet1' if range.empty?
        data = api(url: "#{SHEETS_API}/spreadsheets/#{id}/values/#{CGI.escape(range)}")
        data[:values] || []
      end

      public_class_method def self.sheets_update(opts = {})
        sheets_write(opts.merge(verb: :put, path: 'values'))
      end

      public_class_method def self.sheets_append(opts = {})
        sheets_write(opts.merge(verb: :post, path: 'values', suffix: ':append'))
      end

      private_class_method def self.sheets_write(opts = {})
        id = opts[:id].to_s
        raise 'id is required' if id.empty?

        range = opts[:range].to_s
        range = 'Sheet1' if range.empty?
        values = opts[:values]
        values = JSON.parse(values) if values.is_a?(String)
        raise 'values is required' unless values.is_a?(Array)

        url = "#{SHEETS_API}/spreadsheets/#{id}/#{opts[:path]}/#{CGI.escape(range)}#{opts[:suffix]}"
        api(
          http_method: opts[:verb],
          url: url,
          params: { valueInputOption: 'USER_ENTERED' },
          http_body: { values: values }
        )
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Run scopes and return its result
          #{self}.scopes(
            scope: 'optional - scope value consumed by #scopes',
            services: 'optional - services value consumed by #scopes'
          )

          # Run parse oauth code and return its result
          #{self}.parse_oauth_code(
            code: 'optional - code value consumed by #parse_oauth_code'
          )

          # Run obtain oauth auth url and return its result
          #{self}.obtain_oauth_auth_url(
            wait: 'optional - wait value consumed by #obtain_oauth_auth_url',
            timeout: 'optional - seconds to wait before giving up',
            probe: 'optional - probe value consumed by #obtain_oauth_auth_url'
          )

          # Run exchange oauth code and return its result
          #{self}.exchange_oauth_code(
            code: 'required - code value consumed by #exchange_oauth_code',
            code_verifier: 'optional - code verifier value consumed by #exchange_oauth_code (defaults to pending[:verifier])'
          )

          # Run refresh oauth bearer token and return its result
          #{self}.refresh_oauth_bearer_token(
            refresh_token: 'required - refresh token value consumed by #refresh_oauth_bearer_token (defaults to c[:refresh_token])',
            client_id: 'required - client id value consumed by #refresh_oauth_bearer_token (defaults to c[:client_id])',
            client_secret: 'required - client secret value consumed by #refresh_oauth_bearer_token (defaults to c[:client_secret])'
          )

          # Run bearer token and return its result
          #{self}.bearer_token

          # Run authenticated and return its result
          #{self}.authenticated?

          # Run revoke and return its result
          #{self}.revoke

          # ── Gmail ──────────────────────────────────────────────────────────
          #{self}.gmail_search(
            query: 'optional - search query string',
            max: 'optional - max value consumed by #gmail_search'
          )

          # Run gmail get and return its result
          #{self}.gmail_get(
            id: 'required - id value consumed by #gmail_get',
            format: 'optional - format value consumed by #gmail_get (defaults to full)'
          )

          # Run gmail send and return its result
          #{self}.gmail_send(
            to: 'required - to value consumed by #gmail_send'
          )

          # Run gmail reply and return its result
          #{self}.gmail_reply(
            id: 'required - id value consumed by #gmail_reply'
          )

          # Run gmail labels and return its result
          #{self}.gmail_labels

          # Run gmail modify and return its result
          #{self}.gmail_modify(
            id: 'required - id value consumed by #gmail_modify',
            add_labels: 'optional - add labels value consumed by #gmail_modify',
            add: 'required - add value consumed by #gmail_modify',
            remove_labels: 'optional - remove labels value consumed by #gmail_modify',
            remove: 'required - remove value consumed by #gmail_modify'
          )

          # ── Calendar ───────────────────────────────────────────────────────
          #{self}.calendar_list(
            calendar_id: 'optional - calendar id value consumed by #calendar_list',
            start: 'optional - start value consumed by #calendar_list',
            end: 'optional - end value consumed by #calendar_list',
            max: 'optional - max value consumed by #calendar_list'
          )

          # Run calendar create and return its result
          #{self}.calendar_create(
            calendar_id: 'optional - calendar id value consumed by #calendar_create'
          )

          # Run calendar update and return its result
          #{self}.calendar_update(
            id: 'required - id value consumed by #calendar_update',
            calendar_id: 'optional - calendar id value consumed by #calendar_update'
          )

          # Run calendar delete and return its result
          #{self}.calendar_delete(
            id: 'required - id value consumed by #calendar_delete',
            calendar_id: 'optional - calendar id value consumed by #calendar_delete'
          )

          # ── Drive ──────────────────────────────────────────────────────────
          #{self}.drive_search(
            query: 'optional - search query string',
            raw_query: 'optional - raw query value consumed by #drive_search',
            max: 'optional - max value consumed by #drive_search'
          )

          # Run drive get and return its result
          #{self}.drive_get(
            id: 'required - id value consumed by #drive_get'
          )

          # Run drive upload and return its result
          #{self}.drive_upload(
            path: 'required - filesystem path to read or write',
            name: 'required - binary or identifier name',
            parent: 'optional - parent value consumed by #drive_upload',
            mime: 'optional - mime value consumed by #drive_upload'
          )

          # Run drive download and return its result
          #{self}.drive_download(
            id: 'required - id value consumed by #drive_download',
            export_mime: 'optional - export mime value consumed by #drive_download (defaults to EXPORT_MIME[meta[:mimeType])',
            output: 'optional - output value consumed by #drive_download'
          )

          # Run drive create folder and return its result
          #{self}.drive_create_folder(
            name: 'required - binary or identifier name',
            parent: 'optional - parent value consumed by #drive_create_folder'
          )

          # Run drive share and return its result
          #{self}.drive_share(
            id: 'required - id value consumed by #drive_share',
            role: 'optional - role value consumed by #drive_share',
            type: 'optional - type value consumed by #drive_share',
            email: 'optional - email value consumed by #drive_share',
            domain: 'optional - FQDN to query (e.g. example.com)',
            notify: 'optional - notify value consumed by #drive_share'
          )

          # Run drive delete and return its result
          #{self}.drive_delete(
            id: 'required - id value consumed by #drive_delete',
            permanent: 'optional - permanent value consumed by #drive_delete'
          )

          # ── Docs ───────────────────────────────────────────────────────────
          #{self}.docs_get(
            id: 'required - id value consumed by #docs_get'
          )

          # Run docs create and return its result
          #{self}.docs_create(
            title: 'required - title value consumed by #docs_create',
            body: 'optional - body value consumed by #docs_create'
          )

          # Run docs append and return its result
          #{self}.docs_append(
            id: 'required - id value consumed by #docs_append',
            text: 'optional - text value consumed by #docs_append'
          )

          # ── Sheets ─────────────────────────────────────────────────────────
          #{self}.sheets_create(
            title: 'required - title value consumed by #sheets_create',
            sheet_name: 'optional - sheet name value consumed by #sheets_create'
          )

          # Run sheets get and return its result
          #{self}.sheets_get(
            id: 'required - id value consumed by #sheets_get',
            range: 'required - range value consumed by #sheets_get'
          )

          # Run sheets update and return its result
          #{self}.sheets_update

          # Run sheets append and return its result
          #{self}.sheets_append

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
