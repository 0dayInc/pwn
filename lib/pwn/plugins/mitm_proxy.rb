# frozen_string_literal: true

require 'webrick/httpproxy'
require 'net/http'
require 'json'
require 'base64'
require 'securerandom'
require 'time'
require 'fileutils'
require 'tmpdir'
require 'openssl'

module PWN
  module Plugins
    # Native HTTP interception and opaque CONNECT tunnelling. CONNECT traffic is
    # not decrypted: HAR explicitly marks the tunnel as metadata-only.
    module MitmProxy
      SESSIONS = {} # rubocop:disable Style/MutableConstant -- live process-local session registry
      LOCK = Mutex.new
      HOP_HEADERS = %w[connection keep-alive proxy-authenticate proxy-authorization proxy-connection te trailer trailers transfer-encoding upgrade content-length host].freeze

      # WEBrick owns socket parsing, framing, concurrency and CONNECT transport.
      class Server < WEBrick::HTTPProxyServer
        def proxy_service(req, res)
          entry = MitmProxy.exchange(proxy: @config[:PWNSession], request: {
                                       method: req.request_method, url: req.request_uri.to_s,
                                       headers: req.header.transform_values { |v| v.join(', ') }, body: req.body.to_s
                                     })
          res.status = entry[:response][:status]
          entry[:response][:headers].each do |h|
            if h[:name] == 'set-cookie'
              res.cookies << h[:value]
            else
              res[h[:name]] = h[:value]
            end
          end
          content = entry[:response][:content]
          res.body = content[:encoding] == 'base64' ? Base64.strict_decode64(content[:text]) : content[:text]
        rescue StandardError => e
          res.status = 502
          res.body = "#{e.class}: #{e.message}"
        end
      end

      public_class_method def self.start(opts = {})
        raise ArgumentError, 'backend must be native' unless (opts[:backend] || 'native').to_s == 'native'

        id = SecureRandom.hex(12)
        path = File.expand_path(opts[:har_path] || File.join(Dir.tmpdir, "pwn-proxy-#{id}.har"))
        rules = validate_rules(rules: opts[:rules])
        session = { id: id, backend: 'native', har_path: path, rules: rules, entries: [], mutex: Mutex.new,
                    timeout: Float(opts[:timeout] || 30), https_capture: opts[:mitm_tls] ? 'TLS MITM' : 'CONNECT metadata only; TLS is not decrypted',
                    on_request: opts[:on_request], on_response: opts[:on_response], ca: self_signed_ca }
        server = Server.new(BindAddress: opts[:host] || '127.0.0.1', Port: Integer(opts[:port] || 0),
                            Logger: WEBrick::Log.new(File::NULL), AccessLog: [], PWNSession: session,
                            ProxyContentHandler: lambda { |req, res|
                              next unless req.request_method == 'CONNECT'

                              persist_entry(proxy: session, entry: { _request_id: SecureRandom.hex(12), _capture: 'opaque_connect',
                                                                     startedDateTime: Time.now.utc.iso8601, time: 0,
                                                                     request: { method: 'CONNECT', url: req.unparsed_uri, headers: [] },
                                                                     response: { status: res.status, headers: [], content: { size: 0, mimeType: '', text: '' } },
                                                                     cache: {}, timings: { send: 0, wait: 0, receive: 0 } })
                            })
        session.merge!(host: server.config[:BindAddress], port: server.config[:Port], server: server)
        session[:url] = "http://#{session[:host]}:#{session[:port]}"
        LOCK.synchronize { SESSIONS[id] = session }
        session[:thread] = Thread.new { server.start }
        persist(proxy: session)
        descriptor(proxy: session)
      rescue StandardError
        server&.shutdown
        LOCK.synchronize { SESSIONS.delete(id) } if id
        raise
      end

      public_class_method def self.stop(opts = {})
        session = lookup(opts)
        session[:server].shutdown
        thread = session[:thread]
        unless thread.join(5)
          thread.kill
          thread.join(1)
        end
        persist(proxy: session)
        LOCK.synchronize { SESSIONS.delete(session[:id]) }
        { stopped: true, id: session[:id], har_path: session[:har_path], entries: session[:entries].length }
      end

      public_class_method def self.entries(opts = {})
        session = lookup(opts)
        session[:mutex].synchronize { Marshal.load(Marshal.dump(session[:entries])) }
      end

      public_class_method def self.rules(opts = {})
        session = lookup(opts)
        rules = validate_rules(rules: opts[:rules])
        session[:mutex].synchronize { session[:rules] = rules }
        { id: session[:id], rules: rules }
      end

      public_class_method def self.http_replay(opts = {})
        session = lookup(opts)
        entry = entries(proxy: session).find { |row| row[:_request_id] == opts[:request_id].to_s }
        raise ArgumentError, 'unknown request_id' unless entry
        raise ArgumentError, 'opaque CONNECT tunnels cannot be replayed as HTTP' if entry[:_capture] == 'opaque_connect'

        original = entry[:request]
        mutations = (opts[:mutations] || {}).transform_keys(&:to_sym)
        unknown = mutations.keys - %i[method url path query headers body]
        raise ArgumentError, "unknown mutations: #{unknown.join(', ')}" unless unknown.empty?

        uri = URI(mutations[:url] || original[:url])
        uri.path = mutations[:path] if mutations.key?(:path)
        uri.query = mutations[:query].is_a?(Hash) ? URI.encode_www_form(mutations[:query]) : mutations[:query] if mutations.key?(:query)
        headers = original[:headers].to_h { |h| [h[:name].downcase, h[:value]] }
        (mutations[:headers] || {}).each { |k, v| v.nil? ? headers.delete(k.downcase) : headers[k.downcase] = v }
        post = original[:postData] || {}
        body = post[:encoding] == 'base64' ? Base64.strict_decode64(post[:text]) : post[:text].to_s
        exchange(proxy: session, request: { method: mutations[:method] || original[:method], url: uri.to_s,
                                            headers: headers, body: mutations.fetch(:body, body) })
      end

      public_class_method def self.exchange(opts = {})
        session = lookup(opts)
        request = Marshal.load(Marshal.dump(opts.fetch(:request)))
        session[:on_request]&.call(request)
        apply_rules(proxy: session, phase: 'request', message: request)
        uri = URI(request[:url])
        raise ArgumentError, 'HTTP(S) URL without userinfo required' unless %w[http https].include?(uri.scheme) && uri.host && !uri.userinfo

        method = request[:method].to_s.upcase
        raise ArgumentError, 'invalid HTTP method' unless method.match?(/\A[A-Z]+\z/) && method != 'CONNECT'

        headers = clean_headers(headers: request[:headers])
        headers['accept-encoding'] ||= 'identity'
        client = Net::HTTP.new(uri.host, uri.port, nil) # Never inherit ambient proxies.
        client.use_ssl = uri.scheme == 'https'
        client.open_timeout = client.read_timeout = client.write_timeout = session[:timeout]
        wire = Net::HTTPGenericRequest.new(method, !request[:body].to_s.empty?, method != 'HEAD', uri.request_uri, headers)
        wire.body = request[:body].to_s unless request[:body].to_s.empty?
        started = Time.now.utc
        clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        response = client.request(wire)
        message = { headers: response.to_hash.transform_values { |v| v.join(', ') }, body: response.body.to_s }
        session[:on_response]&.call(message)
        apply_rules(proxy: session, phase: 'response', message: message)
        elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - clock) * 1000
        response_headers = clean_headers(headers: message[:headers]).map { |k, v| { name: k, value: v } }
        response_headers.reject! { |h| h[:name] == 'set-cookie' }
        Array(response.get_fields('set-cookie')).each { |v| response_headers << { name: 'set-cookie', value: v } }
        entry = { _request_id: SecureRandom.hex(12), startedDateTime: started.iso8601(6), time: elapsed,
                  request: { method: method, url: uri.to_s, httpVersion: 'HTTP/1.1', headers: headers.map { |k, v| { name: k, value: v } },
                             queryString: URI.decode_www_form(uri.query.to_s).map { |k, v| { name: k, value: v } }, cookies: [],
                             headersSize: -1, bodySize: request[:body].to_s.bytesize,
                             postData: encoded(body: request[:body].to_s).merge(mimeType: headers['content-type'].to_s) },
                  response: { status: response.code.to_i, statusText: response.message, httpVersion: 'HTTP/1.1',
                              headers: response_headers, cookies: [], redirectURL: response['location'].to_s, headersSize: -1,
                              bodySize: message[:body].bytesize, content: encoded(body: message[:body]).merge(size: message[:body].bytesize, mimeType: response['content-type'].to_s) },
                  cache: {}, timings: { send: 0, wait: elapsed, receive: 0 } }
        persist_entry(proxy: session, entry: entry)
        entry
      end

      private_class_method def self.self_signed_ca(opts = {})
        _unused = opts[:unused]
        key = OpenSSL::PKey::RSA.new(2048)
        cert = OpenSSL::X509::Certificate.new
        cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=pwn-mitm-ca')
        cert.not_before = Time.now
        cert.not_after = Time.now + (365 * 24 * 3600)
        cert.public_key = key.public_key
        cert.serial = 1
        cert.version = 2
        ef = OpenSSL::X509::ExtensionFactory.new
        cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
        cert.sign(key, OpenSSL::Digest.new('SHA256'))
        { cert: cert, key: key }
      end

      private_class_method def self.encoded(opts = {})
        body = opts[:body].dup.force_encoding(Encoding::UTF_8)
        body.valid_encoding? ? { text: body } : { text: Base64.strict_encode64(body), encoding: 'base64' }
      end

      private_class_method def self.clean_headers(opts = {})
        headers = (opts[:headers] || {}).transform_keys { |k| k.to_s.downcase }
        excluded = HOP_HEADERS + headers.fetch('connection', '').split(',').map { |h| h.strip.downcase }
        headers.except(*excluded)
      end

      private_class_method def self.validate_rules(opts = {})
        Array(opts[:rules]).map do |rule|
          r = rule.transform_keys(&:to_sym)
          raise ArgumentError, 'rule requires phase=request|response, field=body|url|header:NAME, match and replace' unless %w[request response].include?(r[:phase]) && (r[:field].to_s.match?(/\Aheader:[\w-]+\z/) || %w[body url].include?(r[:field])) && r.key?(:match) && r.key?(:replace)
          raise ArgumentError, 'response URL rules are unsupported' if r[:phase] == 'response' && r[:field] == 'url'

          r
        end
      end

      private_class_method def self.apply_rules(opts = {})
        session = opts[:proxy]
        message = opts[:message]
        rules = session[:mutex].synchronize { session[:rules].dup }
        rules.select { |r| r[:phase] == opts[:phase] }.each do |r|
          if r[:field].start_with?('header:')
            key = r[:field].delete_prefix('header:').downcase
            message[:headers][key] = message[:headers][key].to_s.gsub(r[:match].to_s, r[:replace].to_s)
          else
            key = r[:field].to_sym
            message[key] = message[key].to_s.gsub(r[:match].to_s, r[:replace].to_s)
          end
        end
      end

      private_class_method def self.lookup(opts = {})
        ref = opts[:proxy] || opts[:proxy_id]
        return ref if ref.is_a?(Hash) && ref[:mutex]

        id = ref.is_a?(Hash) ? ref[:id] : ref.to_s
        LOCK.synchronize { SESSIONS.fetch(id) { raise ArgumentError, 'unknown proxy session' } }
      end

      private_class_method def self.descriptor(opts = {})
        opts[:proxy].slice(:id, :backend, :host, :port, :url, :har_path, :https_capture)
      end

      private_class_method def self.persist_entry(opts = {})
        session = opts[:proxy]
        session[:mutex].synchronize do
          session[:entries] << opts[:entry]
          write_har(proxy: session)
        end
      end

      private_class_method def self.persist(opts = {})
        session = opts[:proxy]
        session[:mutex].synchronize { write_har(proxy: session) }
      end

      private_class_method def self.write_har(opts = {})
        session = opts[:proxy]
        path = session[:har_path]
        FileUtils.mkdir_p(File.dirname(path))
        tmp = "#{path}.#{SecureRandom.hex(6)}.tmp"
        File.open(tmp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          file.write(JSON.pretty_generate(log: { version: '1.2', creator: { name: 'PWN native proxy', version: '1' }, entries: session[:entries] }))
        end
        File.rename(tmp, path)
      ensure
        FileUtils.rm_f(tmp) if tmp
      end

      public_class_method def self.replay(opts = {})
        _id = opts[:request_id]
        http_replay(opts)
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Start a native HTTP capture proxy; CONNECT tunnels are metadata-only.
          #{self}.start(
            har_path: 'optional - HAR destination, contains sensitive raw traffic',
            host: 'optional - bind address, default 127.0.0.1',
            port: 'optional - bind port, default ephemeral',
            backend: 'optional - native (only supported backend)',
            rules: 'optional - literal phase/field/match/replace rules',
            timeout: 'optional - upstream timeout seconds, default 30',
            on_request: 'optional - callable that mutates the request hash',
            on_response: 'optional - callable that mutates the response hash',
            mitm_tls: 'optional - true generates a local CA for TLS interception'
          )

          # Return a snapshot of captured HAR entries.
          #{self}.entries(proxy: 'required - descriptor or session id')

          # Replace the active request/response substitution rules.
          #{self}.rules(
            proxy: 'required - descriptor or session id',
            rules: 'required - array of phase/field/match/replace hashes'
          )

          # Replay a captured HTTP request with optional mutations.
          #{self}.http_replay(
            proxy: 'required - descriptor or session id',
            request_id: 'required - captured _request_id',
            mutations: 'optional - method, url, path, query, headers, body'
          )

          # Alias of http_replay for pwn_eval callers.
          #{self}.replay(
            proxy: 'required - descriptor or session id',
            request_id: 'required - captured _request_id',
            mutations: 'optional - method, url, path, query, headers, body'
          )

          # Send and capture one HTTP request through the shared rule engine.
          #{self}.exchange(
            proxy: 'required - descriptor or session id',
            request: 'required - method, url, headers, body hash'
          )

          # Stop the listener and flush its HAR.
          #{self}.stop(proxy: 'required - descriptor or session id')

          # Print the module authors.
          #{self}.authors
        "
      end
    end
  end
end
