# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'digest'
require 'socket'
require 'open3'
require 'etc'
require 'uri'
require 'shellwords'
require 'timeout'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Extrospection is the outward-facing counterpart to
      # PWN::AI::Agent::Learning (introspection).
      #
      # PRIMARY INTENT — on-demand external sensing
      # -------------------------------------------
      # Quickly explore *external* resources when that produces a more
      # informed answer. Call a sense tool only when the question needs it:
      #
      #   "weather in Tokyo"        → verify / watch / TransparentBrowser
      #   "what's on 101.1 FM?"     → rf_tune(freq: "101.1") → RDS / observe(:rf)
      #   "CVE for openssl 3.0?"    → intel(query:) / verify(claim:, kind: :cve)
      #   "did the target change?"  → watch(url:) / snapshot(sections: [:web])
      #
      # Secondary / optional — ambient host baseline
      # --------------------------------------------
      # snapshot / drift / correlate can record cheap local posture so the
      # agent can tell "I called the API wrong" from "the world moved"
      # (kernel upgrade, dongle unplugged). This is NEVER the reason to
      # launch GUI / JVM / heavy-REPL binaries — those are presence-only.
      # auto_extrospect, when enabled, uses only side-effect-free sections.
      #
      #   INTROSPECTIVE (self)        EXTROSPECTIVE (world)
      #   ----------------------      -------------------------------------
      #   Metrics.record              Extrospection.intel/verify/watch/rf_tune (sense)
      #   Learning.note_outcome       Extrospection.observe         (fact)
      #   Learning.reflect            Extrospection.snapshot/drift  (baseline)
      #   Learning.stats              Extrospection.correlate       (self×world)
      #
      # PromptBuilder re-injects Extrospection.to_context on every turn.
      # Persistence: ~/.pwn/extrospection.json across REPL restarts.
      module Extrospection
        EXTRO_FILE = File.join(Dir.home, '.pwn', 'extrospection.json')
        MAX_OBSERVATIONS = 500
        # CLI tools that accept a cheap, non-interactive --version / -V.
        SAFE_VERSION_BINS = %w[nmap curl git ruby python3 gcc openssl docker].freeze
        # GUI / JVM / heavy REPL / interactive tools — presence-only.
        # NEVER spawn these from auto-probe (Burp Suite splash, ZAP UI, msfconsole, GQRX).
        PRESENCE_ONLY_BINS = %w[burpsuite zaproxy msfconsole gqrx sqlmap].freeze
        RF_BINS    = %w[rtl_sdr rtl_test rtl_433 hackrf_info gqrx dump1090 multimon-ng SoapySDRUtil].freeze
        PROBE_BINS = (SAFE_VERSION_BINS + PRESENCE_ONLY_BINS + RF_BINS).uniq.freeze
        # Cheap, side-effect-free sections used by auto_extrospect.
        # toolchain / rf / web are on-demand only (sense tools or explicit snapshot).
        AUTO_SECTIONS = %i[host repo env].freeze
        WEB_SHOT_DIR = File.join(Dir.home, '.pwn', 'extrospection', 'web')
        DEFAULT_WEB_ANCHORS = %w[
          https://services.nvd.nist.gov/rest/json/cves/2.0
          https://www.exploit-db.com/
          https://raw.githubusercontent.com/0dayinc/pwn/master/lib/pwn/version.rb
        ].freeze

        # Supported Method Parameters::
        # store = PWN::AI::Agent::Extrospection.load

        public_class_method def self.load
          FileUtils.mkdir_p(File.dirname(EXTRO_FILE))
          return { snapshot: {}, previous: {}, observations: [], updated_at: nil } unless File.exist?(EXTRO_FILE)

          JSON.parse(File.read(EXTRO_FILE), symbolize_names: true)
        rescue StandardError
          { snapshot: {}, previous: {}, observations: [], updated_at: nil }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Extrospection.save(
        #   store: 'required - Hash returned by .load / mutated in place'
        # )

        public_class_method def self.save(opts = {})
          store = opts[:store] ||= { snapshot: {}, previous: {}, observations: [] }
          store[:updated_at] = Time.now.utc.iso8601
          FileUtils.mkdir_p(File.dirname(EXTRO_FILE))
          File.write(EXTRO_FILE, JSON.pretty_generate(store))
          store
        end

        # Supported Method Parameters::
        # snap = PWN::AI::Agent::Extrospection.snapshot(
        #   persist: 'optional - Boolean, write snapshot to disk & rotate previous (default true)',
        #   sections: 'optional - Array subset of [:host, :net, :toolchain, :repo, :env, :rf, :web] (default all except :web)'
        # )
        #
        # Ambient host baseline (secondary to sense tools like intel/verify/watch).
        # :toolchain never spawns GUI/JVM tools (presence-only). auto_extrospect
        # uses AUTO_SECTIONS (host/repo/env) only. When persist:true the prior
        # snapshot is rotated into :previous so .drift can diff them.

        public_class_method def self.snapshot(opts = {})
          persist  = if opts.key?(:persist)
                       opts[:persist] ? true : false
                     else
                       true
                     end
          sections = Array(opts[:sections]).map(&:to_sym)
          sections = %i[host net toolchain repo env rf] if sections.empty?

          snap = {}
          snap[:host]      = probe_host      if sections.include?(:host)
          snap[:net]       = probe_net       if sections.include?(:net)
          snap[:toolchain] = probe_toolchain if sections.include?(:toolchain)
          snap[:repo]      = probe_repo      if sections.include?(:repo)
          snap[:env]       = probe_env       if sections.include?(:env)
          snap[:rf]        = probe_rf        if sections.include?(:rf)
          snap[:web]       = probe_web       if sections.include?(:web)
          snap[:captured_at] = Time.now.utc.iso8601
          snap[:fingerprint] = Digest::SHA256.hexdigest(JSON.generate(snap.except(:captured_at)))[0, 16]

          if persist
            store = load
            store[:previous] = store[:snapshot] || {}
            store[:snapshot] = snap
            save(store: store)
          end

          drift = compute_drift(before: load[:previous] || {}, after: snap)
          { snapshot: snap, drift: drift, persisted: persist }
        end

        # Supported Method Parameters::
        # obs = PWN::AI::Agent::Extrospection.observe(
        #   source: 'required - where the observation came from (nmap, shodan, burp, cve, human, ...)',
        #   data: 'required - the observation payload (String or Hash)',
        #   category: 'optional - :recon, :vuln, :intel, :target, :network, :env, :rf, :web, :misc (default :misc)',
        #   target: 'optional - host/ip/url/asset the observation is about',
        #   tags: 'optional - Array of String labels',
        #   ttl: 'optional - seconds until this observation is considered stale (default nil = forever)'
        # )
        #
        # Records a fact about the OUTSIDE world (as opposed to
        # Learning.note_outcome which records a fact about the agent's own
        # behaviour). Observations are re-injected via .to_context so recon
        # findings and threat-intel persist across sessions.

        public_class_method def self.observe(opts = {})
          source = opts[:source].to_s
          data   = opts[:data]
          raise 'ERROR: source is required' if source.strip.empty?
          raise 'ERROR: data is required'   if data.to_s.strip.empty?

          entry = {
            id: Digest::SHA256.hexdigest("#{source}-#{data}-#{Time.now.to_f}")[0, 12],
            source: source,
            category: (opts[:category] || :misc).to_s,
            target: opts[:target].to_s.empty? ? nil : opts[:target].to_s,
            data: data.is_a?(String) ? data[0, 4_000] : data,
            tags: Array(opts[:tags]).map(&:to_s),
            ttl: opts[:ttl]&.to_i,
            timestamp: Time.now.utc.iso8601
          }
          store = load
          store[:observations] ||= []
          store[:observations] << entry
          store[:observations].shift(store[:observations].length - MAX_OBSERVATIONS) if store[:observations].length > MAX_OBSERVATIONS
          save(store: store)
          entry
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Extrospection.observations(
        #   limit: 'optional - max entries newest-first (default 50)',
        #   source: 'optional - filter by source substring',
        #   category: 'optional - filter by category',
        #   target: 'optional - filter by target substring',
        #   tag: 'optional - filter by tag substring',
        #   fresh_only: 'optional - drop entries whose ttl has expired (default false)'
        # )

        public_class_method def self.observations(opts = {})
          limit  = opts[:limit] || 50
          src    = opts[:source].to_s.downcase
          cat    = opts[:category].to_s.downcase
          tgt    = opts[:target].to_s.downcase
          tag    = opts[:tag].to_s.downcase
          fresh  = opts[:fresh_only] ? true : false
          now    = Time.now.utc

          rows = Array(load[:observations])
          rows = rows.reject do |o|
            next true if fresh && o[:ttl] && (Time.parse(o[:timestamp].to_s) + o[:ttl].to_i) < now

            (src.empty? ? false : !o[:source].to_s.downcase.include?(src)) ||
              (cat.empty? ? false : o[:category].to_s.downcase != cat) ||
              (tgt.empty? ? false : !o[:target].to_s.downcase.include?(tgt)) ||
              (tag.empty? ? false : Array(o[:tags]).none? { |t| t.to_s.downcase.include?(tag) })
          rescue StandardError
            false
          end
          rows.reverse.first(limit)
        end

        # Supported Method Parameters::
        # delta = PWN::AI::Agent::Extrospection.drift(
        #   live: 'optional - probe host NOW and diff vs stored snapshot (default true). When false, diff stored :snapshot vs stored :previous.'
        # )

        public_class_method def self.drift(opts = {})
          live  = if opts.key?(:live)
                    opts[:live] ? true : false
                  else
                    true
                  end
          store = load
          if live
            after  = snapshot(persist: false)[:snapshot]
            before = store[:snapshot] || {}
          else
            after  = store[:snapshot] || {}
            before = store[:previous] || {}
          end
          compute_drift(before: before, after: after)
        end

        # Supported Method Parameters::
        # hits = PWN::AI::Agent::Extrospection.intel(
        #   query: 'required - keyword / product / CVE id to search external threat-intel for',
        #   feeds: 'optional - Array subset of [:nvd, :circl, :exploitdb] (default all)',
        #   limit: 'optional - max results per feed (default 5)',
        #   record: 'optional - also persist each hit as an observation (default false)'
        # )
        #
        # Best-effort external lookups. Network / API failures degrade to
        # an empty result for that feed rather than raising, so learning
        # never breaks the primary loop when offline.

        public_class_method def self.intel(opts = {})
          query = opts[:query].to_s.strip
          raise 'ERROR: query is required' if query.empty?

          feeds  = Array(opts[:feeds]).map(&:to_sym)
          feeds  = %i[nvd circl exploitdb] if feeds.empty?
          limit  = opts[:limit] || 5
          record = opts[:record] ? true : false

          results = {}
          results[:nvd]       = intel_nvd(query: query, limit: limit)       if feeds.include?(:nvd)
          results[:circl]     = intel_circl(query: query, limit: limit)     if feeds.include?(:circl)
          results[:exploitdb] = intel_exploitdb(query: query, limit: limit) if feeds.include?(:exploitdb)

          if record
            results.each do |feed, hits|
              Array(hits).each do |h|
                observe(source: feed.to_s, category: :intel, data: h, tags: ['intel', query], target: h.is_a?(Hash) ? h[:id].to_s : nil)
              end
            end
          end
          { query: query, feeds: feeds, results: results, total: results.values.flatten.compact.length }
        end

        # Supported Method Parameters::
        # verdict = PWN::AI::Agent::Extrospection.verify(
        #   claim:  'required - factual claim to fact-check against the live web',
        #   kind:   'optional - :cve | :version | :doc | :generic (default auto-detect)',
        #   url:    'optional - explicit URL the claim cites (forces kind: :doc)',
        #   commit: 'optional - write Mistakes/Memory/observe on refute/confirm (default true)',
        #   proxy:  'optional - upstream proxy for TransparentBrowser (e.g. "tor")'
        # )
        #
        # Browser-backed self fact-checking. Drives PWN::Plugins::TransparentBrowser
        # in :headless mode against a canonical source for the claim class,
        # renders the DOM (JS executed), and returns:
        #
        #   { claim:, kind:, verdict: :confirmed|:refuted|:unknown,
        #     confidence: 0.0..1.0,
        #     evidence: [{url:, title:, excerpt:, dom_sha:, screenshot:}],
        #     action_taken: :mistakes_record | :extro_observe | :learning_note | nil }
        #
        # On :refuted  -> Mistakes.record(tool:'assumption', error:claim) so the
        #                 KNOWN MISTAKES block warns every future run.
        # On :confirmed-> observe(category::intel, ttl:30d) reinforces w/ freshness.
        # On :unknown  -> Learning.note_outcome(success:false, tags:['needs_human']).
        #
        # This is the extrospective mirror of Mistakes: a PROACTIVE trigger that
        # catches the model being wrong about the world before a human does.

        public_class_method def self.verify(opts = {})
          claim = opts[:claim].to_s.strip
          raise 'ERROR: claim is required' if claim.empty?

          kind   = (opts[:kind] || detect_claim_kind(claim: claim, url: opts[:url])).to_sym
          commit = opts.key?(:commit) ? !opts[:commit].nil? && opts[:commit] != false : true
          proxy  = opts[:proxy] || web_config[:proxy]

          evidence = []
          verdict  = :unknown
          conf     = 0.0

          with_headless_browser(proxy: proxy) do |bo|
            case kind
            when :cve
              cve = claim[/CVE-\d{4}-\d{4,}/i].to_s.upcase
              %W[https://nvd.nist.gov/vuln/detail/#{cve} https://www.cve.org/CVERecord?id=#{cve}].each do |u|
                fp = fingerprint_page(browser_obj: bo, url: u)
                evidence << fp if fp
              end
              body = evidence.map { |e| e[:text].to_s }.join(' ')
              if evidence.empty? || evidence.all? { |e| e[:status].to_i >= 400 } || body =~ /could not be found|does not exist|reserved but/i
                verdict = :refuted
                conf = 0.8
              else
                prod = claim.sub(/CVE-\d{4}-\d{4,}/i, '').gsub(/affects?|is|in|the/i, ' ').split.select { |w| w.length > 2 }
                hit  = prod.count { |w| body.downcase.include?(w.downcase) }
                if prod.empty? || hit.to_f / prod.length >= 0.5
                  verdict = :confirmed
                  conf = prod.empty? ? 0.6 : [0.5 + (hit.to_f / prod.length * 0.5), 0.95].min
                else
                  verdict = :refuted
                  conf = 0.6
                end
              end
            when :doc
              u = opts[:url] || claim[URI::DEFAULT_PARSER.make_regexp(%w[http https])]
              fp = fingerprint_page(browser_obj: bo, url: u)
              evidence << fp if fp
              if fp.nil? || fp[:status].to_i >= 400 || fp[:reachable] == false
                verdict = :refuted
                conf = 0.7
              else
                snippet = claim.sub(u.to_s, '').strip
                overlap = fuzzy_overlap(needle: snippet, haystack: fp[:text].to_s)
                if fp[:title].to_s =~ /not found|404|error/i && overlap < 0.2
                  verdict = :refuted
                  conf = 0.7
                else
                  verdict = overlap >= 0.4 ? :confirmed : :unknown
                  conf    = overlap
                end
              end
            when :version
              proj = claim[/[A-Za-z][\w.+-]{2,}/].to_s
              ver  = claim[/v?\d+\.\d+(?:\.\d+)?/].to_s
              %W[https://rubygems.org/gems/#{proj} https://pypi.org/project/#{proj}/ https://github.com/search?q=#{URI.encode_www_form_component(proj)}&type=repositories].each do |u|
                fp = fingerprint_page(browser_obj: bo, url: u)
                evidence << fp if fp
              end
              body = evidence.map { |e| e[:text].to_s }.join(' ')
              if !ver.empty? && body.include?(ver)
                verdict = :confirmed
                conf = 0.7
              elsif body =~ /\d+\.\d+(?:\.\d+)?/
                verdict = :unknown
                conf = 0.3
              end
            else
              q  = URI.encode_www_form_component(claim)
              fp = fingerprint_page(browser_obj: bo, url: "https://html.duckduckgo.com/html/?q=#{q}")
              evidence << fp if fp
              overlap = fuzzy_overlap(needle: claim, haystack: fp ? fp[:text].to_s : '')
              verdict = overlap >= 0.5 ? :confirmed : :unknown
              conf    = overlap
            end
          end

          evidence.each { |e| e.delete(:text) }
          action = commit ? commit_verdict(claim: claim, kind: kind, verdict: verdict, confidence: conf, evidence: evidence) : nil
          { claim: claim, kind: kind, verdict: verdict, confidence: conf.round(2), evidence: evidence, action_taken: action }
        rescue StandardError => e
          { claim: claim, kind: kind, verdict: :unknown, confidence: 0.0, evidence: evidence, error: "#{e.class}: #{e.message}", action_taken: nil }
        end

        # Supported Method Parameters::
        # obs = PWN::AI::Agent::Extrospection.watch(
        #   url:      'required - URL to render and fingerprint',
        #   selector: 'optional - CSS selector whose innerText to hash (default full body)',
        #   ttl:      'optional - seconds until stale (default 7 days)',
        #   proxy:    'optional - upstream proxy for TransparentBrowser'
        # )
        #
        # Passive change-detection on an external artefact you care about
        # (target /api/version, vendor changelog, bounty scope page).
        # Renders headless, hashes the DOM text, screenshots, and persists as
        # observe(category: :web). On subsequent snapshot(sections:[:web]) or
        # watch of the same URL, a hash mismatch surfaces in drift() as
        # ~web.<host>.dom_sha exactly like ~toolchain.nmap today.

        public_class_method def self.watch(opts = {})
          url = opts[:url].to_s
          raise 'ERROR: url is required' if url.empty?

          ttl   = opts[:ttl] || (7 * 24 * 3600)
          proxy = opts[:proxy] || web_config[:proxy]
          fp    = nil
          with_headless_browser(proxy: proxy) do |bo|
            fp = fingerprint_page(browser_obj: bo, url: url, selector: opts[:selector], screenshot: true)
          end
          raise "unreachable: #{url}" unless fp

          prior = observations(category: 'web', target: url, limit: 1).first
          changed = prior && prior.dig(:data, :dom_sha) && prior.dig(:data, :dom_sha) != fp[:dom_sha]
          data = fp.slice(:status, :final_url, :title, :dom_sha, :cert_fp, :cert_not_after, :screenshot).merge(excerpt: fp[:text].to_s[0, 200])
          observe(source: 'transparent_browser', category: :web, target: url, data: data, tags: (['watch'] + Array(opts[:tags])).compact, ttl: ttl)
          { url: url, changed: changed, prior_sha: prior && prior.dig(:data, :dom_sha), current: data }
        end

        # Supported Method Parameters::
        # result = PWN::AI::Agent::Extrospection.rf_tune(
        #   freq:             'required - frequency: "101.1", "101.1 FM", "101.100.000", 101_100_000, ...',
        #   host:             'optional - GQRX remote-control host (default 127.0.0.1)',
        #   port:             'optional - GQRX remote-control port (default 7356)',
        #   settle_secs:      'optional - seconds to sample RDS after tune (default 8)',
        #   rds:              'optional - force RDS on/off (default: auto when FM broadcast / band-plan decoder=:rds)',
        #   demodulator_mode: 'optional - e.g. :WFM_ST, :WFM, :FM, :AM (default from band-plan / FM range)',
        #   bandwidth:        'optional - passband Hz string, e.g. "200.000" (default from band-plan)',
        #   record:           'optional - also observe(category: :rf) so it hits EXTROSPECTION (default true)',
        #   ttl:              'optional - observation TTL seconds (default 300 — radio content is ephemeral)'
        # )
        #
        # RF sense organ — the RF analogue of extro_watch / extro_verify.
        # Tunes a *running* GQRX instance (never launches the GUI), demodulates,
        # measures strength, and when appropriate samples RDS (PI / PS / RadioText)
        # so questions like "what's playing on 101.1?" have a live answer.
        # Requires GQRX remote control already listening (default :7356) and an
        # SDR attached; fails fast with actionable advice otherwise.
        # On success, records observe(category: :rf, source: 'gqrx') so correlate
        # and to_context keep the agent aware of what was last heard.

        public_class_method def self.rf_tune(opts = {})
          raw_freq = opts[:freq]
          raise 'ERROR: freq is required' if raw_freq.nil? || raw_freq.to_s.strip.empty?

          host        = (opts[:host] || rf_config[:host] || '127.0.0.1').to_s
          port        = (opts[:port] || rf_config[:port] || 7356).to_i
          settle      = (opts[:settle_secs] || rf_config[:settle_secs] || 8).to_f
          settle      = 1.0 if settle < 1.0
          settle      = 30.0 if settle > 30.0
          record      = opts.key?(:record) ? !opts[:record].nil? && opts[:record] != false : true
          ttl         = (opts[:ttl] || rf_config[:ttl] || 300).to_i
          force_rds   = opts.key?(:rds) ? opts[:rds] : nil

          hz_i, freq_label = normalize_rf_freq(freq: raw_freq)
          plan = match_rf_band_plan(hz: hz_i)
          demod = (opts[:demodulator_mode] || (plan && plan[:demodulator_mode]) || default_rf_demod(hz: hz_i)).to_s.upcase
          bandwidth = (opts[:bandwidth] || (plan && plan[:bandwidth]) || default_rf_bandwidth(hz: hz_i)).to_s
          passband_hz = begin
            require 'pwn/sdr' unless defined?(PWN::SDR)
            PWN::SDR.hz_to_i(freq: bandwidth)
          rescue StandardError
            bandwidth.to_s.gsub(/[^\d]/, '').to_i
          end
          passband_hz = 200_000 if passband_hz <= 0
          decoder_key = plan && plan[:decoder]
          band_name   = plan && plan[:name]
          do_rds = if force_rds.nil?
                     decoder_key.to_s == 'rds' || hz_i.between?(87_500_000, 108_100_000)
                   else
                     !force_rds.nil? && force_rds != false
                   end

          unless tcp_open?(host: host, port: port)
            advice = 'Start GQRX with remote control enabled (Tools → Remote Control, port 7356) and an SDR attached, then retry extro_rf_tune.'
            err = {
              ok: false,
              error: "gqrx remote control not reachable at #{host}:#{port}",
              advice: advice,
              freq: freq_label,
              hz: hz_i,
              band_plan: band_name,
              demodulator_mode: demod,
              bandwidth: bandwidth
            }
            observe(source: 'gqrx', category: :rf, target: freq_label, data: err, tags: %w[rf_tune unreachable], ttl: ttl) if record
            return err
          end

          require 'pwn/sdr/gqrx' unless defined?(PWN::SDR::GQRX)
          sock = nil
          begin
            sock = PWN::SDR::GQRX.connect(target: host, port: port)
            # Ensure DSP is running so strength/RDS update.
            begin
              dsp = PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'u DSP').to_s.strip
              PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U DSP 1', resp_ok: 'RPRT 0') if dsp == '0'
            rescue StandardError
              nil
            end

            PWN::SDR::GQRX.cmd(
              gqrx_sock: sock,
              cmd: "M #{demod} #{passband_hz}",
              resp_ok: 'RPRT 0'
            )
            PWN::SDR::GQRX.cmd(
              gqrx_sock: sock,
              cmd: "F #{hz_i}",
              resp_ok: 'RPRT 0'
            )
            sleep 0.4

            strength = begin
              PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'l STRENGTH').to_f
            rescue StandardError
              nil
            end
            mode_now = begin
              PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'm').to_s.strip
            rescue StandardError
              "#{demod} #{passband_hz}"
            end
            tuned = begin
              PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'f').to_s.strip
            rescue StandardError
              freq_label
            end

            rds = do_rds ? sample_rds(gqrx_sock: sock, settle_secs: settle) : nil

            payload = {
              ok: true,
              freq: freq_label,
              hz: hz_i,
              tuned: tuned,
              strength_dbfs: strength,
              demodulator_mode: demod,
              mode: mode_now,
              bandwidth: bandwidth,
              passband_hz: passband_hz,
              band_plan: band_name,
              decoder: decoder_key,
              rds: rds,
              now_playing: rds && (rds[:radiotext].to_s.strip.empty? ? nil : rds[:radiotext].to_s.strip),
              station: rds && (rds[:station].to_s.strip.empty? ? nil : rds[:station].to_s.strip),
              host: host,
              port: port,
              captured_at: Time.now.utc.iso8601
            }

            if record
              summary = build_rf_summary(payload)
              observe(
                source: 'gqrx',
                category: :rf,
                target: freq_label,
                data: summary,
                tags: ['rf_tune', band_name, decoder_key, ('rds' if rds)].compact.map(&:to_s),
                ttl: ttl
              )
              payload[:observed] = true
              payload[:summary] = summary
            else
              payload[:observed] = false
            end

            payload
          rescue StandardError => e
            {
              ok: false,
              error: "#{e.class}: #{e.message}",
              freq: freq_label,
              hz: hz_i,
              band_plan: band_name,
              advice: 'Confirm GQRX is running with remote control, the SDR is not claimed by another process, and the frequency is in-band for the attached radio.'
            }
          ensure
            begin
              PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U RDS 0') if sock && do_rds
            rescue StandardError
              nil
            end
            begin
              PWN::SDR::GQRX.disconnect(gqrx_sock: sock) if sock
            rescue StandardError
              nil
            end
          end
        end

        # Supported Method Parameters::
        # report = PWN::AI::Agent::Extrospection.revalidate_memory(
        #   limit: 'optional - max :fact entries to check (default 25)',
        #   proxy: 'optional - upstream proxy for TransparentBrowser'
        # )
        #
        # The browser as garbage-collector for PWN::Memory. Walks :fact entries
        # containing a CVE id, version string or URL, runs verify() on each and
        # prefixes stale ones with [UNVERIFIED yyyy-mm-dd] so the injected
        # MEMORY block stops calcifying into confidently-wrong priors.
        # Designed to be scheduled: cron_create(schedule:'0 4 * * 0',
        #   ruby:'PWN::AI::Agent::Extrospection.revalidate_memory')

        public_class_method def self.revalidate_memory(opts = {})
          return { checked: 0, refuted: [], confirmed: [], unknown: [] } unless defined?(PWN::Memory)

          lim   = opts[:limit] || 25
          proxy = opts[:proxy] || web_config[:proxy]
          rx    = %r{(CVE-\d{4}-\d{4,}|v?\d+\.\d+\.\d+|https?://\S+)}i
          out   = { checked: 0, refuted: [], confirmed: [], unknown: [] }

          PWN::Memory.load.each do |key, v|
            break if out[:checked] >= lim
            next unless v.is_a?(Hash) && v[:category].to_s == 'fact' && v[:value].to_s =~ rx
            next if v[:value].to_s.start_with?('[UNVERIFIED')

            res = verify(claim: v[:value].to_s[0, 400], commit: false, proxy: proxy)
            out[:checked] += 1
            out[res[:verdict]] << key
            next unless res[:verdict] == :refuted && res[:confidence] >= 0.6

            stamp = Time.now.utc.strftime('%Y-%m-%d')
            PWN::Memory.remember(key: key, value: "[UNVERIFIED #{stamp}] #{v[:value]}", category: :fact)
            observe(source: 'extro_verify', category: :web, target: key.to_s, data: "Memory :fact '#{key}' failed re-validation (#{res[:confidence]})", tags: %w[stale memory])
          end
          out
        end

        # Supported Method Parameters::
        # findings = PWN::AI::Agent::Extrospection.correlate(
        #   limit: 'optional - max findings returned (default 10)'
        # )
        #
        # THE join between introspection and extrospection. Cross-references:
        #   * Metrics tools with success_rate < 50 %  vs  toolchain drift / missing bins
        #   * Learning failures                       vs  host / net drift on the same day
        #   * Observations tagged :vuln / :intel      vs  installed package versions
        # Emits human-readable, actionable findings the model can reason on.

        public_class_method def self.correlate(opts = {})
          limit    = opts[:limit] || 10
          findings = []
          delta    = drift(live: false)
          snap     = load[:snapshot] || {}

          # 1) failing tools whose backing binary vanished / changed version
          if defined?(Metrics)
            Metrics.summary(limit: 50).each do |m|
              next unless m[:success_rate] < 0.5 && m[:calls] > 2

              bin = m[:name].to_s.split('_').first
              tc  = Array(delta[:changed]).find { |c| c[:path].to_s.include?("toolchain.#{bin}") }
              miss = snap.dig(:toolchain, bin.to_sym).to_s.empty?
              next unless tc || miss

              findings << { kind: :tool_env_mismatch, tool: m[:name], success_rate: m[:success_rate], evidence: tc || "binary '#{bin}' not found in PATH", advice: "Re-verify `which #{bin}` / reinstall before relying on #{m[:name]}." }
            end
          end

          # 2) introspective failures coinciding with extrospective drift
          if defined?(Learning)
            Learning.outcomes(limit: 30, success: false).each do |o|
              day = o[:timestamp].to_s[0, 10]
              hit = Array(delta[:changed]).find { |c| c[:after].to_s.include?(day) || c[:path].to_s.match?(/kernel|repo|net/) }
              findings << { kind: :failure_during_drift, task: o[:task], on: day, drift: hit, advice: 'Environment changed around this failure — re-test under current snapshot before trusting the negative result.' } if hit
            end
          end

          # 3) intel observations matching installed components
          pkgs = snap[:toolchain] || {}
          observations(category: 'intel', limit: 100).each do |ob|
            blob = ob[:data].to_s.downcase
            pkgs.each do |bin, ver|
              next if ver.to_s.empty?
              next unless blob.include?(bin.to_s.downcase)

              findings << { kind: :intel_matches_host, component: bin, installed: ver, intel: ob[:data], source: ob[:source], advice: "Review #{ob[:source]} advisory for #{bin} #{ver} on this host." }
            end
          end

          # 4) :rf observations vs missing SDR hardware / binaries
          rf = snap[:rf] || {}
          hw_present = %i[rtl_sdr hackrf flipper gqrx_sock].any? { |k| rf_present?(val: rf[k]) }
          observations(category: 'rf', limit: 50).each do |ob|
            miss = RF_BINS.select { |b| pkgs[b.to_sym].to_s.empty? }
            if !hw_present
              findings << { kind: :rf_no_hardware, observation: ob[:data], source: ob[:source], target: ob[:target], advice: 'RF observation recorded but no SDR hardware detected in snapshot — plug in RTL-SDR/HackRF/Flipper or start gqrx (`-r`) before trusting RF results.' }
            elsif rf[:gqrx_sock] == false && ob[:source].to_s == 'gqrx'
              findings << { kind: :rf_gqrx_down, observation: ob[:data], target: ob[:target], advice: 'gqrx remote-control socket (127.0.0.1:7356) is closed — start gqrx with remote control enabled before re-running the scan.' }
            elsif !miss.empty?
              findings << { kind: :rf_toolchain_gap, missing: miss, observation: ob[:data], advice: "SDR toolchain gap: install #{miss.join(', ')} to decode/act on this RF observation." }
            end
          end

          # 5) :web drift on a target the same day a Learning failure references it —
          #    "your exploit stopped working because the TARGET changed, not your approach"
          if defined?(Learning)
            observations(category: 'web', limit: 50).each do |ob|
              tgt  = ob[:target].to_s
              host = safe_host(url: tgt)
              Learning.outcomes(limit: 30, success: false).each do |o|
                next unless o[:task].to_s.include?(host) || o[:details].to_s.include?(host)

                findings << { kind: :target_web_drift, target: tgt, dom_sha: ob.dig(:data, :dom_sha), task: o[:task], advice: "Target #{host} DOM changed (#{ob[:timestamp]}) around this failure — re-recon before assuming your technique is wrong." }
              end
            end
          end

          # 6) extro_verify refutations whose claim substring appears in a PWN::Memory :fact -> stale memory
          if defined?(PWN::Memory)
            observations(category: 'web', tag: 'stale', limit: 50).each do |ob|
              findings << { kind: :stale_memory_fact, key: ob[:target], evidence: ob[:data], advice: "PWN::Memory[:#{ob[:target]}] failed browser re-verification — audit or memory_forget it before it poisons future prompts." }
            end
          end

          # 7) :intel observations whose source anchor is currently probe_web-unreachable -> downgrade
          web = snap[:web] || {}
          web.each do |host, fp|
            next unless fp.is_a?(Hash) && (fp[:reachable] == false || fp[:status].to_i >= 500)

            observations(category: 'intel', limit: 100).each do |ob|
              next unless ob[:source].to_s.include?(host.to_s) || ob[:data].to_s.include?(host.to_s)

              findings << { kind: :intel_source_unreachable, source: host, status: fp[:status], intel: ob[:data].to_s[0, 120], advice: "Feed anchor #{host} is currently unreachable (#{fp[:status] || 'down'}) — treat this :intel as stale until probe_web sees it 2xx again." }
            end
          end

          # 8) raw drift as low-priority findings when nothing else matched
          Array(delta[:added]).first(5).each   { |c| findings << { kind: :env_added,   detail: c } } if findings.empty?
          Array(delta[:removed]).first(5).each { |c| findings << { kind: :env_removed, detail: c } } if findings.empty?

          findings.uniq.first(limit)
        end

        # Supported Method Parameters::
        # ctx = PWN::AI::Agent::Extrospection.to_context(
        #   drift_limit: 'optional - max drift lines (default 4)',
        #   obs_limit: 'optional - max observation lines (default 4)'
        # )

        public_class_method def self.to_context(opts = {})
          dlim = opts[:drift_limit] || 4
          olim = opts[:obs_limit]   || 4
          store = load
          return '' if (store[:snapshot] || {}).empty? && Array(store[:observations]).empty?

          snap  = store[:snapshot] || {}
          delta = compute_drift(before: store[:previous] || {}, after: snap)
          lines = []
          host  = snap[:host] || {}
          lines << "  host_fp   : #{snap[:fingerprint]}  (#{host[:os]} #{host[:kernel]}, #{host[:arch]})" if snap[:fingerprint]
          lines << "  captured  : #{snap[:captured_at]}" if snap[:captured_at]

          ch = Array(delta[:changed]).first(dlim).map { |c| "    ~ #{c[:path]}: #{c[:before].to_s[0, 40]} -> #{c[:after].to_s[0, 40]}" }
          ad = Array(delta[:added]).first(dlim).map   { |c| "    + #{c[:path]}: #{c[:after].to_s[0, 60]}" }
          rm = Array(delta[:removed]).first(dlim).map { |c| "    - #{c[:path]}: #{c[:before].to_s[0, 60]}" }
          unless ch.empty? && ad.empty? && rm.empty?
            lines << '  drift     :'
            lines.concat(ch).concat(ad).concat(rm)
          end

          obs = observations(limit: olim, fresh_only: true)
          unless obs.empty?
            lines << '  observed  :'
            obs.each { |o| lines << "    * [#{o[:category]}/#{o[:source]}] #{"#{o[:target]} — " if o[:target]}#{o[:data].to_s.gsub(/\s+/, ' ')[0, 120]}" }
          end

          "EXTROSPECTION (world-state; correlate with introspective failures)\n#{lines.join("\n")}\n\n"
        end

        # Supported Method Parameters::
        # stats = PWN::AI::Agent::Extrospection.stats

        public_class_method def self.stats
          store = load
          snap  = store[:snapshot] || {}
          delta = compute_drift(before: store[:previous] || {}, after: snap)
          {
            snapshot_captured_at: snap[:captured_at],
            snapshot_fingerprint: snap[:fingerprint],
            observations: Array(store[:observations]).length,
            drift_changed: Array(delta[:changed]).length,
            drift_added: Array(delta[:added]).length,
            drift_removed: Array(delta[:removed]).length,
            toolchain_bins: (snap[:toolchain] || {}).count { |_, v| !v.to_s.empty? },
            listening_ports: Array(snap.dig(:net, :listening)).length,
            rf_devices: (snap[:rf] || {}).values_at(:rtl_sdr, :hackrf, :flipper, :gqrx_sock).count { |v| rf_present?(val: v) },
            web_anchors: (snap[:web] || {}).count { |_, v| v.is_a?(Hash) && v[:reachable] }
          }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Extrospection.auto_extrospect(
        #   session_id: 'optional - id of the just-completed session (for tagging)'
        # )
        #
        # Called by Learning.auto_introspect when
        # PWN::Env[:ai][:agent][:auto_extrospect] is truthy. Captures a fresh
        # snapshot and, if drift is non-trivial, records it as an observation
        # and a PWN::Memory :env fact so the NEXT session's system prompt
        # already knows the world moved. Never raises.

        public_class_method def self.auto_extrospect(opts = {})
          sid = opts[:session_id]
          return unless auto_extrospect_enabled?

          # Ambient baseline only — never toolchain / rf / web (those spawn
          # hardware probes or GUI binaries and belong on the *sense* path).
          res   = snapshot(persist: true, sections: AUTO_SECTIONS)
          delta = res[:drift]
          moved = Array(delta[:changed]).length + Array(delta[:added]).length + Array(delta[:removed]).length
          return res if moved.zero?

          summary = summarise_drift(delta: delta)
          observe(source: 'auto_extrospect', category: :env, data: summary, tags: ['drift', sid.to_s].reject(&:empty?))
          if defined?(PWN::Memory)
            key = :"extro_drift_#{res[:snapshot][:fingerprint]}"
            PWN::Memory.remember(key: key, value: "ENV DRIFT #{res[:snapshot][:captured_at]}: #{summary[0, 260]}", category: :env)
          end
          res
        rescue StandardError => e
          warn "[pwn-ai/extrospection] auto_extrospect swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Extrospection.reset

        public_class_method def self.reset
          FileUtils.rm_f(EXTRO_FILE)
          { cleared: true }
        end

        # -------------------------------------------------------------
        # privates
        # -------------------------------------------------------------

        private_class_method def self.auto_extrospect_enabled?
          return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          PWN::Env.dig(:ai, :agent, :auto_extrospect) ? true : false
        rescue StandardError
          false
        end

        private_class_method def self.sh(opts = {})
          cmd = opts[:cmd].to_s
          return '' if cmd.empty?

          out, = Open3.capture2e(cmd)
          out.to_s.strip
        rescue StandardError
          ''
        end

        private_class_method def self.probe_host
          {
            hostname: begin
              Socket.gethostname
            rescue StandardError
              ''
            end,
            os: sh(cmd: 'uname -s'),
            kernel: sh(cmd: 'uname -r'),
            arch: sh(cmd: 'uname -m'),
            distro: begin
              File.read('/etc/os-release')[/PRETTY_NAME="?([^"\n]+)/, 1]
            rescue StandardError
              nil
            end,
            uptime_s: begin
              File.read('/proc/uptime').split.first.to_i
            rescue StandardError
              nil
            end,
            user: ENV.fetch('USER', ''),
            cpu_count: (Etc.respond_to?(:nprocessors) ? Etc.nprocessors : nil)
          }
        end

        private_class_method def self.probe_net
          listen = sh(cmd: 'ss -tlnH 2>/dev/null').lines.map { |l| l.split[3].to_s.split(':').last }.compact.uniq.sort
          ifaces = sh(cmd: 'ip -o -4 addr show 2>/dev/null').lines.map do |l|
            p = l.split
            { if: p[1], addr: p[3] }
          end
          route = sh(cmd: 'ip route show default 2>/dev/null').lines.first.to_s.strip
          { listening: listen, interfaces: ifaces, default_route: route }
        end

        # Inventory of tooling PATH presence. SAFE_VERSION_BINS may receive a
        # timeout-bounded --version; PRESENCE_ONLY_BINS + anything that looks
        # GUI/JVM never get executed — path-only. Never open Burp/ZAP/msf/GQRX.
        private_class_method def self.probe_toolchain
          PROBE_BINS.each_with_object({}) do |b, h|
            path = sh(cmd: "which #{Shellwords.escape(b)} 2>/dev/null").split("\n").first.to_s.strip
            if path.empty?
              h[b.to_sym] = ''
            elsif presence_only_bin?(b)
              h[b.to_sym] = path
            else
              ver = sh(cmd: "timeout 2 #{Shellwords.escape(b)} --version 2>/dev/null").lines.first.to_s.strip[0, 80]
              h[b.to_sym] = "#{path} #{ver}".strip
            end
          end
        end

        private_class_method def self.presence_only_bin?(name)
          n = name.to_s
          return true if PRESENCE_ONLY_BINS.include?(n)

          # Defence in depth: never auto-exec anything that smells like a GUI suite.
          n.match?(/burp|zaproxy|zap$|msfconsole|gqrx|wireshark|firefox|chrome|chromium/i)
        end

        private_class_method def self.probe_repo
          root = defined?(PWN::ROOT) ? PWN::ROOT.to_s : Dir.pwd
          return {} unless Dir.exist?(File.join(root, '.git'))

          {
            root: root,
            head: sh(cmd: "git -C #{root} rev-parse --short HEAD"),
            branch: sh(cmd: "git -C #{root} rev-parse --abbrev-ref HEAD"),
            dirty: !sh(cmd: "git -C #{root} status --porcelain").empty?,
            pwn_version: (defined?(PWN::VERSION) ? PWN::VERSION : nil)
          }
        end

        private_class_method def self.probe_env
          {
            cwd: Dir.pwd,
            ruby: RUBY_VERSION,
            path_entries: ENV.fetch('PATH', '').split(':').length,
            ai_engine: (PWN::Env.dig(:ai, :active) if defined?(PWN::Env) && PWN::Env.is_a?(Hash))
          }
        rescue StandardError
          { cwd: Dir.pwd, ruby: RUBY_VERSION }
        end

        # Passive RF / SDR hardware inventory. NO transmit, NO active spectrum
        # scan — this is the RF analogue of probe_toolchain: "what radios and
        # SDR plumbing are attached / reachable right now?" so drift can flag
        # "HackRF unplugged", "gqrx remote-control down", "new RTL dongle".
        private_class_method def self.probe_rf
          {
            rtl_sdr: sh(cmd: 'timeout 3 rtl_test -t 2>&1 | head -5'),
            hackrf: sh(cmd: 'timeout 3 hackrf_info 2>&1 | head -8'),
            soapy: sh(cmd: 'timeout 3 SoapySDRUtil --find 2>&1 | head -10'),
            gqrx_sock: tcp_open?(host: '127.0.0.1', port: 7356),
            flipper: Dir.glob('/dev/serial/by-id/*Flipper*').any?,
            serial_devs: Dir.glob('/dev/{ttyUSB,ttyACM}*'),
            band_plans: rf_band_plan_keys.length
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.tcp_open?(opts = {})
          host = opts[:host] || '127.0.0.1'
          port = opts[:port].to_i
          Socket.tcp(host, port, connect_timeout: 1, &:close)
          true
        rescue StandardError
          false
        end

        private_class_method def self.rf_present?(opts = {})
          v = opts[:val]
          return false if v.nil? || v == false || v.to_s.strip.empty?

          v.to_s !~ /no\s+.*devices|no\s+hackrf|not\s+found|no\s+such\s+file|command\s+not\s+found|^false$/i
        end

        private_class_method def self.rf_band_plan_keys
          require 'pwn/sdr/frequency_allocation' unless defined?(PWN::SDR::FrequencyAllocation)
          PWN::SDR::FrequencyAllocation.band_plans.keys.map(&:to_s).sort
        rescue StandardError
          []
        end

        # Rendered-DOM fingerprint of a small, config-declared set of canonical
        # web anchors the agent depends on for truth (feed reachability,
        # upstream drift, in-scope target tech fingerprint). OPT-IN — never
        # part of the default auto_extrospect section set because a headless
        # browser is ~1-3s cold vs ~50ms for probe_host.
        private_class_method def self.probe_web
          anchors = web_anchors
          return { anchors: 0 } if anchors.empty?

          out = {}
          with_headless_browser(proxy: web_config[:proxy]) do |bo|
            anchors.first(web_config[:max_anchors]).each do |u|
              host = safe_host(url: u).tr('.', '_')
              fp   = fingerprint_page(browser_obj: bo, url: u, screenshot: web_config[:screenshot])
              out[host.to_sym] = fp ? fp.slice(:status, :final_url, :title, :dom_sha, :server, :generator, :cert_fp, :cert_not_after, :reachable, :screenshot) : { reachable: false }
            end
          end
          out
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.web_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :web) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          {
            anchors: Array(cfg[:anchors] || cfg[:web_anchors]),
            proxy: cfg[:proxy],
            max_anchors: (cfg[:max_anchors] || 8).to_i,
            per_page_timeout: (cfg[:per_page_timeout] || 15).to_i,
            screenshot: cfg.key?(:screenshot) ? !cfg[:screenshot].nil? && cfg[:screenshot] != false : false,
            allow_targets: cfg[:allow_targets] ? true : false
          }
        rescue StandardError
          { anchors: [], proxy: nil, max_anchors: 8, per_page_timeout: 15, screenshot: false, allow_targets: false }
        end

        private_class_method def self.web_anchors
          a = web_config[:anchors]
          a = DEFAULT_WEB_ANCHORS.dup if a.empty?
          a += Array(PWN::Env[:targets]) if defined?(PWN::Env) && PWN::Env.is_a?(Hash) && web_config[:allow_targets]
          a.compact.map(&:to_s).reject(&:empty?).uniq
        rescue StandardError
          DEFAULT_WEB_ANCHORS.dup
        end

        private_class_method def self.safe_host(opts = {})
          URI.parse(opts[:url].to_s).host || opts[:url].to_s
        rescue StandardError
          opts[:url].to_s
        end

        # One shared headless browser per call — open once, reuse across
        # anchors, always close in ensure. Prefers :headless (firefox) which
        # is lightest; degrades to :rest (RestClient) if watir/selenium is
        # unavailable so probe_web/verify/watch never hard-fail the loop.
        private_class_method def self.with_headless_browser(opts = {})
          require 'pwn/plugins/transparent_browser'
          bo = nil
          begin
            bo = PWN::Plugins::TransparentBrowser.open(browser_type: :headless, proxy: opts[:proxy])
          rescue StandardError
            bo = PWN::Plugins::TransparentBrowser.open(browser_type: :rest, proxy: opts[:proxy])
          end
          yield bo
        ensure
          begin
            PWN::Plugins::TransparentBrowser.close(browser_obj: bo) if bo
          rescue StandardError
            nil
          end
        end

        private_class_method def self.fingerprint_page(opts = {})
          bo  = opts[:browser_obj]
          url = opts[:url].to_s
          return nil if bo.nil? || url.empty?

          tmo = web_config[:per_page_timeout]
          b   = bo[:browser]
          if bo[:type] == :rest
            resp = b.get(url) { |r, _rq, _res| r }
            body = resp.body.to_s
            require 'nokogiri'
            doc  = Nokogiri::HTML.parse(body)
            text = doc.text.to_s
            cfp, cna = tls_fingerprint(url: url)
            return { url: url, final_url: url, status: resp.code.to_i, title: doc.title.to_s,
                     server: resp.headers[:server].to_s, generator: doc.at('meta[name="generator"]')&.[]('content').to_s,
                     dom_sha: Digest::SHA256.hexdigest(text)[0, 16], text: text, cert_fp: cfp,
                     cert_not_after: cna, reachable: resp.code.to_i < 400 }
          end
          Timeout.timeout(tmo) { b.goto(url) }
          text  = extract_text(browser: b, selector: opts[:selector])
          title = safe_attr(browser: b, meth: :title)
          final = safe_attr(browser: b, meth: :url) || url
          gen   = safe_meta(browser: b, name: 'generator')
          shot  = opts[:screenshot] ? capture_screenshot(browser: b, url: url) : nil
          cfp, cna = tls_fingerprint(url: final)
          { url: url, final_url: final, status: 200, title: title.to_s, generator: gen.to_s, server: nil,
            dom_sha: Digest::SHA256.hexdigest(text.to_s)[0, 16], text: text.to_s,
            cert_fp: cfp, cert_not_after: cna, screenshot: shot, reachable: true }
        rescue StandardError => e
          { url: url, reachable: false, status: 0, error: "#{e.class}: #{e.message.to_s[0, 120]}", text: '' }
        end

        private_class_method def self.extract_text(opts = {})
          b   = opts[:browser]
          sel = opts[:selector]
          return b.element(css: sel).text if sel && b.element(css: sel).exists?

          b.text
        rescue StandardError
          b.respond_to?(:text) ? b.text.to_s : ''
        end

        private_class_method def self.safe_attr(opts = {})
          opts[:browser].public_send(opts[:meth])
        rescue StandardError
          nil
        end

        private_class_method def self.safe_meta(opts = {})
          el = opts[:browser].element(css: "meta[name=\"#{opts[:name]}\"]")
          el.exists? ? el.attribute_value('content') : ''
        rescue StandardError
          ''
        end

        private_class_method def self.capture_screenshot(opts = {})
          FileUtils.mkdir_p(WEB_SHOT_DIR)
          host = safe_host(url: opts[:url]).gsub(/[^\w.-]/, '_')
          path = File.join(WEB_SHOT_DIR, "#{host}.png")
          opts[:browser].screenshot.save(path)
          path
        rescue StandardError
          nil
        end

        private_class_method def self.tls_fingerprint(opts = {})
          u = URI.parse(opts[:url].to_s)
          return [nil, nil] unless u.scheme == 'https'

          require 'openssl'
          ssl = tcp = nil
          tcp = TCPSocket.new(u.host, u.port || 443)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
          ssl.hostname = u.host
          ssl.connect
          cert = ssl.peer_cert
          [Digest::SHA256.hexdigest(cert.to_der)[0, 16], cert.not_after.utc.iso8601]
        rescue StandardError
          [nil, nil]
        ensure
          ssl&.close
          tcp&.close
        end

        private_class_method def self.fuzzy_overlap(opts = {})
          needle = opts[:needle].to_s.downcase.scan(/[a-z0-9]{3,}/).uniq
          hay    = opts[:haystack].to_s.downcase
          return 0.0 if needle.empty?

          hit = needle.count { |w| hay.include?(w) }
          hit.to_f / needle.length
        end

        private_class_method def self.detect_claim_kind(opts = {})
          c = opts[:claim].to_s
          return :doc     if opts[:url] || c =~ URI::DEFAULT_PARSER.make_regexp(%w[http https])
          return :cve     if c =~ /CVE-\d{4}-\d{4,}/i
          return :version if c =~ /\bv?\d+\.\d+(?:\.\d+)?\b/

          :generic
        end

        private_class_method def self.commit_verdict(opts = {})
          claim = opts[:claim]
          ev    = Array(opts[:evidence]).first
          case opts[:verdict]
          when :refuted
            Mistakes.record(tool: 'assumption', error: "REFUTED (extro_verify #{opts[:kind]}, conf=#{opts[:confidence].round(2)}): #{claim}", args: ev&.dig(:final_url), source: :model) if defined?(Mistakes)
            observe(source: 'extro_verify', category: :web, target: ev&.dig(:final_url), data: "REFUTED: #{claim}", tags: %w[verify refuted], ttl: 30 * 24 * 3600)
            :mistakes_record
          when :confirmed
            observe(source: 'extro_verify', category: :intel, target: ev&.dig(:final_url), data: claim, tags: %w[verify confirmed], ttl: 30 * 24 * 3600)
            :extro_observe
          else
            Learning.note_outcome(task: "extro_verify: #{claim[0, 120]}", success: false, details: 'verdict :unknown — needs human review', tags: %w[needs_human extro_verify]) if defined?(Learning) && Learning.respond_to?(:note_outcome)
            :learning_note
          end
        rescue StandardError
          nil
        end

        private_class_method def self.flatten(opts = {})
          hash   = opts[:hash] || {}
          prefix = opts[:prefix].to_s
          out    = opts[:out] || {}
          hash.each do |k, v|
            path = prefix.empty? ? k.to_s : "#{prefix}.#{k}"
            case v
            when Hash  then flatten(hash: v, prefix: path, out: out)
            when Array then out[path] = v.map(&:to_s).sort
            else            out[path] = v
            end
          end
          out
        end

        private_class_method def self.compute_drift(opts = {})
          before = flatten(hash: (opts[:before] || {}).except(:captured_at, :fingerprint))
          after  = flatten(hash: (opts[:after]  || {}).except(:captured_at, :fingerprint))
          changed = []
          added   = []
          removed = []
          (before.keys | after.keys).each do |k|
            next if k =~ /uptime_s$/

            b = before[k]
            a = after[k]
            if b.nil? && !a.nil?
              added << { path: k, after: a }
            elsif a.nil? && !b.nil?
              removed << { path: k, before: b }
            elsif a != b
              changed << { path: k, before: b, after: a }
            end
          end
          { changed: changed, added: added, removed: removed }
        end

        private_class_method def self.summarise_drift(opts = {})
          d = opts[:delta] || {}
          parts = Array(d[:changed]).first(5).map { |c| "~#{c[:path]}:#{c[:before].to_s[0, 30]}->#{c[:after].to_s[0, 30]}" }
          Array(d[:added]).first(5).each   { |c| parts << "+#{c[:path]}" }
          Array(d[:removed]).first(5).each { |c| parts << "-#{c[:path]}" }
          parts.empty? ? '(no drift)' : parts.join(' | ')
        end

        private_class_method def self.http_get_json(opts = {})
          url = opts[:url].to_s
          return nil if url.empty?

          require 'rest-client'
          resp = RestClient::Request.execute(method: :get, url: url, timeout: 8, open_timeout: 4, headers: { accept: :json, user_agent: 'pwn-ai-extrospection' })
          JSON.parse(resp.body, symbolize_names: true)
        rescue StandardError
          nil
        end

        private_class_method def self.intel_nvd(opts = {})
          q     = opts[:query].to_s
          limit = opts[:limit] || 5
          url   = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=#{URI.encode_www_form_component(q)}&resultsPerPage=#{limit}"
          body  = http_get_json(url: url)
          return [] unless body

          Array(body[:vulnerabilities]).first(limit).map do |v|
            c = v[:cve] || {}
            { id: c[:id], published: c[:published], desc: Array(c[:descriptions])&.first&.dig(:value).to_s[0, 300], cvss: c.dig(:metrics, :cvssMetricV31, 0, :cvssData, :baseScore) }
          end
        rescue StandardError
          []
        end

        private_class_method def self.intel_circl(opts = {})
          q     = opts[:query].to_s
          limit = opts[:limit] || 5
          body  = if q =~ /^CVE-\d{4}-\d+$/i
                    r = http_get_json(url: "https://cve.circl.lu/api/cve/#{q.upcase}")
                    r ? [r] : []
                  else
                    http_get_json(url: "https://cve.circl.lu/api/search/#{URI.encode_www_form_component(q)}") || []
                  end
          Array(body).flatten.first(limit).map do |c|
            { id: c[:id], cvss: c[:cvss], summary: c[:summary].to_s[0, 300], refs: Array(c[:references]).first(3) }
          end
        rescue StandardError
          []
        end

        private_class_method def self.intel_exploitdb(opts = {})
          q     = opts[:query].to_s
          limit = opts[:limit] || 5
          bin   = sh(cmd: 'which searchsploit 2>/dev/null')
          return [] if bin.empty?

          raw = sh(cmd: "searchsploit --json #{q.shellescape} 2>/dev/null")
          j   = begin
            JSON.parse(raw, symbolize_names: true)
          rescue StandardError
            nil
          end
          return [] unless j

          Array(j[:RESULTS_EXPLOIT]).first(limit).map { |e| { id: "EDB-#{e[:'EDB-ID']}", title: e[:Title].to_s[0, 200], path: e[:Path] } }
        rescue StandardError
          []
        end

        # ── RF sense helpers (rf_tune) ─────────────────────────────────────

        private_class_method def self.rf_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :rf) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          {
            host: cfg[:host] || '127.0.0.1',
            port: (cfg[:port] || 7356).to_i,
            settle_secs: (cfg[:settle_secs] || 8).to_f,
            ttl: (cfg[:ttl] || 300).to_i
          }
        rescue StandardError
          { host: '127.0.0.1', port: 7356, settle_secs: 8.0, ttl: 300 }
        end

        # Accept free-form user input ("101.1", "101.1 FM", "101.1 MHz",
        # "101100000", "101.100.000", 101_100_000) → [hz_i, human_label].
        private_class_method def self.normalize_rf_freq(opts = {})
          raw = opts[:freq]
          s = raw.to_s.strip
          unit = :auto
          case s
          when /\b(mhz|m hz)\b/i, /\bfm\b/i
            unit = :mhz
          when /\b(khz|k hz)\b/i
            unit = :khz
          when /\b(ghz|g hz)\b/i
            unit = :ghz
          when /\bhz\b/i
            unit = :hz
          end
          s = s.gsub(/[^0-9._-]/, '')
          # Dotted-group form used throughout PWN::SDR ("101.100.000")
          if s.count('.') >= 2
            hz = s.gsub('.', '').to_i
            return [hz, human_rf_label(hz: hz)]
          end
          num = s.gsub('_', '').to_f
          raise "ERROR: could not parse frequency from #{opts[:freq].inspect}" if num <= 0

          hz = case unit
               when :hz  then num.to_i
               when :khz then (num * 1_000).to_i
               when :mhz then (num * 1_000_000).to_i
               when :ghz then (num * 1_000_000_000).to_i
               else
                 # Heuristic: bare integers ≥ 1e6 already look like Hz
                 # (e.g. 101100000); everything smaller is treated as MHz
                 # because broadcast / hobby speech says "101.1" / "433.92".
                 if num >= 1_000_000
                   num.to_i
                 else
                   (num * 1_000_000).to_i
                 end
               end
          # Snap FM broadcast channels onto the 100 kHz raster when they land near it.
          hz = ((hz + 50_000) / 100_000) * 100_000 if hz.between?(87_500_000, 108_100_000)
          [hz, human_rf_label(hz: hz)]
        end

        private_class_method def self.human_rf_label(opts = {})
          hz = opts[:hz].to_i
          if hz >= 1_000_000
            mhz = hz / 1_000_000.0
            # Drop trailing zeros: 101.1 not 101.100000
            txt = format('%.6f', mhz).sub(/\.?0+$/, '')
            "#{txt} MHz"
          elsif hz >= 1_000
            "#{format('%.3f', hz / 1_000.0).sub(/\.?0+$/, '')} kHz"
          else
            "#{hz} Hz"
          end
        end

        private_class_method def self.match_rf_band_plan(opts = {})
          hz = opts[:hz].to_i
          require 'pwn/sdr/frequency_allocation' unless defined?(PWN::SDR::FrequencyAllocation)
          # Prefer the narrowest matching plan so e.g. fm_radio (87.9–108 MHz)
          # wins over the broad analog_tv_vhf (54–216 MHz) that contains it.
          # Explicit decoder-bearing plans also beat bare occupancy plans.
          matches = []
          PWN::SDR::FrequencyAllocation.band_plans.each do |name, plan|
            Array(plan[:ranges]).each do |r|
              lo = begin
                PWN::SDR.hz_to_i(freq: r[:start_freq])
              rescue StandardError
                r[:start_freq].to_s.gsub(/[^\d]/, '').to_i
              end
              hi = begin
                PWN::SDR.hz_to_i(freq: r[:target_freq])
              rescue StandardError
                r[:target_freq].to_s.gsub(/[^\d]/, '').to_i
              end
              lo, hi = hi, lo if lo > hi
              # FM broadcast band plan ends at 108.000.000 — include the top channel.
              hi += 100_000 if name.to_s == 'fm_radio'
              next unless hz.between?(lo, hi)

              width = (hi - lo).abs
              decoder_bonus = plan[:decoder] ? 0 : 1
              # Lower score = better match. Decoder-bearing + narrower wins.
              score = [decoder_bonus, width]
              matches << { score: score, name: name.to_s, plan: plan, width: width }
            end
          end
          return nil if matches.empty?

          best = matches.min_by { |m| m[:score] }
          best[:plan].merge(name: best[:name])
        rescue StandardError
          nil
        end

        private_class_method def self.default_rf_demod(opts = {})
          hz = opts[:hz].to_i
          return :WFM_ST if hz.between?(87_500_000, 108_100_000)
          return :AM     if hz.between?(530_000, 1_710_000)
          return :FM     if hz >= 30_000_000

          :WFM
        end

        private_class_method def self.default_rf_bandwidth(opts = {})
          hz = opts[:hz].to_i
          return '200.000' if hz.between?(87_500_000, 108_100_000)
          return '10.000'  if hz.between?(530_000, 1_710_000)

          '15.000'
        end

        # Sample GQRX's built-in RDS decoder over settle_secs.
        # Canonical implementation lives on PWN::SDR::Decoder::RDS.sample —
        # this is a thin adapter so rf_tune stays stable for agents.
        # Returns { pi:, ps_name:, radiotext:, station:, samples: N, settle_secs: }.
        private_class_method def self.sample_rds(opts = {})
          require 'pwn/sdr/decoder/rds' unless defined?(PWN::SDR::Decoder::RDS)
          PWN::SDR::Decoder::RDS.sample(
            gqrx_sock: opts[:gqrx_sock],
            freq_obj: opts[:freq_obj],
            settle_secs: opts[:settle_secs],
            interval: opts[:interval],
            leave_enabled: opts[:leave_enabled]
          )
        end

        private_class_method def self.build_rf_summary(payload)
          parts = []
          parts << payload[:freq].to_s
          parts << "str=#{payload[:strength_dbfs]} dBFS" if payload[:strength_dbfs]
          parts << "mode=#{payload[:demodulator_mode]}" if payload[:demodulator_mode]
          if payload[:rds].is_a?(Hash)
            r = payload[:rds]
            parts << "PI=#{r[:pi]}" if r[:pi]
            parts << "station=#{r[:station]}" if r[:station]
            parts << "PS=#{r[:ps_name]}" if r[:ps_name] && r[:ps_name] != r[:station]
            parts << "RT=#{r[:radiotext]}" if r[:radiotext]
          end
          parts << "plan=#{payload[:band_plan]}" if payload[:band_plan]
          parts.join(' | ')
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Extrospection.snapshot                          # probe host, persist, return {snapshot:, drift:}
              PWN::AI::Agent::Extrospection.drift(live: true)                 # what changed vs last snapshot
              PWN::AI::Agent::Extrospection.observe(source: 'nmap', category: :recon, target: '10.0.0.5', data: '22/tcp open ssh 9.6')
              PWN::AI::Agent::Extrospection.observe(source: 'gqrx', category: :rf, target: '433.920MHz', data: 'peak -34.2 dBFS bw=200k')
              PWN::AI::Agent::Extrospection.observations(category: 'recon', target: '10.0.0.5')
              PWN::AI::Agent::Extrospection.intel(query: 'openssl 3.0', record: true)
              PWN::AI::Agent::Extrospection.correlate                         # introspection x extrospection findings
              PWN::AI::Agent::Extrospection.to_context                        # injected by PromptBuilder
              PWN::AI::Agent::Extrospection.stats
              PWN::AI::Agent::Extrospection.auto_extrospect(session_id: sid)  # called from Learning.auto_introspect
              PWN::AI::Agent::Extrospection.snapshot(sections: %i[web])        # opt-in browser probe of web_anchors
              PWN::AI::Agent::Extrospection.watch(url: 'https://target/api/version')
              PWN::AI::Agent::Extrospection.rf_tune(freq: '101.1')                 # tune GQRX + RDS → now_playing
              PWN::AI::Agent::Extrospection.verify(claim: 'CVE-2026-12345 affects OpenSSL 3.2.1')
              PWN::AI::Agent::Extrospection.revalidate_memory                  # cron: GC stale PWN::Memory :fact entries
              PWN::AI::Agent::Extrospection.reset

              PRIMARY use = on-demand sensing (intel / verify / watch / rf_tune / observe / rf / web).
              auto_extrospect is OPTIONAL ambient baseline (host/repo/env only — never
              launches burpsuite/zaproxy/msfconsole/gqrx). Prefer calling sense tools
              when a question needs the outside world, not after every turn.

              Enable end-of-run ambient baseline with:
                PWN::Env[:ai][:agent][:auto_extrospect] = true   # sections: AUTO_SECTIONS

              Configure browser-backed :web probe / verify / watch with:
                PWN::Env[:ai][:agent][:extrospection][:web] =
                  { anchors: [...], proxy: 'tor', max_anchors: 8, per_page_timeout: 15, screenshot: false, allow_targets: false }

              Configure RF sense (rf_tune) with:
                PWN::Env[:ai][:agent][:extrospection][:rf] =
                  { host: '127.0.0.1', port: 7356, settle_secs: 8, ttl: 300 }

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
