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
        RF_BINS        = %w[rtl_sdr rtl_test rtl_433 hackrf_info gqrx dump1090 multimon-ng SoapySDRUtil].freeze
        OSINT_BINS     = %w[whois dig host curl jq].freeze
        SERIAL_BINS    = %w[minicom picocom screen cu].freeze
        TELECOMM_BINS  = %w[baresip asterisk linphone sngrep].freeze
        PACKET_BINS    = %w[tshark tcpdump tcpreplay dumpcap].freeze
        VISION_BINS    = %w[tesseract zbarimg qrencode convert identify].freeze
        VOICE_BINS     = %w[sox espeak-ng espeak festival whisper spd-say arecord aplay].freeze
        PROBE_BINS = (
          SAFE_VERSION_BINS + PRESENCE_ONLY_BINS + RF_BINS +
          OSINT_BINS + SERIAL_BINS + TELECOMM_BINS + PACKET_BINS +
          VISION_BINS + VOICE_BINS
        ).uniq.freeze
        # Cheap, side-effect-free sections used by auto_extrospect.
        # toolchain / rf / web / osint / serial / telecomm / packet / vision / voice
        # are on-demand only (sense tools or explicit snapshot).
        AUTO_SECTIONS = %i[host repo env].freeze
        WEB_SHOT_DIR = File.join(Dir.home, '.pwn', 'extrospection', 'web')
        DEFAULT_WEB_ANCHORS = %w[
          https://services.nvd.nist.gov/rest/json/cves/2.0
          https://www.exploit-db.com/
          https://raw.githubusercontent.com/0dayinc/pwn/master/lib/pwn/version.rb
        ].freeze
        # Public / free OSINT anchors (no key). Keys unlock richer feeds via PWN::Env.
        DEFAULT_OSINT_FEEDS = %i[
          ip geo dns whois rdap crtsh bgpview shodan hunter
          phone fcc_id patent person username github wayback
          otx urlhaus threatfox urlscan hackertarget openfda
          nominatim opencorporates courtlistener sec_edgar vital_records
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
        #   sections: 'optional - Array subset of [:host, :net, :toolchain, :repo, :env, :rf, :web, :osint, :serial, :telecomm, :packet, :vision, :voice] (default host/net/toolchain/repo/env/rf)'
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
          snap[:osint]     = probe_osint     if sections.include?(:osint)
          snap[:serial]    = probe_serial    if sections.include?(:serial)
          snap[:telecomm]  = probe_telecomm  if sections.include?(:telecomm)
          snap[:packet]    = probe_packet    if sections.include?(:packet)
          snap[:vision]    = probe_vision    if sections.include?(:vision)
          snap[:voice]     = probe_voice     if sections.include?(:voice)
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
        #   category: 'optional - :recon, :vuln, :intel, :target, :network, :env, :rf, :web, :osint, :serial, :telecomm, :packet, :vision, :voice, :misc (default :misc)',
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
              summary = build_rf_summary(payload: payload)
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

        # ============================================================
        # OSINT sense organ
        # ============================================================
        # Supported Method Parameters::
        # result = PWN::AI::Agent::Extrospection.osint(
        #   query:    'required - phone, IP, domain, email, person name, FCC ID, patent #, username, …',
        #   kind:     'optional - auto|:ip|:geo|:dns|:whois|:rdap|:crtsh|:bgp|:shodan|:hunter|:phone|:fcc_id|:patent|:person|:username|:github|:wayback|:url|:company|:cik|:openfda|:vital_records|:threat (default :auto)',
        #   feeds:    'optional - Array subset of DEFAULT_OSINT_FEEDS (default: auto-selected from kind)',
        #   limit:    'optional - max hits per feed (default 5)',
        #   record:   'optional - also observe(category: :osint) (default true)',
        #   ttl:      'optional - observation TTL seconds (default 86400)',
        #   api_keys: 'optional - Hash of {shodan:, hunter:, …} overriding PWN::Env / ENV'
        # )
        #
        # Aggregates as many *public / free* OSINT APIs as possible, with
        # optional keyed feeds (Shodan / Hunter) when keys exist in
        # PWN::Env or ENV. Best-effort: any unreachable feed degrades to
        # an error hash rather than raising. First-class kinds cover:
        # reverse phone, missing-person / person, patent, FCC ID device
        # content, IP/ASN/BGP, CT logs, whois/RDAP, GitHub identity,
        # Wayback, AlienVault OTX, URLHaus / ThreatFox, urlscan.io,
        # HackerTarget, openFDA, Nominatim geocode, OpenCorporates,
        # CourtListener, SEC EDGAR, and vital-records public-search plans.
        public_class_method def self.osint(opts = {})
          query = opts[:query].to_s.strip
          raise 'ERROR: query is required' if query.empty?

          kind   = (opts[:kind] || :auto).to_s.to_sym
          kind   = detect_osint_kind(query: query) if kind == :auto
          feeds  = Array(opts[:feeds]).map(&:to_sym)
          feeds  = osint_feeds_for(kind: kind) if feeds.empty?
          limit  = (opts[:limit] || 5).to_i
          record = opts.key?(:record) ? !opts[:record].nil? && opts[:record] != false : true
          ttl    = (opts[:ttl] || osint_config[:ttl] || 86_400).to_i
          keys   = osint_api_keys(override: opts[:api_keys])

          results = { ok: true, query: query, kind: kind, feeds: {}, captured_at: Time.now.utc.iso8601 }
          feeds.each do |feed|
            results[:feeds][feed] = osint_dispatch(feed: feed, query: query, kind: kind, limit: limit, keys: keys)
          rescue StandardError => e
            results[:feeds][feed] = { error: "#{e.class}: #{e.message.to_s[0, 160]}" }
          end

          results[:summary] = build_osint_summary(results: results)
          if record
            observe(
              source: 'osint',
              category: :osint,
              target: query,
              data: results[:summary],
              tags: (['osint', kind.to_s] + feeds.map(&:to_s)).uniq,
              ttl: ttl
            )
            results[:observed] = true
          else
            results[:observed] = false
          end
          results
        end

        # ============================================================
        # Serial sense organ
        # ============================================================
        # Supported Method Parameters::
        # result = PWN::AI::Agent::Extrospection.serial_sense(
        #   block_dev:  'optional - device path (default first ttyUSB/ttyACM or config)',
        #   baud:       'optional - baud rate (default 9600)',
        #   payload:    'optional - String or byte Array to write (e.g. "ATI\\r" or [0x41,0x54])',
        #   settle_secs:'optional - seconds to read after write (default 1.5)',
        #   data_bits:  'optional (default 8)',
        #   stop_bits:  'optional (default 1)',
        #   parity:     'optional :none|:even|:odd (default :none)',
        #   record:     'optional - observe(category: :serial) (default true)',
        #   ttl:        'optional - observation TTL (default 600)'
        # )
        #
        # Passive inventory via snapshot(sections:[:serial]); this verb is the
        # active serial sense — open a device (PWN::Plugins::Serial), optional
        # payload write, drain response, disconnect. Never keeps the port
        # open across calls so other tools can claim the bus.
        public_class_method def self.serial_sense(opts = {})
          cfg = serial_config
          block_dev = (opts[:block_dev] || cfg[:block_dev] || first_serial_dev).to_s
          baud      = (opts[:baud] || cfg[:baud] || 9600).to_i
          settle    = (opts[:settle_secs] || cfg[:settle_secs] || 1.5).to_f
          settle    = 0.2 if settle < 0.2
          settle    = 30.0 if settle > 30.0
          record    = opts.key?(:record) ? !opts[:record].nil? && opts[:record] != false : true
          ttl       = (opts[:ttl] || cfg[:ttl] || 600).to_i
          payload   = opts[:payload]

          inv = probe_serial
          if block_dev.empty? || !File.exist?(block_dev)
            err = {
              ok: false,
              error: "serial device not found: #{block_dev.inspect}",
              advice: 'Plug a USB-UART / modem / Arduino or pass block_dev: "/dev/ttyUSB0". See probe_serial inventory.',
              inventory: inv
            }
            observe(source: 'serial', category: :serial, target: block_dev, data: err, tags: %w[serial_sense unreachable], ttl: ttl) if record
            return err
          end

          require 'pwn/plugins/serial' unless defined?(PWN::Plugins::Serial)
          serial_obj = nil
          begin
            serial_obj = PWN::Plugins::Serial.connect(
              block_dev: block_dev,
              baud: baud,
              data_bits: (opts[:data_bits] || 8).to_i,
              stop_bits: (opts[:stop_bits] || 1).to_i,
              parity: (opts[:parity] || :none).to_sym
            )
            PWN::Plugins::Serial.flush_session_data
            PWN::Plugins::Serial.request(serial_obj: serial_obj, payload: payload) if payload
            sleep settle
            raw = Array(PWN::Plugins::Serial.dump_session_data)
            text = raw.join.force_encoding('UTF-8').scrub
            hex  = raw.map do |b|
              case b
              when Integer then format('%02x', b & 0xff)
              when String  then b.bytes.map { |x| format('%02x', x) }.join
              else b.to_s.unpack1('H*').to_s
              end
            end.join(' ')
            line = begin
              PWN::Plugins::Serial.get_line_state(serial_obj: serial_obj)
            rescue StandardError
              nil
            end
            modem = begin
              PWN::Plugins::Serial.get_modem_params(serial_obj: serial_obj)
            rescue StandardError
              nil
            end

            payload_out = {
              ok: true,
              block_dev: block_dev,
              baud: baud,
              bytes: raw.length,
              text: text[0, 2_000],
              hex: hex[0, 2_000],
              line_state: line,
              modem_params: modem,
              inventory: inv,
              captured_at: Time.now.utc.iso8601
            }
            if record
              summary = "serial #{block_dev}@#{baud} bytes=#{raw.length} text=#{text.to_s.gsub(/\s+/, ' ')[0, 120]}"
              observe(source: 'serial', category: :serial, target: block_dev, data: summary, tags: %w[serial_sense], ttl: ttl)
              payload_out[:observed] = true
              payload_out[:summary] = summary
            end
            payload_out
          rescue StandardError => e
            {
              ok: false,
              error: "#{e.class}: #{e.message}",
              block_dev: block_dev,
              advice: 'Confirm device path, permissions (dialout group), and that no minicom/screen is holding the port.'
            }
          ensure
            begin
              PWN::Plugins::Serial.disconnect(serial_obj: serial_obj) if serial_obj
            rescue StandardError
              nil
            end
          end
        end

        # ============================================================
        # Telecomm sense organ (SIP / VoIP / PSTN via BareSIP)
        # ============================================================
        # Supported Method Parameters::
        # result = PWN::AI::Agent::Extrospection.telecomm(
        #   action:  'optional - :status|:dial|:hangup|:inventory (default :inventory)',
        #   target:  'optional - SIP URI / phone number for :dial (e.g. "sip:alice@example.com" or "+13125551212")',
        #   host:    'optional - BareSIP HTTP control host (default 127.0.0.1)',
        #   port:    'optional - BareSIP HTTP control port (default 8000)',
        #   record:  'optional - observe(category: :telecomm) (default true)',
        #   ttl:     'optional - observation TTL (default 600)'
        # )
        #
        # Telecomm analogue of rf_tune — senses live SIP / VoIP / PSTN state
        # through a *running* BareSIP instance (never launches it). Status
        # and inventory always; dial/hangup are explicit and OPSEC-sensitive.
        public_class_method def self.telecomm(opts = {})
          action = (opts[:action] || :inventory).to_s.to_sym
          host   = (opts[:host] || telecomm_config[:host] || '127.0.0.1').to_s
          port   = (opts[:port] || telecomm_config[:port] || 8000).to_i
          record = opts.key?(:record) ? !opts[:record].nil? && opts[:record] != false : true
          ttl    = (opts[:ttl] || telecomm_config[:ttl] || 600).to_i
          target = opts[:target].to_s.strip

          inv = probe_telecomm
          http_up = tcp_open?(host: host, port: port)

          out = {
            ok: true,
            action: action,
            host: host,
            port: port,
            baresip_http: http_up,
            inventory: inv,
            captured_at: Time.now.utc.iso8601
          }

          case action
          when :inventory, :status
            out[:status] = telecomm_baresip_cmd(host: host, port: port, cmd: '/?') if http_up
            out[:status] ||= inv
          when :dial
            if target.empty?
              out[:ok] = false
              out[:error] = 'target is required for action: :dial'
              out[:advice] = 'Pass target: "sip:user@host" or E.164 phone number.'
            elsif !http_up
              out[:ok] = false
              out[:error] = "baresip HTTP control not reachable at #{host}:#{port}"
              out[:advice] = 'Start baresip with HTTP module enabled (or PWN::Plugins::BareSIP.start) then retry.'
            else
              out[:dial] = telecomm_baresip_cmd(host: host, port: port, cmd: "/?dial=#{URI.encode_www_form_component(target)}")
            end
          when :hangup
            if http_up
              out[:hangup] = telecomm_baresip_cmd(host: host, port: port, cmd: '/?hangup')
            else
              out[:ok] = false
              out[:error] = "baresip HTTP control not reachable at #{host}:#{port}"
            end
          else
            out[:ok] = false
            out[:error] = "unsupported action: #{action}"
            out[:advice] = 'Use :inventory, :status, :dial, or :hangup.'
          end

          if record
            summary = "telecomm action=#{action} baresip_http=#{http_up} target=#{target.empty? ? '-' : target}"
            observe(source: 'telecomm', category: :telecomm, target: (target.empty? ? "#{host}:#{port}" : target), data: summary, tags: ['telecomm', action.to_s], ttl: ttl)
            out[:observed] = true
            out[:summary] = summary
          end
          out
        end

        # ============================================================
        # Packet sense organ
        # ============================================================
        # Supported Method Parameters::
        # result = PWN::AI::Agent::Extrospection.packet_sense(
        #   action:   'optional - :inventory|:capture|:summarize_pcap (default :inventory)',
        #   iface:    'optional - capture interface (default first non-lo or "any")',
        #   filter:   'optional - BPF filter (e.g. "tcp port 443")',
        #   count:    'optional - packets to capture (default 20, max 200)',
        #   timeout:  'optional - capture seconds (default 5, max 60)',
        #   path:     'optional - pcap path for :summarize_pcap',
        #   record:   'optional - observe(category: :packet) (default true)',
        #   ttl:      'optional - observation TTL (default 600)'
        # )
        #
        # Passive L2/L3 sense via tshark/tcpdump when present; pcap
        # summarisation via PWN::Plugins::Packet + tshark. Capture is short
        # and bounded so the agent never hangs mid-turn.
        public_class_method def self.packet_sense(opts = {})
          action  = (opts[:action] || :inventory).to_s.to_sym
          record  = opts.key?(:record) ? !opts[:record].nil? && opts[:record] != false : true
          ttl     = (opts[:ttl] || packet_config[:ttl] || 600).to_i
          iface   = (opts[:iface] || packet_config[:iface] || default_capture_iface).to_s
          filter  = opts[:filter].to_s
          count   = (opts[:count] || 20).to_i.clamp(1, 200)
          timeout = (opts[:timeout] || 5).to_i.clamp(1, 60)
          path    = opts[:path].to_s

          inv = probe_packet
          out = {
            ok: true,
            action: action,
            iface: iface,
            inventory: inv,
            captured_at: Time.now.utc.iso8601
          }

          case action
          when :inventory
            out[:ifaces] = inv[:ifaces]
            out[:bins]   = inv[:bins]
          when :capture
            tshark = sh(cmd: 'which tshark 2>/dev/null')
            tcpdump = sh(cmd: 'which tcpdump 2>/dev/null')
            if tshark.empty? && tcpdump.empty?
              out[:ok] = false
              out[:error] = 'neither tshark nor tcpdump found in PATH'
              out[:advice] = 'Install wireshark-common / tcpdump, or summarize an existing pcap with action: :summarize_pcap path:.'
            else
              pcap_out = File.join(Dir.home, '.pwn', 'extrospection', 'packet', "cap_#{Time.now.utc.strftime('%Y%m%d_%H%M%S')}.pcap")
              FileUtils.mkdir_p(File.dirname(pcap_out))
              if tshark.empty?
                bpf = filter.empty? ? '' : filter
                cmd = "timeout #{timeout + 2} tcpdump -i #{Shellwords.escape(iface)} -c #{count} -w #{Shellwords.escape(pcap_out)} #{Shellwords.escape(bpf)} 2>&1"
              else
                bpf = filter.empty? ? '' : "-f #{Shellwords.escape(filter)}"
                cmd = "timeout #{timeout + 2} tshark -i #{Shellwords.escape(iface)} -c #{count} -a duration:#{timeout} -w #{Shellwords.escape(pcap_out)} #{bpf} 2>&1"
              end
              log = sh(cmd: cmd)
              out[:pcap] = File.exist?(pcap_out) ? pcap_out : nil
              out[:log] = log.to_s[0, 500]
              out[:summary] = summarize_pcap_file(path: pcap_out) if out[:pcap]
              out[:ok] = !out[:pcap].nil?
              out[:error] = 'capture produced no pcap' unless out[:ok]
            end
          when :summarize_pcap
            if path.empty? || !File.exist?(path)
              out[:ok] = false
              out[:error] = "pcap not found: #{path.inspect}"
            else
              out[:path] = path
              out[:summary] = summarize_pcap_file(path: path)
            end
          else
            out[:ok] = false
            out[:error] = "unsupported action: #{action}"
          end

          if record
            blob = out[:summary].is_a?(Hash) ? out[:summary].to_json[0, 300] : out[:summary].to_s[0, 200]
            summary = "packet action=#{action} iface=#{iface} #{blob}"
            observe(source: 'packet', category: :packet, target: iface, data: summary, tags: ['packet', action.to_s], ttl: ttl)
            out[:observed] = true
            out[:obs_summary] = summary
          end
          out
        end

        # ============================================================
        # Vision / OCR sense organ
        # ============================================================
        # Supported Method Parameters::
        # result = PWN::AI::Agent::Extrospection.vision(
        #   file:      'required - path to image / screenshot / PDF-page render',
        #   action:    'optional - :ocr|:barcode|:inventory (default :ocr when file given, else :inventory)',
        #   lang:      'optional - tesseract language (default eng)',
        #   record:    'optional - observe(category: :vision) (default true)',
        #   ttl:       'optional - observation TTL (default 86400)'
        # )
        #
        # Eyes on the host: OCR via PWN::Plugins::OCR (RTesseract / tesseract)
        # and barcode/QR decode via zbarimg when present. Inventory only when
        # no file is supplied.
        public_class_method def self.vision(opts = {})
          file   = opts[:file].to_s.strip
          action = (opts[:action] || (file.empty? ? :inventory : :ocr)).to_s.to_sym
          record = opts.key?(:record) ? !opts[:record].nil? && opts[:record] != false : true
          ttl    = (opts[:ttl] || vision_config[:ttl] || 86_400).to_i
          lang   = (opts[:lang] || vision_config[:lang] || 'eng').to_s

          inv = probe_vision
          out = {
            ok: true,
            action: action,
            inventory: inv,
            captured_at: Time.now.utc.iso8601
          }

          case action
          when :inventory
            # nothing else
          when :ocr
            if file.empty? || !File.exist?(file)
              out[:ok] = false
              out[:error] = "image not found: #{file.inspect}"
              out[:advice] = 'Pass file: "/path/to/image.png" (png/jpg/tiff/webp).'
            elsif inv.dig(:bins, :tesseract).to_s.empty? && !defined?(RTesseract)
              out[:ok] = false
              out[:error] = 'tesseract / rtesseract unavailable'
              out[:advice] = 'Install tesseract-ocr (+ eng language data) or the rtesseract gem.'
            else
              text = vision_ocr(file: file, lang: lang)
              out[:file] = file
              out[:text] = text.to_s[0, 8_000]
              out[:chars] = text.to_s.length
              out[:preview] = text.to_s.gsub(/\s+/, ' ')[0, 200]
            end
          when :barcode
            if file.empty? || !File.exist?(file)
              out[:ok] = false
              out[:error] = "image not found: #{file.inspect}"
            else
              codes = vision_barcodes(file: file)
              out[:file] = file
              out[:codes] = codes
            end
          else
            out[:ok] = false
            out[:error] = "unsupported action: #{action}"
          end

          if record
            summary = if out[:preview]
                        "vision ocr file=#{File.basename(file)} chars=#{out[:chars]} preview=#{out[:preview]}"
                      elsif out[:codes]
                        "vision barcode file=#{File.basename(file)} codes=#{Array(out[:codes]).length}"
                      else
                        "vision action=#{action} tesseract=#{!inv.dig(:bins, :tesseract).to_s.empty?}"
                      end
            observe(source: 'vision', category: :vision, target: (file.empty? ? 'inventory' : file), data: summary, tags: ['vision', action.to_s], ttl: ttl)
            out[:observed] = true
            out[:summary] = summary
          end
          out
        end

        # ============================================================
        # Voice sense organ (TTS / STT / inventory)
        # ============================================================
        # Supported Method Parameters::
        # result = PWN::AI::Agent::Extrospection.voice_sense(
        #   action:    'optional - :inventory|:tts|:stt (default :inventory)',
        #   text:      'optional - text to speak for :tts (or text_path:)',
        #   text_path: 'optional - path to text file for :tts',
        #   audio:     'optional - path to audio file for :stt',
        #   out:       'optional - output audio path for :tts (wav)',
        #   engine:    'optional - :espeak|:festival|:spd_say|:whisper (auto)',
        #   model:     'optional - whisper model (default tiny)',
        #   record:    'optional - observe(category: :voice) (default true)',
        #   ttl:       'optional - observation TTL (default 3600)'
        # )
        #
        # Wraps PWN::Plugins::Voice + system TTS/STT binaries (espeak-ng,
        # festival, spd-say, whisper, sox). Inventory is always free;
        # TTS/STT are on-demand and persist optional artefacts under
        # ~/.pwn/extrospection/voice/.
        public_class_method def self.voice_sense(opts = {})
          action = (opts[:action] || :inventory).to_s.to_sym
          record = opts.key?(:record) ? !opts[:record].nil? && opts[:record] != false : true
          ttl    = (opts[:ttl] || voice_config[:ttl] || 3_600).to_i
          inv    = probe_voice

          out = {
            ok: true,
            action: action,
            inventory: inv,
            captured_at: Time.now.utc.iso8601
          }

          case action
          when :inventory
            # nothing else
          when :tts
            text = opts[:text].to_s
            if text.empty? && opts[:text_path]
              text = begin
                File.read(opts[:text_path].to_s)
              rescue StandardError
                ''
              end
            end
            if text.strip.empty?
              out[:ok] = false
              out[:error] = 'text or text_path is required for action: :tts'
            else
              engine = (opts[:engine] || pick_tts_engine(inv: inv)).to_s.to_sym
              art = File.join(Dir.home, '.pwn', 'extrospection', 'voice')
              FileUtils.mkdir_p(art)
              wav = (opts[:out] || File.join(art, "tts_#{Time.now.utc.strftime('%Y%m%d_%H%M%S')}.wav")).to_s
              ok, log = voice_tts(text: text, engine: engine, out: wav, inv: inv)
              out[:engine] = engine
              out[:audio] = File.exist?(wav) ? wav : nil
              out[:log] = log.to_s[0, 400]
              out[:chars] = text.length
              out[:ok] = ok
              out[:error] = 'TTS engine failed' unless ok
            end
          when :stt
            audio = opts[:audio].to_s
            if audio.empty? || !File.exist?(audio)
              out[:ok] = false
              out[:error] = "audio not found: #{audio.inspect}"
              out[:advice] = 'Pass audio: "/path/to/recording.wav". Requires whisper binary or plugin path.'
            else
              engine = (opts[:engine] || pick_stt_engine(inv: inv)).to_s.to_sym
              text, log = voice_stt(audio: audio, engine: engine, model: opts[:model] || 'tiny', inv: inv)
              out[:engine] = engine
              out[:audio] = audio
              out[:text] = text.to_s[0, 8_000]
              out[:log] = log.to_s[0, 400]
              out[:ok] = !text.to_s.strip.empty?
              out[:error] = 'STT produced empty transcript' unless out[:ok]
            end
          else
            out[:ok] = false
            out[:error] = "unsupported action: #{action}"
          end

          if record
            summary = case action
                      when :tts then "voice tts engine=#{out[:engine]} chars=#{out[:chars]} audio=#{out[:audio]}"
                      when :stt then "voice stt engine=#{out[:engine]} text=#{out[:text].to_s.gsub(/\s+/, ' ')[0, 120]}"
                      else "voice inventory espeak=#{!inv.dig(:bins, :'espeak-ng').to_s.empty? && inv.dig(:bins, :'espeak-ng') != ''} sox=#{!inv.dig(:bins, :sox).to_s.empty?}"
                      end
            observe(source: 'voice', category: :voice, target: action.to_s, data: summary, tags: ['voice', action.to_s], ttl: ttl)
            out[:observed] = true
            out[:summary] = summary
          end
          out
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
            web_anchors: (snap[:web] || {}).count { |_, v| v.is_a?(Hash) && v[:reachable] },
            serial_devs: Array((snap[:serial] || {})[:devices]).length,
            packet_bins: ((snap[:packet] || {})[:bins] || {}).count { |_, v| !v.to_s.empty? },
            vision_bins: ((snap[:vision] || {})[:bins] || {}).count { |_, v| !v.to_s.empty? },
            voice_bins: ((snap[:voice] || {})[:bins] || {}).count { |_, v| !v.to_s.empty? },
            telecomm_http: (snap[:telecomm] || {})[:baresip_http] ? true : false,
            osint_feeds: Array((snap[:osint] || {})[:feeds_available]).length
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
            elsif presence_only_bin?(name: b)
              h[b.to_sym] = path
            else
              ver = sh(cmd: "timeout 2 #{Shellwords.escape(b)} --version 2>/dev/null").lines.first.to_s.strip[0, 80]
              h[b.to_sym] = "#{path} #{ver}".strip
            end
          end
        end

        private_class_method def self.presence_only_bin?(opts = {})
          n = opts[:name].to_s
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

        private_class_method def self.build_rf_summary(opts = {})
          payload = opts[:payload] || {}
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

        # ── OSINT / Serial / Telecomm / Packet / Vision / Voice probes ──

        private_class_method def self.probe_osint
          keys = osint_api_keys
          {
            feeds_available: DEFAULT_OSINT_FEEDS.map(&:to_s),
            keyed: {
              shodan: !keys[:shodan].to_s.empty?,
              hunter: !keys[:hunter].to_s.empty?
            },
            bins: presence_map(bins: OSINT_BINS),
            endpoints: {
              ip_api: 'http://ip-api.com/json/',
              ipwhois: 'https://ipwho.is/',
              rdap: 'https://rdap.org/',
              crtsh: 'https://crt.sh/',
              bgpview: 'https://api.bgpview.io/',
              fcc_device: 'https://device.report/fcc/',
              fcc_api: 'https://data.fcc.gov/api/',
              patents_google: 'https://patents.google.com/',
              patentsview: 'https://api.patentsview.org/',
              openfda: 'https://api.fda.gov/',
              nominatim: 'https://nominatim.openstreetmap.org/',
              wayback: 'https://archive.org/wayback/available',
              github: 'https://api.github.com/',
              dns_google: 'https://dns.google/resolve',
              otx: 'https://otx.alienvault.com/api/v1/',
              urlhaus: 'https://urlhaus-api.abuse.ch/v1/',
              threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
              urlscan: 'https://urlscan.io/api/v1/search/',
              hackertarget: 'https://api.hackertarget.com/',
              opencorporates: 'https://api.opencorporates.com/v0.4/',
              courtlistener: 'https://www.courtlistener.com/api/rest/v4/',
              sec_edgar: 'https://efts.sec.gov/LATEST/search-index',
              opensanctions: 'https://api.opensanctions.org/',
              wikidata: 'https://www.wikidata.org/w/api.php',
              wikipedia: 'https://en.wikipedia.org/w/api.php',
              namus: 'https://www.namus.gov/Search',
              charley: 'https://charleyproject.org/',
              fbi_kidnap: 'https://www.fbi.gov/wanted/kidnap',
              vital_cdc: 'https://www.cdc.gov/nchs/nvss/index.htm',
              vital_familysearch: 'https://www.familysearch.org/en/search/'
            }
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.probe_serial
          by_id = Dir.glob('/dev/serial/by-id/*').map do |p|
            { path: p, target: begin
              File.readlink(p)
            rescue StandardError
              p
            end }
          end
          devs = Dir.glob('/dev/{ttyUSB,ttyACM,ttyS,ttyAMA}*')
          {
            devices: devs,
            by_id: by_id.first(20),
            bins: presence_map(bins: SERIAL_BINS),
            default: first_serial_dev
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.probe_telecomm
          host = telecomm_config[:host] || '127.0.0.1'
          port = (telecomm_config[:port] || 8000).to_i
          {
            bins: presence_map(bins: TELECOMM_BINS),
            baresip_http: tcp_open?(host: host, port: port),
            baresip_host: host,
            baresip_port: port,
            baresip_home: Dir.exist?(File.join(Dir.home, '.baresip')),
            sip_ports_listening: begin
              sh(cmd: "ss -tulnH 2>/dev/null | awk '{print $5}'").lines.map(&:strip).grep(/:(5060|5061|5080|8000)\b/).uniq
            rescue StandardError
              []
            end
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.probe_packet
          ifaces = begin
            sh(cmd: "ip -o link show 2>/dev/null | awk -F': ' '{print $2}'").lines.map { |l| l.strip.split('@').first }.reject { |i| i == 'lo' || i.empty? }
          rescue StandardError
            []
          end
          {
            bins: presence_map(bins: PACKET_BINS),
            ifaces: ifaces,
            default_iface: default_capture_iface,
            cap_dir: File.join(Dir.home, '.pwn', 'extrospection', 'packet')
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.probe_vision
          {
            bins: presence_map(bins: VISION_BINS),
            tesseract_langs: begin
              raw = sh(cmd: 'tesseract --list-langs 2>&1')
              raw.lines.drop(1).map(&:strip).reject(&:empty?).first(20)
            rescue StandardError
              []
            end,
            plugin_ocr: defined?(PWN::Plugins::OCR) || File.exist?(File.join(defined?(PWN::ROOT) ? PWN::ROOT.to_s : '/opt/pwn', 'lib/pwn/plugins/ocr.rb')),
            plugin_scannable: defined?(PWN::Plugins::ScannableCodes) || true
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.probe_voice
          {
            bins: presence_map(bins: VOICE_BINS),
            plugin_voice: true,
            art_dir: File.join(Dir.home, '.pwn', 'extrospection', 'voice')
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.presence_map(opts = {})
          Array(opts[:bins]).each_with_object({}) do |b, h|
            path = sh(cmd: "which #{Shellwords.escape(b)} 2>/dev/null").split("\n").first.to_s.strip
            h[b.to_sym] = path
          end
        end

        private_class_method def self.first_serial_dev
          (Dir.glob('/dev/ttyUSB*') + Dir.glob('/dev/ttyACM*')).min.to_s
        end

        private_class_method def self.default_capture_iface
          ifaces = begin
            sh(cmd: "ip -o link show 2>/dev/null | awk -F': ' '{print $2}'").lines.map { |l| l.strip.split('@').first }.reject { |i| i == 'lo' || i.empty? }
          rescue StandardError
            []
          end
          ifaces.first || 'any'
        end

        # ── limb configs ────────────────────────────────────────────

        private_class_method def self.osint_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :osint) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          { ttl: (cfg[:ttl] || 86_400).to_i, proxy: cfg[:proxy] }
        rescue StandardError
          { ttl: 86_400, proxy: nil }
        end

        private_class_method def self.serial_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :serial) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          { block_dev: cfg[:block_dev], baud: (cfg[:baud] || 9600).to_i, settle_secs: (cfg[:settle_secs] || 1.5).to_f, ttl: (cfg[:ttl] || 600).to_i }
        rescue StandardError
          { block_dev: nil, baud: 9600, settle_secs: 1.5, ttl: 600 }
        end

        private_class_method def self.telecomm_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :telecomm) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          { host: cfg[:host] || '127.0.0.1', port: (cfg[:port] || 8000).to_i, ttl: (cfg[:ttl] || 600).to_i }
        rescue StandardError
          { host: '127.0.0.1', port: 8000, ttl: 600 }
        end

        private_class_method def self.packet_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :packet) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          { iface: cfg[:iface], ttl: (cfg[:ttl] || 600).to_i }
        rescue StandardError
          { iface: nil, ttl: 600 }
        end

        private_class_method def self.vision_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :vision) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          { lang: cfg[:lang] || 'eng', ttl: (cfg[:ttl] || 86_400).to_i }
        rescue StandardError
          { lang: 'eng', ttl: 86_400 }
        end

        private_class_method def self.voice_config
          cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :voice) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          { ttl: (cfg[:ttl] || 3_600).to_i }
        rescue StandardError
          { ttl: 3_600 }
        end

        # ── OSINT helpers ───────────────────────────────────────────

        private_class_method def self.osint_api_keys(opts = {})
          ov = opts[:override] || {}
          env_cfg = (PWN::Env.dig(:ai, :agent, :extrospection, :osint, :api_keys) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          pwn_cfg = (PWN::Env[:shodan] if defined?(PWN::Env) && PWN::Env.is_a?(Hash)) || {}
          {
            shodan: (ov[:shodan] || env_cfg[:shodan] || pwn_cfg[:api_key] || ENV['SHODAN_API_KEY'] || ENV.fetch('PWN_SHODAN_API_KEY', nil)).to_s,
            hunter: (ov[:hunter] || env_cfg[:hunter] || ENV['HUNTER_API_KEY'] || ENV.fetch('PWN_HUNTER_API_KEY', nil)).to_s
          }
        rescue StandardError
          { shodan: ENV['SHODAN_API_KEY'].to_s, hunter: ENV['HUNTER_API_KEY'].to_s }
        end

        private_class_method def self.detect_osint_kind(opts = {})
          q = opts[:query].to_s.strip
          # Order matters: IPs must beat the phone heuristic (dots are valid phone punctuation).
          return :ip       if q.match?(/\A\d{1,3}(?:\.\d{1,3}){3}\z/)
          return :ip       if q.include?(':') && q.match?(/\A[0-9a-f:.]+\z/i) # IPv6-ish
          return :email    if q.include?('@') && q.include?('.')
          return :url      if q.match?(%r{\Ahttps?://}i)
          return :domain   if q.match?(/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\z/i) && !q.include?(' ')
          return :github   if q.start_with?('github.com/', 'gh:')
          return :patent   if q.match?(/\A(?:US|EP|WO|CN|JP)\s?\d{5,}[A-Z]?\d?\z/i) || q.match?(/\Apatent\b/i)
          return :cik      if q.match?(/\A(?:CIK)?\s?\d{10}\z/i)
          return :phone    if q.match?(/\A\+\d[\d\-\s().]{6,}\z/) || q.match?(/\A\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}\z/) || q.match?(/\A\d{10,15}\z/)
          # FCC ID: grantee (3+) + optional hyphen + product code; require a letter and a digit.
          return :fcc_id   if q.match?(/\A[A-Z0-9]{3,5}-[A-Z0-9]{1,14}\z/i) || (q.match?(/\A[A-Z0-9]{5,14}\z/i) && q.match?(/[A-Za-z]/) && q.match?(/\d/) && !q.match?(/\A(?:US|EP|WO)\d/i))
          # Geocode-looking free-text address (number + street token)
          return :geo      if q.match?(/\A\d{1,6}\s+[A-Za-z]/) && q.match?(/\b(?:st|street|ave|avenue|rd|road|blvd|ln|lane|dr|drive|ct|court|way|hwy|highway)\b/i)
          return :company  if q.match?(/\b(?:inc\.?|llc|ltd\.?|corp\.?|corporation|company|co\.|plc|gmbh|s\.a\.|s\.l\.)\b/i)
          # Vital-record keywords before free-text person name (order matters).
          return :vital_records if q.match?(/\b(?:birth|death|marriage|divorce|vital)\b/i)
          return :username if q.match?(/\A@?[A-Za-z0-9_\-.]{2,32}\z/) && !q.include?(' ')
          return :person   if q.match?(/\A[A-Za-z]+(?:\s+[A-Za-z.'-]+)+\z/)

          :person
        end

        private_class_method def self.osint_feeds_for(opts = {})
          case opts[:kind].to_sym
          when :ip then %i[ip geo dns rdap bgpview otx shodan hackertarget]
          when :geo then %i[geo nominatim ip]
          when :domain, :dns, :whois, :rdap then %i[dns whois rdap crtsh wayback otx urlhaus urlscan shodan hackertarget]
          when :url then %i[urlscan otx urlhaus wayback]
          when :email then %i[hunter person github]
          when :phone then %i[phone person]
          when :fcc_id then %i[fcc_id]
          when :patent then %i[patent]
          when :person then %i[person username github open_sanctions vital_records]
          when :username, :github then %i[username github]
          when :company then %i[opencorporates sec_edgar person courtlistener]
          when :cik then %i[sec_edgar opencorporates]
          when :wayback then %i[wayback]
          when :crtsh then %i[crtsh]
          when :bgp, :bgpview then %i[bgpview]
          when :shodan then %i[shodan]
          when :hunter then %i[hunter]
          when :openfda then %i[openfda]
          when :vital_records then %i[vital_records person]
          when :threat then %i[otx urlhaus threatfox]
          else DEFAULT_OSINT_FEEDS.first(8)
          end
        end

        private_class_method def self.osint_dispatch(opts = {})
          feed  = opts[:feed].to_sym
          query = opts[:query].to_s
          limit = opts[:limit] || 5
          keys  = opts[:keys] || {}
          case feed
          when :ip, :geo then osint_ip_geo(query: query)
          when :dns then osint_dns(query: query)
          when :whois then osint_whois(query: query)
          when :rdap then osint_rdap(query: query)
          when :crtsh then osint_crtsh(query: query, limit: limit)
          when :bgpview, :bgp then osint_bgpview(query: query)
          when :shodan then osint_shodan(query: query, api_key: keys[:shodan], limit: limit)
          when :hunter then osint_hunter(query: query, api_key: keys[:hunter], limit: limit)
          when :phone then osint_phone(query: query)
          when :fcc_id then osint_fcc_id(query: query)
          when :patent then osint_patent(query: query, limit: limit)
          when :person, :open_sanctions then osint_person(query: query, limit: limit)
          when :username then osint_username(query: query)
          when :github then osint_github(query: query)
          when :wayback then osint_wayback(query: query)
          when :otx then osint_otx(query: query)
          when :urlhaus then osint_urlhaus(query: query)
          when :threatfox then osint_threatfox(query: query)
          when :urlscan then osint_urlscan(query: query, limit: limit)
          when :hackertarget then osint_hackertarget(query: query)
          when :openfda then osint_openfda(query: query, limit: limit)
          when :nominatim then osint_nominatim(query: query, limit: limit)
          when :opencorporates then osint_opencorporates(query: query, limit: limit)
          when :courtlistener then osint_courtlistener(query: query, limit: limit)
          when :sec_edgar then osint_sec_edgar(query: query, limit: limit)
          when :vital_records then osint_vital_records(query: query)
          else { error: "unknown feed: #{feed}" }
          end
        end

        private_class_method def self.osint_ip_geo(opts = {})
          q = opts[:query].to_s
          # Prefer existing PWN plugin when query is an IP/host.
          if defined?(PWN::Plugins::IPInfo) || true
            begin
              require 'pwn/plugins/ip_info' unless defined?(PWN::Plugins::IPInfo)
              res = PWN::Plugins::IPInfo.get(target: q, skip_api: false)
              return { source: 'ip-api.com+plugin', data: res }
            rescue StandardError => e
              # fall through to raw REST
              _ = e
            end
          end
          body = http_get_json(url: "http://ip-api.com/json/#{URI.encode_www_form_component(q)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,query")
          { source: 'ip-api.com', data: body }
        end

        private_class_method def self.osint_dns(opts = {})
          q = opts[:query].to_s
          local = {
            a: sh(cmd: "dig +short A #{Shellwords.escape(q)} 2>/dev/null").lines.map(&:strip).reject(&:empty?).first(10),
            aaaa: sh(cmd: "dig +short AAAA #{Shellwords.escape(q)} 2>/dev/null").lines.map(&:strip).reject(&:empty?).first(10),
            mx: sh(cmd: "dig +short MX #{Shellwords.escape(q)} 2>/dev/null").lines.map(&:strip).reject(&:empty?).first(10),
            ns: sh(cmd: "dig +short NS #{Shellwords.escape(q)} 2>/dev/null").lines.map(&:strip).reject(&:empty?).first(10),
            txt: sh(cmd: "dig +short TXT #{Shellwords.escape(q)} 2>/dev/null").lines.map(&:strip).reject(&:empty?).first(10)
          }
          doh = http_get_json(url: "https://dns.google/resolve?name=#{URI.encode_www_form_component(q)}&type=A")
          { source: 'dig+dns.google', local: local, doh: doh }
        end

        private_class_method def self.osint_whois(opts = {})
          q = opts[:query].to_s
          raw = sh(cmd: "timeout 8 whois #{Shellwords.escape(q)} 2>/dev/null")
          { source: 'whois', data: raw.to_s[0, 4_000] }
        end

        private_class_method def self.osint_rdap(opts = {})
          q = opts[:query].to_s
          # Try domain then IP RDAP bootstrap via rdap.org
          body = http_get_json(url: "https://rdap.org/domain/#{URI.encode_www_form_component(q)}")
          body ||= http_get_json(url: "https://rdap.org/ip/#{URI.encode_www_form_component(q)}")
          { source: 'rdap.org', data: body }
        end

        private_class_method def self.osint_crtsh(opts = {})
          q = opts[:query].to_s
          limit = opts[:limit] || 5
          # crt.sh returns JSON array
          require 'rest-client'
          resp = RestClient::Request.execute(
            method: :get,
            url: "https://crt.sh/?q=#{URI.encode_www_form_component(q)}&output=json",
            timeout: 12,
            open_timeout: 5,
            headers: { accept: :json, user_agent: 'pwn-ai-extrospection' }
          )
          rows = JSON.parse(resp.body, symbolize_names: true)
          hits = Array(rows).first(limit).map do |r|
            { id: r[:id], logged_at: r[:entry_timestamp], not_before: r[:not_before], not_after: r[:not_after], name: r[:name_value].to_s[0, 200], issuer: r[:issuer_name].to_s[0, 120] }
          end
          { source: 'crt.sh', total_hint: Array(rows).length, hits: hits }
        rescue StandardError => e
          { source: 'crt.sh', error: "#{e.class}: #{e.message.to_s[0, 120]}" }
        end

        private_class_method def self.osint_bgpview(opts = {})
          q = opts[:query].to_s
          if q.match?(/\A\d{1,3}(?:\.\d{1,3}){3}\z/)
            body = http_get_json(url: "https://api.bgpview.io/ip/#{q}")
          elsif q.match?(/\AAS?\d+\z/i)
            asn = q.gsub(/[^0-9]/, '')
            body = http_get_json(url: "https://api.bgpview.io/asn/#{asn}")
          else
            body = http_get_json(url: "https://api.bgpview.io/search?query_term=#{URI.encode_www_form_component(q)}")
          end
          { source: 'bgpview.io', data: body }
        end

        private_class_method def self.osint_shodan(opts = {})
          key = opts[:api_key].to_s
          return { source: 'shodan', skipped: true, reason: 'no API key (set SHODAN_API_KEY or PWN::Env)' } if key.empty?

          require 'pwn/plugins/shodan' unless defined?(PWN::Plugins::Shodan)
          res = PWN::Plugins::Shodan.search(api_key: key, query: opts[:query].to_s)
          # trim
          if res.is_a?(Hash)
            matches = Array(res[:matches] || res['matches']).first(opts[:limit] || 5)
            { source: 'shodan', total: res[:total] || res['total'], matches: matches }
          else
            { source: 'shodan', data: res }
          end
        rescue StandardError => e
          { source: 'shodan', error: "#{e.class}: #{e.message.to_s[0, 120]}" }
        end

        private_class_method def self.osint_hunter(opts = {})
          key = opts[:api_key].to_s
          return { source: 'hunter.how', skipped: true, reason: 'no API key (set HUNTER_API_KEY)' } if key.empty?

          require 'pwn/plugins/hunter' unless defined?(PWN::Plugins::Hunter)
          end_time = Time.now.utc.strftime('%Y-%m-%d')
          start_time = (Time.now.utc - (30 * 24 * 3600)).strftime('%Y-%m-%d')
          res = PWN::Plugins::Hunter.search(api_key: key, query: opts[:query].to_s, start_time: start_time, end_time: end_time, page_size: opts[:limit] || 5)
          { source: 'hunter.how', data: res }
        rescue StandardError => e
          { source: 'hunter.how', error: "#{e.class}: #{e.message.to_s[0, 120]}" }
        end

        private_class_method def self.osint_phone(opts = {})
          q = opts[:query].to_s.gsub(/[^\d+]/, '')
          # Free public heuristics + libphonenumber-less metadata. Prefer NumVerify if key present later.
          digits = q.gsub(/\D/, '')
          country = case digits
                    when /\A1\d{10}\z/ then 'US/CA (NANP)'
                    when /\A44\d+/ then 'UK'
                    when /\A33\d+/ then 'FR'
                    when /\A49\d+/ then 'DE'
                    when /\A81\d+/ then 'JP'
                    when /\A86\d+/ then 'CN'
                    when /\A61\d+/ then 'AU'
                    when /\A91\d+/ then 'IN'
                    else 'unknown'
                    end
          nanp = nil
          if digits.match?(/\A1?(\d{3})(\d{3})(\d{4})\z/)
            area = Regexp.last_match(1)
            # Area-code → region via public NPA style (best-effort subset)
            nanp = { area_code: area, nxx: Regexp.last_match(2), station: Regexp.last_match(3) }
          end
          # OpenCNAM-style public CNAM is largely paywalled; expose format + link targets for deeper manual/keyed lookup.
          {
            source: 'phone-heuristic',
            e164_guess: (q.start_with?('+') ? q : "+#{digits}"),
            digits: digits,
            country_guess: country,
            nanp: nanp,
            reverse_lookup_targets: [
              "https://www.truepeoplesearch.com/results?phoneno=#{digits}",
              "https://www.whitepages.com/phone/#{digits}",
              "https://www.fastpeoplesearch.com/#{digits.chars.each_slice(3).map(&:join).join('-')}"
            ],
            note: 'Public reverse-phone APIs are largely paywalled; heuristic metadata + OSINT search targets returned. Set a CNAM/NumVerify key in PWN::Env for live CNAM.'
          }
        end

        private_class_method def self.osint_fcc_id(opts = {})
          q = opts[:query].to_s.strip.upcase.gsub(/\s+/, '')
          grantee = q[0, 3]
          product = q.sub(/\A[A-Z0-9]{3}-?/i, '')
          pages = []
          # Prefer headless/TB where available for bot-walled aggregators; fall back to REST.
          candidates = [
            "https://fccid.io/#{URI.encode_www_form_component(q)}",
            "https://device.report/fcc/#{URI.encode_www_form_component(q)}",
            "https://www.fcc.gov/oet/ea/fccid?grantee_code=#{URI.encode_www_form_component(grantee)}&product_code=#{URI.encode_www_form_component(product)}"
          ]
          candidates.each do |url|
            body = ''
            title = ''
            begin
              require 'rest-client'
              resp = RestClient::Request.execute(
                method: :get,
                url: url,
                timeout: 12,
                open_timeout: 5,
                max_redirects: 5,
                headers: {
                  user_agent: 'Mozilla/5.0 (compatible; pwn-ai-extrospection/0.5)',
                  accept: 'text/html,application/json'
                }
              )
              body = resp.body.to_s
              title = body[%r{<title[^>]*>(.*?)</title>}im, 1].to_s.gsub(/\s+/, ' ').strip
            rescue StandardError
              # TransparentBrowser rest/headless as last resort
              begin
                require 'pwn/plugins/transparent_browser' unless defined?(PWN::Plugins::TransparentBrowser)
                bo = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
                resp = bo[:browser].get(url) { |r, _rq, _res| r }
                body = resp.body.to_s
                title = body[%r{<title[^>]*>(.*?)</title>}im, 1].to_s.gsub(/\s+/, ' ').strip
                PWN::Plugins::TransparentBrowser.close(browser_obj: bo)
              rescue StandardError => e
                pages << { url: url, error: "#{e.class}: #{e.message.to_s[0, 100]}" }
                next
              end
            end
            next if body.empty?

            interesting = body.scan(/(?:Grantee|Product|Frequency|Grant Date|Equipment Class|Rule Parts|FCC ID|Applicant)[^<]{0,60}/i)
                              .map { |s| s.gsub(/\s+/, ' ').strip }.uniq.first(16)
            # Also extract MHz mentions for RF device content
            freqs = body.scan(/\b\d{2,5}(?:\.\d+)?\s*(?:MHz|GHz|kHz)\b/i).uniq.first(12)
            pages << { url: url, title: title[0, 160], excerpts: interesting, frequencies: freqs, bytes: body.length, reachable: true }
          end
          {
            source: 'fccid.io+device.report+fcc.gov',
            fcc_id: q,
            grantee_code: grantee,
            product_code: product,
            pages: pages,
            references: [
              "https://fccid.io/#{q}",
              "https://device.report/fcc/#{q}",
              'https://www.fcc.gov/oet/ea/fccid'
            ]
          }
        end

        private_class_method def self.osint_patent(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          # Google Patents public search (HTML) + USPTO patentsview when query looks like a number
          gurl = "https://patents.google.com/?q=#{URI.encode_www_form_component(q)}"
          html = begin
            require 'rest-client'
            RestClient::Request.execute(method: :get, url: gurl, timeout: 12, open_timeout: 5, headers: { user_agent: 'pwn-ai-extrospection' }).body.to_s
          rescue StandardError
            ''
          end
          titles = html.scan(/itemprop="title"[^>]*content="([^"]+)"/i).flatten.uniq.first(limit)
          titles = html.scan(%r{<title>(.*?)</title>}im).flatten.map { |t| t.gsub(/\s+/, ' ').strip } if titles.empty?
          # PatentsView API (public, no key) — inventor / patent search
          pv = nil
          if q.match?(/\d{5,}/)
            num = q.gsub(/[^0-9]/, '')
            pv = http_get_json(url: "https://api.patentsview.org/patents/query?q={\"patent_number\":\"#{num}\"}&f=[\"patent_number\",\"patent_title\",\"patent_date\",\"assignee_organization\"]&o={\"per_page\":#{limit}}")
          else
            pv = http_get_json(url: "https://api.patentsview.org/patents/query?q={\"_text_any\":{\"patent_title\":\"#{q.gsub('"', '')}\"}}&f=[\"patent_number\",\"patent_title\",\"patent_date\"]&o={\"per_page\":#{limit}}")
          end
          { source: 'google-patents+patentsview', query: q, google_url: gurl, titles: titles, patentsview: pv }
        end

        private_class_method def self.osint_person(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          # Public people-search is policy-constrained; return structured search plan + free sources.
          # Wikidata + Wikipedia open search are fully public and useful for missing-person / public-figure.
          wiki = http_get_json(url: "https://en.wikipedia.org/w/api.php?action=opensearch&search=#{URI.encode_www_form_component(q)}&limit=#{limit}&namespace=0&format=json")
          wikidata = http_get_json(url: "https://www.wikidata.org/w/api.php?action=wbsearchentities&search=#{URI.encode_www_form_component(q)}&language=en&limit=#{limit}&format=json")
          open_sanctions = http_get_json(url: "https://api.opensanctions.org/search/default?q=#{URI.encode_www_form_component(q)}")
          {
            source: 'wikipedia+wikidata+opensanctions',
            query: q,
            wikipedia: wiki,
            wikidata: wikidata,
            open_sanctions: open_sanctions.is_a?(Hash) ? open_sanctions.slice(:results, :total) : open_sanctions,
            missing_person_targets: [
              'https://www.namus.gov/Search',
              'https://www.fbi.gov/wanted/kidnap',
              "https://charleyproject.org/?s=#{URI.encode_www_form_component(q)}"
            ],
            note: 'Commercial people-search APIs (Pipl, Spokeo, etc.) require keys/ToS; public free sources aggregated here.'
          }
        end

        private_class_method def self.osint_username(opts = {})
          q = opts[:query].to_s.sub(/\A@/, '').strip
          platforms = {
            github: "https://api.github.com/users/#{URI.encode_www_form_component(q)}",
            gitlab: "https://gitlab.com/api/v4/users?username=#{URI.encode_www_form_component(q)}",
            reddit: "https://www.reddit.com/user/#{URI.encode_www_form_component(q)}/about.json"
          }
          hits = {}
          platforms.each do |name, url|
            body = http_get_json(url: url)
            hits[name] = body if body
          rescue StandardError => e
            hits[name] = { error: e.message.to_s[0, 80] }
          end
          { source: 'username-public-apis', username: q, hits: hits }
        end

        private_class_method def self.osint_github(opts = {})
          q = opts[:query].to_s.sub(%r{\A(github\.com/|gh:)}, '').strip
          user = http_get_json(url: "https://api.github.com/users/#{URI.encode_www_form_component(q)}")
          search = http_get_json(url: "https://api.github.com/search/users?q=#{URI.encode_www_form_component(q)}&per_page=5")
          { source: 'api.github.com', user: user, search: search }
        end

        private_class_method def self.osint_wayback(opts = {})
          q = opts[:query].to_s
          q = "http://#{q}" unless q.match?(%r{\Ahttps?://}i)
          body = http_get_json(url: "https://archive.org/wayback/available?url=#{URI.encode_www_form_component(q)}")
          cdx = begin
            require 'rest-client'
            resp = RestClient::Request.execute(
              method: :get,
              url: "https://web.archive.org/cdx/search/cdx?url=#{URI.encode_www_form_component(q)}&output=json&limit=5",
              timeout: 10,
              open_timeout: 4,
              headers: { user_agent: 'pwn-ai-extrospection' }
            )
            JSON.parse(resp.body)
          rescue StandardError
            nil
          end
          { source: 'archive.org', available: body, cdx: cdx }
        end

        private_class_method def self.osint_otx(opts = {})
          q = opts[:query].to_s.strip
          kind = if q.match?(/\A\d{1,3}(?:\.\d{1,3}){3}\z/)
                   'IPv4'
                 elsif q.include?(':') && q.match?(/\A[0-9a-fA-F:.]+\z/)
                   'IPv6'
                 elsif q.match?(%r{\Ahttps?://}i)
                   'url'
                 elsif q.include?('.')
                   'domain'
                 else
                   'hostname'
                 end
          path = case kind
                 when 'url' then "https://otx.alienvault.com/api/v1/indicators/url/#{URI.encode_www_form_component(q)}/general"
                 else "https://otx.alienvault.com/api/v1/indicators/#{kind}/#{URI.encode_www_form_component(q)}/general"
                 end
          body = http_get_json(url: path)
          pulse = http_get_json(url: path.sub(%r{/general\z}, '/passive_dns')) if kind != 'url'
          { source: 'otx.alienvault.com', indicator: q, kind: kind, general: body, passive_dns: pulse }
        end

        private_class_method def self.osint_urlhaus(opts = {})
          q = opts[:query].to_s.strip
          require 'rest-client'
          # URLHaus accepts host or url via POST
          payload = if q.match?(%r{\Ahttps?://}i)
                      { url: q }
                    else
                      { host: q } # IPv4 / FQDN / hostname all map to host lookup
                    end
          resp = RestClient::Request.execute(
            method: :post,
            url: payload.key?(:url) ? 'https://urlhaus-api.abuse.ch/v1/url/' : 'https://urlhaus-api.abuse.ch/v1/host/',
            payload: payload,
            timeout: 12,
            open_timeout: 5,
            headers: { user_agent: 'pwn-ai-extrospection' }
          )
          { source: 'urlhaus-api.abuse.ch', data: JSON.parse(resp.body, symbolize_names: true) }
        rescue StandardError => e
          { source: 'urlhaus-api.abuse.ch', error: "#{e.class}: #{e.message.to_s[0, 120]}" }
        end

        private_class_method def self.osint_threatfox(opts = {})
          q = opts[:query].to_s.strip
          require 'rest-client'
          body = {
            query: 'search_ioc',
            search_term: q
          }.to_json
          resp = RestClient::Request.execute(
            method: :post,
            url: 'https://threatfox-api.abuse.ch/api/v1/',
            payload: body,
            timeout: 12,
            open_timeout: 5,
            headers: { content_type: :json, user_agent: 'pwn-ai-extrospection' }
          )
          { source: 'threatfox-api.abuse.ch', data: JSON.parse(resp.body, symbolize_names: true) }
        rescue StandardError => e
          { source: 'threatfox-api.abuse.ch', error: "#{e.class}: #{e.message.to_s[0, 120]}" }
        end

        private_class_method def self.osint_urlscan(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          # Public search endpoint (no key required for search)
          body = http_get_json(url: "https://urlscan.io/api/v1/search/?q=#{URI.encode_www_form_component(q)}&size=#{limit}")
          results = Array(body.is_a?(Hash) ? (body[:results] || body['results']) : []).first(limit).map do |r|
            r = r.transform_keys(&:to_sym) if r.is_a?(Hash) && r.keys.first.is_a?(String)
            page = (r[:page] || {}).is_a?(Hash) ? r[:page] : {}
            page = page.transform_keys(&:to_sym) if page.keys.first.is_a?(String)
            {
              url: page[:url] || r.dig(:task, :url),
              domain: page[:domain],
              ip: page[:ip],
              country: page[:country],
              server: page[:server],
              screenshot: r[:screenshot],
              result: r[:result]
            }
          end
          { source: 'urlscan.io', total: body.is_a?(Hash) ? (body[:total] || body['total']) : nil, hits: results }
        end

        private_class_method def self.osint_hackertarget(opts = {})
          q = opts[:query].to_s.strip
          require 'rest-client'
          base = 'https://api.hackertarget.com'
          outs = {}
          endpoints = {
            whois: "#{base}/whois/?q=#{URI.encode_www_form_component(q)}",
            dnslookup: "#{base}/dnslookup/?q=#{URI.encode_www_form_component(q)}",
            reversedns: "#{base}/reversedns/?q=#{URI.encode_www_form_component(q)}",
            geoip: "#{base}/geoip/?q=#{URI.encode_www_form_component(q)}",
            httpheaders: "#{base}/httpheaders/?q=#{URI.encode_www_form_component(q)}"
          }
          # Only fire a couple of free endpoints to stay within public rate limits
          endpoints.each do |name, url|
            resp = RestClient::Request.execute(method: :get, url: url, timeout: 10, open_timeout: 4, headers: { user_agent: 'pwn-ai-extrospection' })
            outs[name] = resp.body.to_s[0, 2_000]
          rescue StandardError => e
            outs[name] = "error: #{e.class}: #{e.message.to_s[0, 80]}"
          end
          { source: 'api.hackertarget.com', data: outs }
        end

        private_class_method def self.osint_openfda(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          # Device / drug / enforcement open search — best-effort public endpoints
          enc = URI.encode_www_form_component(q)
          device = http_get_json(url: "https://api.fda.gov/device/510k.json?search=device_name:#{enc}+device_name:\"#{enc}\"&limit=#{limit}")
          device ||= http_get_json(url: "https://api.fda.gov/device/510k.json?search=#{enc}&limit=#{limit}")
          drug = http_get_json(url: "https://api.fda.gov/drug/label.json?search=openfda.brand_name:#{enc}&limit=#{limit}")
          enforce = http_get_json(url: "https://api.fda.gov/device/enforcement.json?search=product_description:#{enc}&limit=#{limit}")
          {
            source: 'api.fda.gov',
            query: q,
            device_510k: device.is_a?(Hash) ? device.slice(:meta, :results) : device,
            drug_label: drug.is_a?(Hash) ? drug.slice(:meta, :results) : drug,
            enforcement: enforce.is_a?(Hash) ? enforce.slice(:meta, :results) : enforce
          }
        end

        private_class_method def self.osint_nominatim(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          # OpenStreetMap Nominatim — public, requires identifying UA (we set one)
          require 'rest-client'
          url = "https://nominatim.openstreetmap.org/search?q=#{URI.encode_www_form_component(q)}&format=json&addressdetails=1&limit=#{limit}"
          resp = RestClient::Request.execute(
            method: :get,
            url: url,
            timeout: 12,
            open_timeout: 5,
            headers: { user_agent: 'pwn-ai-extrospection/0.5 (research; support@0dayinc.com)', accept: :json }
          )
          rows = JSON.parse(resp.body, symbolize_names: true)
          hits = Array(rows).first(limit).map do |r|
            {
              display_name: r[:display_name],
              lat: r[:lat],
              lon: r[:lon],
              type: r[:type],
              class: r[:class],
              osm_id: r[:osm_id],
              address: r[:address]
            }
          end
          { source: 'nominatim.openstreetmap.org', hits: hits }
        rescue StandardError => e
          { source: 'nominatim.openstreetmap.org', error: "#{e.class}: #{e.message.to_s[0, 120]}" }
        end

        private_class_method def self.osint_opencorporates(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          # OpenCorporates public API (rate-limited without token)
          body = http_get_json(url: "https://api.opencorporates.com/v0.4/companies/search?q=#{URI.encode_www_form_component(q)}&per_page=#{limit}")
          companies = []
          if body.is_a?(Hash)
            results = body.dig(:results, :companies) || body.dig('results', 'companies') || []
            companies = Array(results).first(limit).map do |row|
              c = row[:company] || row['company'] || row
              c = c.transform_keys(&:to_sym) if c.is_a?(Hash) && c.keys.first.is_a?(String)
              {
                name: c[:name],
                company_number: c[:company_number],
                jurisdiction: c[:jurisdiction_code],
                incorporation_date: c[:incorporation_date],
                company_type: c[:company_type],
                opencorporates_url: c[:opencorporates_url],
                current_status: c[:current_status]
              }
            end
          end
          { source: 'api.opencorporates.com', total: body.is_a?(Hash) ? (body.dig(:results, :total_count) || body.dig('results', 'total_count')) : nil, companies: companies, raw_error: (body[:error] if body.is_a?(Hash)) }
        end

        private_class_method def self.osint_courtlistener(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          # CourtListener (Free Law Project) public search — dockets / opinions
          search = http_get_json(url: "https://www.courtlistener.com/api/rest/v4/search/?q=#{URI.encode_www_form_component(q)}&type=o&page_size=#{limit}")
          people = http_get_json(url: "https://www.courtlistener.com/api/rest/v4/people/?name=#{URI.encode_www_form_component(q)}&page_size=#{limit}")
          {
            source: 'courtlistener.com',
            opinions_search: search.is_a?(Hash) ? search.slice(:count, :results) : search,
            people: people.is_a?(Hash) ? people.slice(:count, :results) : people,
            reference: "https://www.courtlistener.com/?q=#{URI.encode_www_form_component(q)}"
          }
        end

        private_class_method def self.osint_sec_edgar(opts = {})
          q = opts[:query].to_s.strip
          limit = opts[:limit] || 5
          require 'rest-client'
          # SEC EDGAR full-text search index (public). Also company tickers JSON.
          headers = {
            user_agent: 'pwn-ai-extrospection research support@0dayinc.com',
            accept: 'application/json'
          }
          # Prefer company tickers map when query looks like a ticker / name
          tickers = nil
          begin
            resp = RestClient::Request.execute(method: :get, url: 'https://www.sec.gov/files/company_tickers.json', timeout: 12, open_timeout: 5, headers: headers)
            map = JSON.parse(resp.body)
            ql = q.downcase
            tickers = map.values.select do |v|
              v = v.transform_keys(&:to_s)
              v['ticker'].to_s.downcase == ql || v['title'].to_s.downcase.include?(ql) || format('%010d', v['cik_str'].to_i) == q.gsub(/\D/, '').rjust(10, '0')
            end.first(limit)
          rescue StandardError => e
            tickers = [{ error: "#{e.class}: #{e.message.to_s[0, 80]}" }]
          end
          efts = http_get_json(url: "https://efts.sec.gov/LATEST/search-index?q=#{URI.encode_www_form_component(q)}&dateRange=custom&startdt=2000-01-01&enddt=#{Time.now.utc.strftime('%Y-%m-%d')}&forms=")
          {
            source: 'sec.gov+efts',
            query: q,
            company_tickers: tickers,
            filings_index: efts,
            references: [
              "https://www.sec.gov/cgi-bin/browse-edgar?company=#{URI.encode_www_form_component(q)}&action=getcompany",
              "https://efts.sec.gov/LATEST/search-index?q=#{URI.encode_www_form_component(q)}"
            ]
          }
        end

        private_class_method def self.osint_vital_records(opts = {})
          q = opts[:query].to_s.strip
          # Vital records (birth/death/marriage) are almost entirely state/local and often restricted.
          # Return a structured public-record search plan rather than claiming live B2B access.
          {
            source: 'vital-records-public-plan',
            query: q,
            note: 'US birth/death/marriage certificates are state vital-records offices (often restricted 100 years). Aggregate public genealogy + missing-person pivots only.',
            public_genealogy: [
              "https://www.familysearch.org/en/search/record/results?q.givenName=#{URI.encode_www_form_component(q.split.first.to_s)}&q.surname=#{URI.encode_www_form_component(q.split.last.to_s)}",
              "https://www.findagrave.com/memorial/search?firstname=#{URI.encode_www_form_component(q.split.first.to_s)}&lastname=#{URI.encode_www_form_component(q.split.last.to_s)}",
              "https://www.ancestry.com/search/?name=#{URI.encode_www_form_component(q.tr(' ', '+'))}",
              'https://www.cdc.gov/nchs/w2w/index.htm'
            ],
            state_vital_records_index: 'https://www.cdc.gov/nchs/w2w/index.htm',
            missing_person_targets: [
              'https://www.namus.gov/Search',
              'https://www.fbi.gov/wanted/kidnap',
              "https://charleyproject.org/?s=#{URI.encode_www_form_component(q)}"
            ],
            court_public: [
              "https://www.courtlistener.com/?q=#{URI.encode_www_form_component(q)}",
              'https://pacer.uscourts.gov/'
            ]
          }
        end

        private_class_method def self.build_osint_summary(opts = {})
          r = opts[:results] || {}
          parts = ["osint kind=#{r[:kind]} query=#{r[:query]}"]
          Array(r[:feeds]).each do |feed, val|
            if val.is_a?(Hash) && val[:error]
              parts << "#{feed}=err"
            elsif val.is_a?(Hash) && val[:skipped]
              parts << "#{feed}=skip"
            else
              parts << "#{feed}=ok"
            end
          end
          parts.join(' | ')[0, 400]
        end

        # ── Telecomm helpers ────────────────────────────────────────

        private_class_method def self.telecomm_baresip_cmd(opts = {})
          host = opts[:host]
          port = opts[:port]
          cmd  = opts[:cmd].to_s
          require 'rest-client'
          url = "http://#{host}:#{port}#{cmd.start_with?('/') ? cmd : "/?#{cmd}"}"
          resp = RestClient::Request.execute(method: :get, url: url, timeout: 5, open_timeout: 2, headers: { user_agent: 'pwn-ai-extrospection' })
          body = resp.body.to_s
          text = begin
            require 'nokogiri'
            Nokogiri::HTML.parse(body).text.gsub(/\s+/, ' ').strip
          rescue StandardError
            body
          end
          { http_status: resp.code, text: text[0, 1_000] }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message.to_s[0, 120]}" }
        end

        # ── Packet helpers ──────────────────────────────────────────

        private_class_method def self.summarize_pcap_file(opts = {})
          path = opts[:path].to_s
          return { error: 'missing pcap' } unless File.exist?(path)

          tshark = sh(cmd: 'which tshark 2>/dev/null')
          unless tshark.empty?
            stats = sh(cmd: "timeout 15 tshark -r #{Shellwords.escape(path)} -q -z io,phs 2>/dev/null")
            convs = sh(cmd: "timeout 15 tshark -r #{Shellwords.escape(path)} -q -z conv,ip 2>/dev/null")
            frames = sh(cmd: "timeout 15 tshark -r #{Shellwords.escape(path)} -T fields -e frame.number 2>/dev/null | wc -l")
            return {
              path: path,
              bytes: File.size(path),
              frames: frames.to_i,
              protocol_hierarchy: stats.to_s[0, 1_500],
              ip_conversations: convs.to_s[0, 1_500]
            }
          end

          # Fall back to PacketFu packet count / top ethertypes
          begin
            require 'pwn/plugins/packet' unless defined?(PWN::Plugins::Packet)
            pkts = PWN::Plugins::Packet.open_pcap_file(path: path)
            ethertypes = Hash.new(0)
            Array(pkts).first(500).each do |p|
              et = begin
                p.eth_proto
              rescue StandardError
                nil
              end
              ethertypes[et] += 1 if et
            end
            { path: path, bytes: File.size(path), frames: Array(pkts).length, ethertypes: ethertypes }
          rescue StandardError => e
            { path: path, bytes: File.size(path), error: "#{e.class}: #{e.message.to_s[0, 120]}" }
          end
        end

        # ── Vision helpers ──────────────────────────────────────────

        private_class_method def self.vision_ocr(opts = {})
          file = opts[:file].to_s
          lang = opts[:lang] || 'eng'
          begin
            require 'pwn/plugins/ocr' unless defined?(PWN::Plugins::OCR)
            # Plugin currently takes file only; lang is respected via TESSDATA / shell fallback.
            return PWN::Plugins::OCR.process(file: file).to_s
          rescue StandardError
            nil
          end
          sh(cmd: "timeout 60 tesseract #{Shellwords.escape(file)} stdout -l #{Shellwords.escape(lang)} 2>/dev/null")
        end

        private_class_method def self.vision_barcodes(opts = {})
          file = opts[:file].to_s
          zbar = sh(cmd: 'which zbarimg 2>/dev/null')
          unless zbar.empty?
            raw = sh(cmd: "timeout 30 zbarimg -q #{Shellwords.escape(file)} 2>/dev/null")
            return raw.lines.map(&:strip).reject(&:empty?)
          end
          # No decoder — report guidance
          [{ error: 'zbarimg not installed', advice: 'apt install zbar-tools' }]
        end

        # ── Voice helpers ───────────────────────────────────────────

        private_class_method def self.pick_tts_engine(opts = {})
          inv = opts[:inv] || {}
          bins = inv[:bins] || {}
          return :espeak if !bins[:'espeak-ng'].to_s.empty? || !bins[:espeak].to_s.empty?
          return :spd_say unless bins[:'spd-say'].to_s.empty?
          return :festival unless bins[:festival].to_s.empty?

          :espeak
        end

        private_class_method def self.pick_stt_engine(opts = {})
          inv = opts[:inv] || {}
          bins = inv[:bins] || {}
          return :whisper unless bins[:whisper].to_s.empty?

          :whisper
        end

        private_class_method def self.voice_tts(opts = {})
          text = opts[:text].to_s
          engine = opts[:engine].to_sym
          out = opts[:out].to_s
          inv = opts[:inv] || {}
          bins = inv[:bins] || {}
          case engine
          when :espeak
            bin = bins[:'espeak-ng'].to_s
            bin = bins[:espeak].to_s if bin.empty?
            bin = sh(cmd: 'which espeak-ng 2>/dev/null || which espeak 2>/dev/null') if bin.empty?
            return [false, 'espeak not found'] if bin.empty?

            # prefer wav write if -w supported
            log = sh(cmd: "#{Shellwords.escape(bin)} -w #{Shellwords.escape(out)} #{Shellwords.escape(text)} 2>&1")
            return [File.exist?(out), log] if File.exist?(out)

            log = sh(cmd: "printf '%s' #{Shellwords.escape(text)} | #{Shellwords.escape(bin)} --stdout > #{Shellwords.escape(out)} 2>&1")
            [File.exist?(out) && File.size(out).positive?, log]
          when :spd_say
            bin = bins[:'spd-say'].to_s
            bin = sh(cmd: 'which spd-say 2>/dev/null') if bin.empty?
            return [false, 'spd-say not found'] if bin.empty?

            log = sh(cmd: "#{Shellwords.escape(bin)} -w #{Shellwords.escape(text)} 2>&1")
            # spd-say speaks to audio device — no wav; mark ok on exit
            [true, log]
          when :festival
            # Use plugin if text file available
            tmp = File.join(Dir.tmpdir, "pwn_tts_#{Process.pid}.txt")
            File.write(tmp, text)
            begin
              require 'pwn/plugins/voice' unless defined?(PWN::Plugins::Voice)
              PWN::Plugins::Voice.text_to_speech(text_path: tmp)
              [true, 'festival via PWN::Plugins::Voice']
            rescue StandardError => e
              [false, "#{e.class}: #{e.message}"]
            ensure
              FileUtils.rm_f(tmp)
            end
          else
            [false, "unsupported TTS engine: #{engine}"]
          end
        end

        private_class_method def self.voice_stt(opts = {})
          audio = opts[:audio].to_s
          engine = opts[:engine].to_sym
          model = opts[:model] || 'tiny'
          inv = opts[:inv] || {}
          bins = inv[:bins] || {}
          case engine
          when :whisper
            bin = bins[:whisper].to_s
            bin = sh(cmd: 'which whisper 2>/dev/null') if bin.empty?
            art = File.join(Dir.home, '.pwn', 'extrospection', 'voice')
            FileUtils.mkdir_p(art)
            if bin.empty?
              # try plugin (raises if whisper missing)
              begin
                require 'pwn/plugins/voice' unless defined?(PWN::Plugins::Voice)
                PWN::Plugins::Voice.speech_to_text(audio_file_path: audio, model: model, output_dir: art)
              rescue StandardError => e
                return ['', "whisper unavailable: #{e.class}: #{e.message}"]
              end
            else
              sh(cmd: "timeout 300 #{Shellwords.escape(bin)} #{Shellwords.escape(audio)} --model #{Shellwords.escape(model)} --output_dir #{Shellwords.escape(art)} --output_format txt 2>&1")
            end
            base = File.join(art, "#{File.basename(audio, '.*')}.txt")
            alt = Dir.glob(File.join(art, '*.txt')).max_by { |f| File.mtime(f) }
            path = File.exist?(base) ? base : alt
            text = path && File.exist?(path) ? File.read(path) : ''
            [text, "whisper model=#{model} out=#{path}"]
          else
            ['', "unsupported STT engine: #{engine}"]
          end
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
              PWN::AI::Agent::Extrospection.osint(query: '+13125551212', kind: :phone)
              PWN::AI::Agent::Extrospection.osint(query: '2ABIP-ESP32', kind: :fcc_id)
              PWN::AI::Agent::Extrospection.osint(query: 'US10123456', kind: :patent)
              PWN::AI::Agent::Extrospection.serial_sense(payload: "ATI\r")
              PWN::AI::Agent::Extrospection.telecomm(action: :status)
              PWN::AI::Agent::Extrospection.packet_sense(action: :capture, filter: 'tcp port 443', count: 10)
              PWN::AI::Agent::Extrospection.vision(file: '/tmp/shot.png', action: :ocr)
              PWN::AI::Agent::Extrospection.voice_sense(action: :tts, text: 'hello from pwn')
              PWN::AI::Agent::Extrospection.verify(claim: 'CVE-2026-12345 affects OpenSSL 3.2.1')
              PWN::AI::Agent::Extrospection.revalidate_memory                  # cron: GC stale PWN::Memory :fact entries
              PWN::AI::Agent::Extrospection.reset

              PRIMARY use = on-demand sensing (intel / verify / watch / rf_tune / osint /
              serial_sense / telecomm / packet_sense / vision / voice_sense / observe /
              rf / web / osint / serial / telecomm / packet / vision / voice).
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

              Configure new limbs:
                PWN::Env[:ai][:agent][:extrospection][:osint]    = { ttl: 86400, api_keys: { shodan: '…', hunter: '…' } }
                PWN::Env[:ai][:agent][:extrospection][:serial]   = { block_dev: '/dev/ttyUSB0', baud: 115200, settle_secs: 1.5 }
                PWN::Env[:ai][:agent][:extrospection][:telecomm] = { host: '127.0.0.1', port: 8000 }
                PWN::Env[:ai][:agent][:extrospection][:packet]   = { iface: 'eth0' }
                PWN::Env[:ai][:agent][:extrospection][:vision]   = { lang: 'eng' }
                PWN::Env[:ai][:agent][:extrospection][:voice]    = { ttl: 3600 }

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
