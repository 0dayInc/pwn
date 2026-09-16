# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'
require 'digest'
require 'time'

module PWN
  module Plugins
    # Persistent finding rows for pwn-ai (title, severity, host, evidence, PoC).
    module Findings
      FILE = File.join(Dir.home, '.pwn', 'findings.jsonl')

      public_class_method def self.required_bins
        []
      end

      # Strict P10 boundary. Legacy record remains available for older callers.
      public_class_method def self.record_structured(opts = {})
        opts = opts.transform_keys(&:to_sym)
        opts[:affected_asset] ||= opts[:target]
        opts[:poc] ||= opts[:repro_cmd]
        opts[:target] ||= opts[:affected_asset]
        opts[:repro_cmd] ||= opts[:poc]
        %i[title cwe cvss_vector affected_asset poc remediation].each do |key|
          raise ArgumentError, "#{key} must be a non-empty string" unless opts[key].is_a?(String) && !opts[key].strip.empty?
        end
        raise ArgumentError, 'cwe must be CWE-<positive integer>' unless opts[:cwe].match?(/\ACWE-[1-9]\d*\z/)

        engagement = opts[:engagement_id].to_s
        raise ArgumentError, 'engagement_id must be a simple identifier' unless engagement.empty? || engagement.match?(/\A[a-zA-Z0-9_-]+\z/)

        validate_cvss(opts)
        confidence = opts[:confidence]
        raise ArgumentError, 'confidence must be numeric in 0..1' unless confidence.is_a?(Numeric) && confidence.finite? && confidence.between?(0, 1)

        paths = opts[:evidence_paths]
        raise ArgumentError, 'evidence_paths must contain existing readable absolute file paths' unless paths.is_a?(Array) && !paths.empty? && paths.all? { |path| path.is_a?(String) && path.start_with?('/') && File.file?(path) && File.readable?(path) }

        refs = opts[:attack_chain_refs]
        rows = report(engagement_id: opts[:engagement_id].to_s)
        raise ArgumentError, 'attack_chain_refs must reference existing findings in this engagement' unless refs.is_a?(Array) && refs.all? { |id| id.is_a?(String) && rows.any? { |row| row[:id] == id } }

        score = opts[:cvss_score]
        severity = if score.zero?
                     'info'
                   elsif score < 4
                     'low'
                   elsif score < 7
                     'medium'
                   elsif score < 9
                     'high'
                   else
                     'critical'
                   end
        row = opts.slice(:title, :cwe, :cvss_vector, :cvss_score, :affected_asset, :evidence_paths, :poc,
                         :attack_chain_refs, :remediation, :confidence, :engagement_id, :session_id)
        row = row.merge(id: SecureRandom.hex(6), severity: severity, status: 'open', verification_status: 'not_executed',
                        chain_refs: refs, host: opts[:affected_asset], target: opts[:affected_asset],
                        repro_cmd: opts[:poc], evidence: paths.map { |path| Digest::SHA256.file(path).hexdigest },
                        poc_artifacts: [], at: Time.now.utc.iso8601)
        FileUtils.mkdir_p(File.dirname(FILE))
        File.open(FILE, 'a') do |file|
          file.flock(File::LOCK_EX)
          file.puts(JSON.generate(row))
        end
        evidence_anchor(row: row, arts: paths)
        row
      end

      private_class_method def self.validate_cvss(opts = {})
        score = opts[:cvss_score]
        raise ArgumentError, 'cvss_score must be numeric in 0..10' unless score.is_a?(Numeric) && score.finite? && score.between?(0, 10)

        parts = opts[:cvss_vector].split('/')
        version = parts.shift
        values = { 'AV' => %w[N A L P], 'AC' => %w[L H], 'PR' => %w[N L H], 'UI' => %w[N R],
                   'S' => %w[U C], 'C' => %w[N L H], 'I' => %w[N L H], 'A' => %w[N L H] }
        metrics = parts.map { |part| part.split(':', -1) }
        raise ArgumentError, 'cvss_vector contains malformed metrics' unless metrics.all? { |metric| metric.length == 2 }

        valid = %w[CVSS:3.0 CVSS:3.1].include?(version) && metrics.length == values.length &&
                metrics.map(&:first).uniq.length == values.length && metrics.all? { |key, value| values[key]&.include?(value) }
        raise ArgumentError, 'cvss_vector must be a complete CVSS 3.0/3.1 base vector' unless valid

        metrics = metrics.to_h
        changed = metrics['S'] == 'C'
        impact_values = { 'N' => 0.0, 'L' => 0.22, 'H' => 0.56 }
        iss = 1 - %w[C I A].map { |key| 1 - impact_values.fetch(metrics[key]) }.inject(:*)
        impact = changed ? ((7.52 * (iss - 0.029)) - (3.25 * ((iss - 0.02)**15))) : 6.42 * iss
        av = { 'N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2 }.fetch(metrics['AV'])
        ac = metrics['AC'] == 'L' ? 0.77 : 0.44
        pr = { 'N' => 0.85, 'L' => changed ? 0.68 : 0.62, 'H' => changed ? 0.5 : 0.27 }.fetch(metrics['PR'])
        ui = metrics['UI'] == 'N' ? 0.85 : 0.62
        base = if impact <= 0
                 0
               else
                 [10, (impact + (8.22 * av * ac * pr * ui)) * (changed ? 1.08 : 1)].min
               end
        calculated = ((base * 10).round(8).ceil / 10.0)
        raise ArgumentError, "cvss_score must match cvss_vector (#{calculated})" unless score == calculated
      end

      public_class_method def self.record(opts = {})
        title = opts[:title].to_s
        raise 'ERROR: title is required' if title.empty?

        arts = Array(opts[:poc_artifacts]).map(&:to_s).reject(&:empty?)
        if opts[:poc].is_a?(Hash)
          arts << opts[:poc][:path].to_s unless opts[:poc][:path].to_s.empty?
        else
          arts << opts[:poc].to_s unless opts[:poc].to_s.empty?
        end
        raise 'ERROR: poc_artifacts are required' if arts.empty?

        ev = opts[:evidence]
        ev_list = Array(ev).map(&:to_s)
        ev_text = ev_list.join(' ')
        raise 'ERROR: evidence must be at least 40 characters citing the PoC' if ev_text.length < 40

        sha_ev = arts.filter_map do |p|
          next unless File.file?(p)

          Digest::SHA256.file(p).hexdigest
        end
        proven = sha_ev.any?
        row = {
          id: SecureRandom.hex(6),
          title: title,
          severity: proven ? (opts[:severity] || 'info').to_s : 'unproven',
          cvss_vector: (opts[:cvss_vector] || opts[:cvss]).to_s,
          affected_asset: (opts[:affected_asset] || opts[:host]).to_s,
          host: opts[:host].to_s,
          evidence: sha_ev.any? ? sha_ev : ev_list,
          poc: opts[:poc].is_a?(Hash) ? opts[:poc] : { type: 'file', path: arts.first, reproduction_steps: opts[:reproduction_steps].to_s },
          poc_artifacts: arts,
          chain_refs: Array(opts[:chain_refs] || opts[:chain_parent_id]).map(&:to_s).reject(&:empty?),
          cvss: opts[:cvss].to_s,
          status: proven ? (opts[:status] || 'open').to_s : 'unproven',
          engagement_id: opts[:engagement_id].to_s,
          chain_parent_id: opts[:chain_parent_id].to_s,
          session_id: opts[:session_id].to_s,
          at: Time.now.utc.iso8601
        }
        FileUtils.mkdir_p(File.dirname(FILE))
        File.open(FILE, 'a') { |f| f.puts(JSON.generate(row)) }
        evidence_anchor(row: row, arts: arts)
        row
      end

      public_class_method def self.evidence_verify(opts = {})
        eng = (opts[:engagement_id] || opts[:name] || 'default').to_s
        path = File.join(Dir.home, '.pwn', 'engagements', eng, 'evidence.jsonl')
        return { ok: true, rows: 0 } unless File.file?(path)

        mismatches = []
        n = 0
        File.readlines(path).each do |ln|
          row = JSON.parse(ln, symbolize_names: true)
          n += 1
          unless File.file?(row[:path].to_s)
            mismatches << row[:path]
            next
          end

          sha = Digest::SHA256.file(row[:path]).hexdigest
          mismatches << row[:path] unless sha == row[:sha256].to_s
        end
        { ok: mismatches.empty?, rows: n, mismatches: mismatches }
      end

      public_class_method def self.report(opts = {})
        return [] unless File.file?(FILE)

        rows = File.readlines(FILE).filter_map do |ln|
          JSON.parse(ln, symbolize_names: true)
        rescue JSON::ParserError
          nil
        end
        host = opts[:host].to_s
        rows = rows.select { |r| r[:host].to_s == host } unless host.empty?
        rows = rows.select { |r| r[:engagement_id].to_s == opts[:engagement_id].to_s } if opts.key?(:engagement_id)
        rows
      end

      public_class_method def self.query(opts = {})
        report(opts)
      end

      public_class_method def self.chain(opts = {})
        parent_id = opts[:parent_id].to_s
        raise 'ERROR: parent_id is required' if parent_id.empty?

        child = record(
          opts.merge(
            chain_parent_id: parent_id,
            evidence: (opts[:evidence].to_s.length >= 40 ? opts[:evidence] : 'Chained finding reuses parent PoC evidence and raises composite impact.')
          )
        )
        ranks = { 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 }
        parent = report.find { |r| r[:id].to_s == parent_id }
        sev = [parent&.[](:severity), child[:severity]].compact.max_by { |s| ranks[s.to_s] || 0 }
        child.merge(composite_severity: sev)
      end

      public_class_method def self.chain_score(opts = {})
        ids = Array(opts[:ids] || opts[:chain_refs]).map(&:to_s)
        rows = report.select { |r| ids.include?(r[:id].to_s) || ids.include?(r[:chain_parent_id].to_s) }
        rows = report if rows.empty? && ids.empty?
        ranks = { 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4, 'unproven' => 0 }
        peak = rows.map { |r| ranks[r[:severity].to_s] || 0 }.max || 0
        sev = %w[info low medium high critical][peak] || 'info'
        { chain_refs: rows.map { |r| r[:id] }, score: sev, combined_severity: sev, n: rows.length,
          rationale: 'Maximum recorded constituent severity. No automatic escalation; linking is not proof of combined exploitability.' }
      end

      # Attest a working PoC from request/response or script output. File hashes are not execution.

      public_class_method def self.verify(opts = {})
        attest(opts.merge(mode: 'verify'))
      end

      # Re-run the same PoC path after a fix. Impact present => still_open; absent => fixed.

      public_class_method def self.retest(opts = {})
        attest(opts.merge(mode: 'retest'))
      end

      # Combine findings only when a combined-impact evidence file names every id.

      public_class_method def self.chain_impact(opts = {})
        opts = opts.transform_keys(&:to_sym)
        ids = Array(opts[:ids]).map(&:to_s)
        raise ArgumentError, 'ids must name at least two findings' if ids.length < 2

        rows = report
        chosen = ids.map { |id| rows.find { |row| row[:id].to_s == id } }
        raise ArgumentError, 'ids must name existing findings' if chosen.any?(&:nil?)

        path = opts[:combined_impact_path].to_s
        raise ArgumentError, 'combined_impact_path must be an existing readable absolute file' unless path.start_with?('/') && File.file?(path) && File.readable?(path)

        text = File.read(path)
        raise ArgumentError, 'combined_impact_path must be at least 40 characters and name every finding id' unless text.length >= 40 && ids.all? { |id| text.include?(id) }

        score = chain_score(ids: ids)
        ranks = { 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 }
        combined = score[:combined_severity]
        if opts[:escalate]
          wanted = opts[:combined_severity].to_s
          raise ArgumentError, 'combined_severity is required when escalate is true' if wanted.empty? || !ranks.key?(wanted)

          combined = wanted
        end
        patch = { combined_impact: path, combined_severity: combined, attack_chain_refs: (Array(chosen.last[:attack_chain_refs]) + ids[0..-2]).uniq }
        updated = rewrite_row(id: ids.last, patch: patch)
        evidence_anchor(row: updated, arts: [path])
        {
          finding_ids: ids,
          combined_severity: combined,
          combined_impact_path: path,
          rationale: opts[:escalate] ? 'independently evidenced combined impact' : score[:rationale],
          finding: updated
        }
      end

      # Gaps that keep issue work unfinished: unreproduced rows, unchained pairs.

      public_class_method def self.issue_work_gaps(opts = {})
        opts = opts.transform_keys(&:to_sym)
        rows = report
        eng = opts[:engagement_id].to_s
        sid = opts[:session_id].to_s
        rows = rows.select { |row| row[:engagement_id].to_s == eng } unless eng.empty?
        rows = rows.select { |row| row[:session_id].to_s == sid } unless sid.empty?
        structured = rows.select { |row| row[:cwe].to_s.start_with?('CWE-') || row.key?(:verification_status) }
        reproduced = structured.select { |row| row[:verification_status].to_s == 'reproduced' }
        unverified = structured.select { |row| row[:verification_status].to_s == 'not_executed' }
        unchained = reproduced.length >= 2 && reproduced.none? { |row| Array(row[:attack_chain_refs]).any? || row[:combined_impact].to_s.strip != '' }
        { recorded: structured.map { |row| row[:id] }, unverified: unverified.map { |row| row[:id] },
          reproduced: reproduced.map { |row| row[:id] }, unchained: unchained }
      end

      public_class_method def self.render(opts = {})
        dir = opts[:dir_path].to_s
        dir = File.join(Dir.home, '.pwn', 'exports') if dir.empty?
        name = opts[:report_name].to_s
        name = 'findings' if name.empty?
        payload = { title: 'Findings', findings: report(opts) }
        {
          markdown: PWN::Reports::Markdown.generate(results_hash: payload, dir_path: dir, report_name: name),
          html: PWN::Reports::HTML.generate(results_hash: payload, dir_path: dir, report_name: name),
          json: PWN::Reports::JSON.generate(results_hash: payload, dir_path: dir, report_name: name),
          sarif: PWN::Reports::SARIF.generate(results_hash: payload, dir_path: dir, report_name: name)
        }
      end

      private_class_method def self.attest(opts = {})
        opts = opts.transform_keys(&:to_sym)
        row = report.find { |item| item[:id].to_s == opts[:id].to_s }
        raise ArgumentError, 'id must name an existing finding' unless row

        kind = opts[:kind].to_s
        raise ArgumentError, 'kind must be http or script' unless %w[http script].include?(kind)

        impact = opts[:impact].to_s
        raise ArgumentError, 'impact must be a non-empty string' if impact.strip.empty?

        arts, body = execution_blob(opts.merge(kind: kind))
        hit = body.include?(impact)
        if opts[:mode].to_s == 'retest'
          status = hit ? 'still_open' : 'fixed'
          finding_status = hit ? 'open' : 'closed'
        else
          status = hit ? 'reproduced' : 'failed'
          finding_status = row[:status]
        end
        updated = rewrite_row(
          id: row[:id],
          patch: {
            verification_status: status,
            verification_kind: kind,
            impact: impact,
            poc_artifacts: arts,
            status: finding_status,
            verified_at: Time.now.utc.iso8601
          }
        )
        evidence_anchor(row: updated, arts: arts)
        updated
      end

      private_class_method def self.execution_blob(opts = {})
        kind = opts[:kind].to_s
        if kind == 'http'
          req = opts[:request_path].to_s
          res = opts[:response_path].to_s
          [req, res].each do |path|
            raise ArgumentError, 'request_path and response_path must be existing readable absolute files' unless path.start_with?('/') && File.file?(path) && File.readable?(path)
          end
          [[req, res], "#{File.read(req)}\n#{File.read(res)}"]
        else
          log = opts[:execution_log].to_s
          raise ArgumentError, 'execution_log must be an existing readable absolute file' unless log.start_with?('/') && File.file?(log) && File.readable?(log)

          [[log], File.read(log)]
        end
      end

      private_class_method def self.rewrite_row(opts = {})
        id = opts[:id].to_s
        patch = opts[:patch] || {}
        rows = report
        idx = rows.index { |row| row[:id].to_s == id }
        raise ArgumentError, 'id must name an existing finding' unless idx

        rows[idx] = rows[idx].merge(patch)
        FileUtils.mkdir_p(File.dirname(FILE))
        File.open(FILE, File::RDWR | File::CREAT, 0o644) do |file|
          file.flock(File::LOCK_EX)
          file.rewind
          file.truncate(0)
          rows.each { |row| file.puts(JSON.generate(row)) }
        end
        rows[idx]
      end

      private_class_method def self.evidence_anchor(opts = {})
        row = opts[:row]
        arts = Array(opts[:arts])
        eng = (row[:engagement_id] || 'default').to_s
        dir = File.join(Dir.home, '.pwn', 'engagements', eng)
        FileUtils.mkdir_p(dir)
        path = File.join(dir, 'evidence.jsonl')
        arts.each do |art|
          next unless File.file?(art.to_s)

          rec = {
            ts: Time.now.utc.iso8601,
            finding_id: row[:id],
            path: art,
            sha256: Digest::SHA256.file(art).hexdigest,
            size: File.size(art)
          }
          dest = File.join(dir, 'evidence', rec[:sha256])
          FileUtils.mkdir_p(File.dirname(dest))
          FileUtils.cp(art, dest) unless File.file?(dest)
          rec[:stored] = dest
          File.open(path, 'a') { |file| file.puts(JSON.generate(rec)) }
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Strict structured finding boundary; accepted input is not execution proof.
          #{self}.record_structured(
            title: 'required - finding title',
            cwe: 'required - CWE identifier',
            cvss_vector: 'required - complete CVSS 3.0/3.1 base vector',
            cvss_score: 'required - numeric score matching vector',
            affected_asset: 'required - recon asset ID or asset identifier',
            evidence_paths: 'required - existing readable absolute paths',
            poc: 'required - command or code string',
            attack_chain_refs: 'required - Array of existing same-engagement finding IDs',
            remediation: 'required - remediation instructions',
            confidence: 'required - numeric 0..1',
            engagement_id: 'optional - simple engagement identifier',
            session_id: 'optional - session identifier',
            target: 'optional - alias for affected_asset',
            repro_cmd: 'optional - alias for poc'
          )

          # Append a legacy finding row to ~/.pwn/findings.jsonl.
          #{self}.record(
            title: 'required - short finding title',
            severity: 'optional - info|low|medium|high|critical (defaults to info)',
            host: 'optional - affected host or URL',
            evidence: 'optional - proof text or path',
            poc: 'optional - filesystem path of a PoC or Hash with type/path/reproduction_steps',
            poc_artifacts: 'required - Array of artifact paths proving the issue',
            cvss: 'optional - CVSS vector or score string',
            cvss_vector: 'optional - CVSS 3.1 vector string (defaults to cvss)',
            affected_asset: 'optional - host or URL the finding applies to (defaults to host)',
            reproduction_steps: 'optional - how to replay the PoC',
            chain_refs: 'optional - Array of related finding ids',
            status: 'optional - open|closed (defaults to open)',
            engagement_id: 'optional - engagement identifier',
            session_id: 'optional - pwn-ai session id',
            chain_parent_id: 'optional - id of a parent finding this issue chains from'
          )

          # Alias of report for querying stored findings.
          #{self}.query(
            host: 'optional - affected host or URL'
          )

          # Record a child finding chained to a parent and return composite severity.
          #{self}.chain(
            parent_id: 'required - id of the parent finding',
            title: 'required - short finding title',
            severity: 'optional - info|low|medium|high|critical (defaults to info)',
            poc_artifacts: 'required - Array of artifact paths proving the issue',
            host: 'optional - affected host or URL',
            session_id: 'optional - pwn-ai session id'
          )

          # List recorded findings, optionally filtered by host.
          #{self}.report(
            host: 'optional - only rows whose host matches this string'
          )

          # Render findings as markdown, html, json, and SARIF reports.
          #{self}.render(
            dir_path: 'optional - output directory (defaults to ~/.pwn/exports)',
            report_name: 'optional - basename without extension (defaults to findings)'
          )

          # Re-hash evidence files and report tampering.
          #{self}.evidence_verify(
            engagement_id: 'optional - engagement name (defaults to default)',
            name: 'optional - alias for engagement_id'
          )

          # Recompute combined severity for chained findings.
          #{self}.chain_score(
            ids: 'optional - Array of finding ids to score together',
            chain_refs: 'optional - alias for ids'
          )

          # Attest a working PoC from HTTP or script evidence; hashes are not execution.
          #{self}.verify(
            id: 'required - finding id',
            kind: 'required - http or script',
            impact: 'required - marker that must appear in the evidence',
            request_path: 'optional - absolute HTTP request file when kind is http',
            response_path: 'optional - absolute HTTP response file when kind is http',
            execution_log: 'optional - absolute script output file when kind is script'
          )

          # Re-run the same PoC path after a fix (still_open or fixed).
          #{self}.retest(
            id: 'required - finding id',
            kind: 'required - http or script',
            impact: 'required - marker that must appear in the evidence',
            request_path: 'optional - absolute HTTP request file when kind is http',
            response_path: 'optional - absolute HTTP response file when kind is http',
            execution_log: 'optional - absolute script output file when kind is script'
          )

          # Escalate combined severity only with an evidence file that names every id.
          #{self}.chain_impact(
            ids: 'required - Array of at least two finding ids',
            combined_impact_path: 'required - absolute evidence file',
            escalate: 'optional - true to set combined_severity from evidence',
            combined_severity: 'optional - info|low|medium|high|critical when escalate is true'
          )

          # List unreproduced findings and whether two-plus reproduced rows lack a chain.
          #{self}.issue_work_gaps(
            engagement_id: 'optional - engagement identifier',
            session_id: 'optional - pwn-ai session id'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
