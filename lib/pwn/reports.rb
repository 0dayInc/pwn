# frozen_string_literal: true

require 'fileutils'
require 'digest'

module PWN
  # This file, using the autoload directive loads Report modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Reports
    autoload :AIRedTeam, 'pwn/reports/ai_red_team'
    autoload :CSV, 'pwn/reports/csv'
    autoload :Engagement, 'pwn/reports/engagement'
    autoload :Fuzz, 'pwn/reports/fuzz'
    autoload :HTML, 'pwn/reports/html'
    autoload :HTMLFooter, 'pwn/reports/html_footer'
    autoload :HTMLHeader, 'pwn/reports/html_header'
    autoload :JSON, 'pwn/reports/json'
    autoload :Markdown, 'pwn/reports/markdown'
    autoload :PDF, 'pwn/reports/pdf'
    autoload :Phone, 'pwn/reports/phone'
    autoload :SAST, 'pwn/reports/sast'
    autoload :SARIF, 'pwn/reports/sarif'
    autoload :URIBuster, 'pwn/reports/uri_buster'
    autoload :XML, 'pwn/reports/xml'

    public_class_method def self.resolve_path(opts = {})
      path = opts[:path].to_s
      ext = opts[:ext].to_s.sub(/\A\./, '')
      unless path.empty?
        FileUtils.mkdir_p(File.dirname(path)) unless File.dirname(path).to_s.empty? || File.dirname(path) == '.'
        return path
      end

      dir = opts[:dir_path].to_s
      dir = '.' if dir.empty?
      FileUtils.mkdir_p(dir)
      name = opts[:report_name].to_s
      name = File.basename(Dir.pwd) if name.empty?
      File.join(dir, "#{name}.#{ext}")
    end

    public_class_method def self.report_payload(opts = {})
      raw = opts[:results_hash]
      raw = {} unless raw.is_a?(Hash)
      title = (
        opts[:title] ||
        raw[:title] || raw['title'] ||
        raw[:report_name] || raw['report_name'] ||
        'PWN Report'
      ).to_s
      summary = (
        opts[:executive_summary] ||
        raw[:executive_summary] || raw['executive_summary']
      ).to_s
      findings = raw[:findings] || raw['findings'] || raw[:data] || raw['data'] || []
      findings = [] unless findings.is_a?(Array)
      findings = findings.map { |row| stringify_keys(hash: row) }
      chains = attack_chains(findings: findings)
      refuse_unproven_combined!(findings: findings, chains: chains)
      {
        title: title,
        executive_summary: summary,
        findings: findings,
        attack_chains: chains,
        priorities: rank_priorities(findings: findings, chains: chains),
        raw: raw
      }
    end

    # Directed maximal paths; only scoped, evidenced impact can override member severity.
    public_class_method def self.attack_chains(opts = {})
      rows = Array(opts[:findings]).map { |row| stringify_keys(hash: row) }
      identified = rows.reject { |row| row['id'].to_s.empty? }
      by_id = identified.to_h { |row| [row['id'].to_s, row] }
      raise ArgumentError, 'duplicate finding IDs in attack graph' unless by_id.length == identified.length

      adjacency = by_id.keys.to_h { |id| [id, []] }
      by_id.each do |id, row|
        legacy = %w[attack_chain_refs chain_refs chain_parent_id].flat_map { |key| Array(row[key]) }
        edges = Array(row['enables']).map { |target| [id, target.to_s] } + legacy.map { |source| [source.to_s, id] }
        edges.each do |source, target|
          next unless by_id.key?(source) && by_id.key?(target)

          engagements = [source, target].map { |key| by_id[key]['engagement_id'].to_s }.map { |value| value.empty? ? 'default' : value }
          next unless engagements.uniq.length == 1

          raise ArgumentError, 'cycle in attack graph' if source == target

          adjacency[source] << target unless adjacency[source].include?(target)
        end
      end
      incoming = by_id.keys.to_h { |id| [id, 0] }
      adjacency.each_value { |targets| targets.each { |target| incoming[target] += 1 } }
      roots = incoming.select { |_id, count| count.zero? }.keys.sort
      pending = roots.dup
      visited = 0
      until pending.empty?
        source = pending.shift
        visited += 1
        adjacency[source].each do |target|
          incoming[target] -= 1
          pending << target if incoming[target].zero?
        end
      end
      raise ArgumentError, 'cycle in attack graph' unless visited == by_id.length

      paths = []
      pending = roots.select { |id| adjacency[id].any? }.map { |id| [id] }
      until pending.empty?
        path = pending.pop
        targets = adjacency[path.last]
        if targets.empty?
          paths << assess_path(path: path, by_id: by_id) if path.length > 1
        else
          targets.sort.reverse_each { |target| pending << (path + [target]) }
        end
        raise ArgumentError, 'attack graph exceeds 1000 reportable paths' if paths.length > 1000 || pending.length > 1000
      end
      paths.sort_by { |path| [-impact_rank(severity: path[:combined_severity]), path[:finding_ids]] }
    end

    private_class_method def self.assess_path(opts = {})
      path = opts[:path]
      by_id = opts[:by_id]
      assessment = Array(by_id[path.last]['chain_assessments']).reverse.find { |item| item['finding_ids'] == path }
      severity = path.map { |id| by_id[id]['severity'].to_s }.max_by { |value| impact_rank(severity: value) }
      result = { finding_ids: path, title: path.map { |id| by_id[id]['title'].to_s.empty? ? id : by_id[id]['title'].to_s }.join(' -> '),
                 combined_severity: severity, assessment_status: 'unassessed',
                 rationale: 'Maximum recorded constituent severity. No automatic escalation; linking is not proof of combined exploitability.',
                 links: path.each_cons(2).map { |source, target| { from: source, to: target } }, evidence_artifacts: [],
                 reproduction_steps: path.flat_map { |id| Array(by_id[id]['reproduction_steps']) } }
      return result unless assessment

      evidence = Array(assessment['evidence_artifacts'])
      raise ArgumentError, 'chain assessment needs severity, rationale and evidence' if impact_rank(severity: assessment['combined_severity']).negative? || assessment['rationale'].to_s.strip.empty? || evidence.empty?

      evidence.each do |artifact|
        stored = artifact['stored'].to_s
        sha = artifact['sha256'].to_s
        size = artifact['size']
        raise IOError, 'chain evidence integrity mismatch or missing durable copy' unless sha.match?(/\A[0-9a-f]{64}\z/) && size.is_a?(Integer) && File.file?(stored) && File.size(stored) == size && Digest::SHA256.file(stored).hexdigest == sha
      end
      result.merge(combined_severity: assessment['combined_severity'], rationale: assessment['rationale'], assessment_status: 'evidence_backed',
                   evidence_artifacts: evidence.map { |artifact| artifact.transform_keys(&:to_sym) },
                   reproduction_steps: assessment['reproduction_steps'] || result[:reproduction_steps])
    end

    private_class_method def self.refuse_unproven_combined!(opts = {})
      findings = Array(opts[:findings])
      Array(opts[:chains]).each do |chain|
        next unless %w[high critical].include?(chain[:combined_severity].to_s)
        next if Array(chain[:finding_ids]).length < 2

        members = chain[:finding_ids].map { |id| findings.find { |row| row['id'].to_s == id } }
        raise ArgumentError, 'refusing to print high or critical for an unverified linked pair' unless members.all? { |row| row && row['verification_status'].to_s == 'reproduced' }

        text = Array(chain[:evidence_artifacts]).map { |artifact| File.file?(artifact[:stored].to_s) ? File.read(artifact[:stored]) : '' }.join
        raise ArgumentError, 'combined-impact file must name every finding id' unless chain[:finding_ids].all? { |id| text.include?(id.to_s) }
      end
    end

    private_class_method def self.impact_rank(opts = {})
      %w[info low medium high critical].index(opts[:severity].to_s) || -1
    end

    private_class_method def self.rank_priorities(opts = {})
      chains = Array(opts[:chains])
      linked = chains.flat_map { |chain| chain[:finding_ids] }
      singles = Array(opts[:findings]).reject { |row| linked.include?(row['id'].to_s) }.map do |row|
        { kind: 'finding', finding_ids: [row['id'].to_s], combined_severity: row['severity'].to_s,
          title: row['title'].to_s, rationale: row['severity_justification'].to_s }
      end
      (chains.map { |chain| chain.merge(kind: 'chain') } + singles).sort_by do |item|
        [-impact_rank(severity: item[:combined_severity]), item[:finding_ids], item[:title]]
      end
    end

    private_class_method def self.stringify_keys(opts = {})
      hash = opts[:hash]
      return { 'value' => hash.to_s } unless hash.is_a?(Hash)

      hash.each_with_object({}) do |(key, val), acc|
        acc[key.to_s] = case val
                        when Hash then stringify_keys(hash: val)
                        when Array then val.map { |item| item.is_a?(Hash) ? stringify_keys(hash: item) : item }
                        else val
                        end
      end
    end

    # Package verified bytes, never source filenames or caller-provided URLs.
    public_class_method def self.package_evidence(opts = {})
      payload = opts[:payload]
      directory = File.join(File.dirname(File.expand_path(opts[:path])), 'attachments')
      chains = Array(payload[:attack_chains])
      chain_rows = chains.map { |chain| { 'evidence_artifacts' => Array(chain[:evidence_artifacts]).map { |artifact| stringify_keys(hash: artifact) } } }
      (payload[:findings] + chain_rows).each do |row|
        Array(row['evidence_artifacts']).each do |artifact|
          source = artifact['stored']
          digest = artifact['sha256'].to_s
          size = artifact['size']
          raise ArgumentError, 'Evidence requires full SHA-256 and integer size' unless digest.match?(/\A[a-fA-F0-9]{64}\z/) && size.is_a?(Integer) && size >= 0
          raise IOError, "Evidence missing: #{source}" unless source && File.file?(source)

          bytes = File.binread(source)
          raise IOError, "Evidence integrity mismatch: #{source}" unless bytes.bytesize == size && Digest::SHA256.hexdigest(bytes) == digest.downcase

          extension = { 'pcap' => 'pcap', 'poc' => 'txt', 'crash' => 'bin' }.fetch(artifact['kind'], 'bin')
          artifact.delete('inline_image')
          if artifact['kind'] == 'screenshot'
            extension = if bytes.start_with?("\x89PNG\r\n\x1a\n".b)
                          'png'
                        elsif bytes.start_with?("\xff\xd8\xff".b)
                          'jpg'
                        elsif bytes.start_with?('GIF87a', 'GIF89a')
                          'gif'
                        else
                          'bin'
                        end
            artifact['inline_image'] = true unless extension == 'bin'
          end
          artifact['attachment'] = write_attachment(directory: directory, bytes: bytes, extension: extension)
        end
        row.delete('poc_export')
        code = row['poc'].to_s
        next if code.empty?

        row['poc_export'] = {
          'kind' => 'poc', 'label' => 'Full PoC text (not executed)', 'finding_id' => row['id'],
          'sha256' => Digest::SHA256.hexdigest(code), 'size' => code.bytesize,
          'attachment' => write_attachment(directory: directory, bytes: code, extension: 'txt')
        }
      end
      chains.zip(chain_rows).each do |chain, row|
        chain[:evidence_artifacts] = row['evidence_artifacts'].map { |artifact| artifact.transform_keys(&:to_sym) }
      end
      payload[:priorities] = rank_priorities(findings: payload[:findings], chains: chains)
      payload
    end

    private_class_method def self.write_attachment(opts = {})
      directory = opts[:directory]
      bytes = opts[:bytes]
      digest = Digest::SHA256.hexdigest(bytes)
      relative = "attachments/#{digest}.#{opts[:extension]}"
      FileUtils.mkdir_p(directory)
      raise IOError, 'Evidence attachment directory is a symlink' if File.symlink?(directory)

      target = File.join(directory, File.basename(relative))
      raise IOError, "Evidence attachment is a symlink: #{target}" if File.symlink?(target)

      if File.exist?(target)
        raise IOError, "Evidence attachment integrity mismatch: #{target}" unless File.size(target) == bytes.bytesize && Digest::SHA256.file(target).hexdigest == digest
      else
        File.open(target, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(bytes) }
      end
      relative
    end

    public_class_method def self.poc_preview(opts = {})
      code = opts[:text].to_s
      return 'Not supplied' if code.empty?
      return code if code.length <= 16_384

      "#{code[0, 16_384]}\n[Preview truncated; download full PoC text below.]"
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Run resolve path and return its result
        #{self}.resolve_path(
          path: 'required - filesystem path to read or write',
          ext: 'optional - ext value consumed by #resolve_path',
          dir_path: 'optional - dir path value consumed by #resolve_path',
          report_name: 'optional - report name value consumed by #resolve_path'
        )

        # Verify and copy evidence to portable report-relative attachments; raises on missing or altered bytes.
        #{self}.package_evidence(
          payload: 'required - normalized report payload Hash',
          path: 'required - actual output report path'
        )

        # Bound displayed PoC text; never execute it or read it as a filename.
        #{self}.poc_preview(text: 'optional - PoC text to preview, limited to 16384 characters')

        # Rank directed same-engagement paths using scoped, hash-checked combined-impact assessments.
        #{self}.attack_chains(findings: 'required - Array of finding hashes')

        # Run report payload and return its result
        #{self}.report_payload(
          results_hash: 'optional - results hash value consumed by #report_payload',
          title: 'optional - title value consumed by #report_payload',
          executive_summary: 'optional - executive summary value consumed by #report_payload'
        )

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
      constants.sort
    end
  end
end
