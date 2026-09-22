# frozen_string_literal: true

require 'json'
require 'open3'
require 'fileutils'
require 'tempfile'
require 'securerandom'
require 'tmpdir'
require 'uri'

module PWN
  module Plugins
    # nuclei wrapper: template/severity, JSONL findings into the findings store.
    module Nuclei
      TECH_TAGS = {
        'wordpress' => %w[wordpress wp],
        'wp' => %w[wordpress],
        'nginx' => %w[nginx],
        'apache' => %w[apache],
        'php' => %w[php],
        'tomcat' => %w[tomcat java],
        'spring' => %w[springboot java],
        'iis' => %w[iis],
        'jquery' => %w[jquery],
        'react' => %w[react],
        'django' => %w[django python],
        'laravel' => %w[laravel php],
        'drupal' => %w[drupal],
        'joomla' => %w[joomla]
      }.freeze

      public_class_method def self.required_bins
        %w[nuclei]
      end

      public_class_method def self.select_templates(opts = {})
        techs = Array(opts[:techs] || opts[:tech] || opts[:stack]).map { |item| item.to_s.downcase }
        tags = techs.flat_map { |tech| TECH_TAGS[tech] || [tech.gsub(/[^a-z0-9]+/, '-')] }.uniq
        tags = %w[http] if tags.empty?
        { tags: tags, techs: techs, flag: tags.join(',') }
      end

      public_class_method def self.scan(opts = {})
        handoff = PWN::Plugins::Recon.handoff(handoff: opts[:handoff] || opts[:asset]) if opts[:handoff] || opts[:asset]
        target = handoff && !handoff[:host].empty? ? handoff[:host] : (opts[:target] || opts[:url])
        stdout = jsonl_body(opts)
        opts = opts.merge(techs: PWN::Plugins::Httpx.probe(jsonl: opts[:httpx_jsonl])[:techs]) if stdout.nil? && !opts[:httpx_jsonl].to_s.empty?
        unless stdout
          skipped = skip_known(target: target, port: handoff && handoff[:port], refresh: opts[:refresh], engagement_id: opts[:engagement_id])
          return skipped if skipped

          PWN::Plugins::PreflightChecker.require_bin!(name: 'nuclei')
          raise 'ERROR: target is required' if target.to_s.empty?

          cmd = ['nuclei', '-u', target.to_s, '-jsonl', '-silent']
          cmd += ['-severity', opts[:severity].to_s] if opts[:severity]
          cmd += ['-t', opts[:templates].to_s] if opts[:templates]
          if opts[:tags] || opts[:techs]
            selected = select_templates(techs: opts[:techs] || opts[:tags])
            cmd += ['-tags', selected[:flag]]
          end
          cmd += ['-rate-limit', opts[:rate_limit].to_s] if opts[:rate_limit]
          stdout, stderr, status = capture(cmd: cmd)
        end
        findings = parse_jsonl(text: stdout)
        rows = to_findings(rows: findings)
        recorded = []
        recorded = rows.map { |row| persist_observation(finding: row, dir: opts[:dir], engagement_id: opts[:engagement_id]) } if opts[:record] != false
        { findings: rows, raw: findings, recorded: recorded, stderr: stderr, exit: status&.exitstatus }
      end

      public_class_method def self.to_findings(opts = {})
        Array(opts[:rows] || opts[:findings]).map do |row|
          row = row.transform_keys(&:to_s) if row.is_a?(Hash)
          info = row['info'] || {}
          info = info.transform_keys(&:to_s) if info.is_a?(Hash)
          {
            title: info['name'] || row['template-id'] || 'nuclei finding',
            severity: (info['severity'] || 'info').to_s,
            url: row['matched-at'] || row['host'],
            matched_at: row['matched-at'] || row['host'],
            template_id: row['template-id'] || row['template_id'],
            template: row['template-id'] || row['template_id'],
            description: info['description']
          }
        end
      end

      public_class_method def self.to_defectdojo(opts = {})
        to_findings(opts).map do |finding|
          { title: finding[:title], severity: finding[:severity], description: "#{finding[:url]} #{finding[:template_id]}".strip }
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Map detected product names to nuclei -tags values.
          #{self}.select_templates(
            techs: 'optional - Array of httpx tech/product names',
            tech: 'optional - alias for techs',
            stack: 'optional - alias for techs'
          )

          # Run nuclei or ingest existing JSONL; records findings unless record: false.
          #{self}.scan(
            target: 'optional - hostname, IP, or URL (required unless jsonl is set)',
            url: 'optional - HTTP(S) URL alias for target',
            jsonl: 'optional - nuclei JSONL file path or raw JSONL text (skips the nuclei binary)',
            httpx_jsonl: 'optional - httpx JSONL used to select -tags from detected tech',
            record: 'optional - false skips the recon observation (defaults to true); a template match is not a finding',
            refresh: 'optional - true rescans a port that already has an observation',
            handoff: 'optional - recon asset hash with host, port, product, version, and evidence_path',
            asset: 'optional - alias for handoff',
            engagement_id: 'optional - engagement identifier for stored observations',
            severity: 'optional - nuclei -severity filter',
            templates: 'optional - nuclei -t template path or id',
            tags: 'optional - tech names forwarded to select_templates',
            techs: 'optional - alias for tags',
            rate_limit: 'optional - requests per second passed to nuclei -rate-limit',
            dir: 'optional - directory for PoC JSONL artifacts'
          )

          # Map nuclei JSONL rows into report-shaped finding hashes.
          #{self}.to_findings(
            rows: 'optional - Array of parsed nuclei JSONL objects',
            findings: 'optional - alias for rows'
          )

          # Shape findings for a DefectDojo import payload.
          #{self}.to_defectdojo(
            rows: 'optional - Array of parsed nuclei JSONL objects',
            findings: 'optional - alias for rows'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.jsonl_body(opts = {})
        src = opts[:jsonl]
        return nil if src.nil?

        File.file?(src.to_s) ? File.read(src) : src.to_s
      end

      private_class_method def self.parse_jsonl(opts = {})
        opts[:text].to_s.each_line.filter_map do |line|
          JSON.parse(line)
        rescue JSON::ParserError
          nil
        end
      end

      private_class_method def self.capture(opts = {})
        Open3.capture3(*opts[:cmd])
      rescue Errno::ENOENT
        stdout, status = Open3.capture2(*opts[:cmd])
        [stdout, '', status]
      end

      private_class_method def self.persist_observation(opts = {})
        finding = opts[:finding]
        dir = opts[:dir].to_s
        dir = Dir.tmpdir if dir.empty?
        FileUtils.mkdir_p(dir)
        poc = File.join(dir, "nuclei-#{finding[:template_id].to_s.gsub(/[^A-Za-z0-9._-]/, '_')}-#{SecureRandom.hex(4)}.json")
        File.write(poc, JSON.pretty_generate(finding))
        uri = URI.parse(finding[:url].to_s)
        PWN::Plugins::Recon.observe(
          host: uri.host || finding[:url].to_s,
          port: uri.port,
          product: finding[:template_id].to_s,
          version: '',
          evidence_path: poc,
          source: 'nuclei',
          lead: finding[:title],
          engagement_id: opts[:engagement_id]
        )
      rescue URI::InvalidURIError
        PWN::Plugins::Recon.observe(host: finding[:url].to_s, product: finding[:template_id].to_s, evidence_path: poc, source: 'nuclei', lead: finding[:title], engagement_id: opts[:engagement_id])
      end

      private_class_method def self.skip_known(opts = {})
        return nil if opts[:refresh]
        return nil if opts[:target].to_s.empty? || opts[:port].nil?

        known = PWN::Plugins::Recon.known_ports(host: opts[:target], engagement_id: opts[:engagement_id])
        return nil unless known.include?(opts[:port].to_i)

        { findings: [], recorded: [], skipped: true, skipped_ports: [opts[:port].to_i], reason: 'existing observation' }
      end
    end
  end
end
