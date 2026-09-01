# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'securerandom'

module PWN
  module Plugins
    # Persistent finding rows for pwn-ai (title, severity, host, evidence, PoC).
    module Findings
      FILE = File.join(Dir.home, '.pwn', 'findings.jsonl')

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.record(opts = {})
        title = opts[:title].to_s
        raise 'ERROR: title is required' if title.empty?

        arts = Array(opts[:poc_artifacts]).map(&:to_s).reject(&:empty?)
        arts << opts[:poc].to_s unless opts[:poc].to_s.empty?
        raise 'ERROR: poc_artifacts are required' if arts.empty?

        row = {
          id: SecureRandom.hex(6),
          title: title,
          severity: (opts[:severity] || 'info').to_s,
          host: opts[:host].to_s,
          evidence: opts[:evidence].to_s,
          poc: opts[:poc].to_s,
          poc_artifacts: arts,
          session_id: opts[:session_id].to_s,
          at: Time.now.utc.iso8601
        }
        FileUtils.mkdir_p(File.dirname(FILE))
        File.open(FILE, 'a') { |f| f.puts(JSON.generate(row)) }
        row
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
        rows
      end

      public_class_method def self.render(opts = {})
        dir = opts[:dir_path].to_s
        dir = File.join(Dir.home, '.pwn', 'exports') if dir.empty?
        name = opts[:report_name].to_s
        name = 'findings' if name.empty?
        payload = { title: 'Findings', findings: report }
        {
          markdown: PWN::Reports::Markdown.generate(results_hash: payload, dir_path: dir, report_name: name),
          html: PWN::Reports::HTML.generate(results_hash: payload, dir_path: dir, report_name: name),
          json: PWN::Reports::JSON.generate(results_hash: payload, dir_path: dir, report_name: name)
        }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Append a finding row to ~/.pwn/findings.jsonl.
          #{self}.record(
            title: 'required - short finding title',
            severity: 'optional - info|low|medium|high|critical (defaults to info)',
            host: 'optional - affected host or URL',
            evidence: 'optional - proof text or path',
            poc: 'optional - filesystem path of a PoC',
            poc_artifacts: 'required - Array of artifact paths proving the issue',
            session_id: 'optional - pwn-ai session id'
          )

          # List recorded findings, optionally filtered by host.
          #{self}.report(
            host: 'optional - only rows whose host matches this string'
          )

          # Render findings as markdown, html, and json reports.
          #{self}.render(
            dir_path: 'optional - output directory (defaults to ~/.pwn/exports)',
            report_name: 'optional - basename without extension (defaults to findings)'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
