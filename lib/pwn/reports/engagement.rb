# frozen_string_literal: true

require 'json'

module PWN
  module Reports
    # Compile engagement findings into a client-ready HTML/Markdown report.
    module Engagement
      public_class_method def self.render(opts = {})
        out = generate(opts)
        fmt = (opts[:format] || 'md').to_s
        case fmt
        when 'html' then { path: out[:html], format: fmt }
        when 'json' then { path: out[:json], format: fmt }
        else { path: out[:markdown], format: 'md', all: out }
        end
      end

      public_class_method def self.generate(opts = {})
        name = (opts[:engagement] || opts[:name] || 'default').to_s
        rows = if opts[:findings]
                 Array(opts[:findings]).select do |row|
                   engagement = (row[:engagement_id] || row['engagement_id']).to_s
                   engagement.empty? || engagement == name
                 end
               elsif defined?(PWN::Plugins::Findings)
                 rows = PWN::Plugins::Findings.report
                 rows.select do |row|
                   engagement = (row[:engagement_id] || row['engagement_id']).to_s
                   engagement == name || (name == 'default' && engagement.empty?)
                 end
               else
                 []
               end
        rows = rows.sort_by { |r| -severity_rank(row: r) }
        payload = {
          title: "Engagement #{name}",
          findings: rows,
          summary: { count: rows.length, critical: rows.count { |r| r[:severity].to_s == 'critical' || r['severity'].to_s == 'critical' } }
        }
        dir = opts[:dir_path].to_s
        dir = File.join(Dir.home, '.pwn', 'exports') if dir.empty?
        report_name = (opts[:report_name] || "engagement-#{name}").to_s
        {
          markdown: PWN::Reports::Markdown.generate(results_hash: payload, dir_path: dir, report_name: report_name),
          html: PWN::Reports::HTML.generate(results_hash: payload, dir_path: dir, report_name: report_name),
          json: PWN::Reports::JSON.generate(results_hash: payload, dir_path: dir, report_name: report_name)
        }
      end

      private_class_method def self.severity_rank(opts = {})
        row = opts[:row]
        row = {} unless row.is_a?(Hash)
        sev = (row[:severity] || row['severity']).to_s
        { 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1 }[sev] || 0
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Compile findings into markdown, html, and json.
          #{self}.generate(
            engagement: 'optional - engagement name (defaults to default)',
            name: 'optional - alias for engagement',
            findings: 'optional - Array of finding hashes (defaults to Findings.report)',
            dir_path: 'optional - output directory',
            report_name: 'optional - basename without extension'
          )

          # Render one format (md|html|json) for a session/engagement.
          #{self}.render(
            session_id: 'optional - pwn-ai session id',
            format: 'optional - md, html, or json (defaults to md)',
            engagement: 'optional - engagement name',
            dir_path: 'optional - output directory',
            report_name: 'optional - basename without extension'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
