# frozen_string_literal: true

require 'json'

module PWN
  module Reports
    # SARIF 2.1.0 writer for finding export.
    module SARIF
      public_class_method def self.generate(opts = {})
        payload = PWN::Reports.report_payload(opts)
        doc = {
          version: '2.1.0',
          '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
          runs: [
            {
              tool: { driver: { name: 'pwn', version: (defined?(PWN::VERSION) ? PWN::VERSION : '0') } },
              results: Array(payload[:findings]).map { |row| result_row(row: row) }
            }
          ]
        }
        path = PWN::Reports.resolve_path(opts.merge(ext: 'sarif.json'))
        File.write(path, ::JSON.pretty_generate(doc))
        path
      end

      private_class_method def self.result_row(opts = {})
        row = opts[:row]
        row = {} unless row.is_a?(Hash)
        sev = (row['severity'] || row[:severity] || 'note').to_s
        level = { 'critical' => 'error', 'high' => 'error', 'medium' => 'warning', 'low' => 'note', 'info' => 'note' }[sev] || 'note'
        {
          ruleId: (row['id'] || row[:id] || 'finding').to_s,
          level: level,
          message: { text: (row['title'] || row[:title]).to_s },
          properties: row
        }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Write a SARIF 2.1 document from a findings hash.
          #{self}.generate(
            results_hash: 'required - Hash with :findings Array',
            dir_path: 'optional - output directory',
            report_name: 'optional - basename without extension',
            path: 'optional - exact output path'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
