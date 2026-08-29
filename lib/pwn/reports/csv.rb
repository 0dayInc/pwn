# frozen_string_literal: true

require 'csv'

module PWN
  module Reports
    # Generic CSV report writer for pentest / findings payloads.
    module CSV
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'csv'))
        payload = PWN::Reports.report_payload(opts)
        rows = payload[:findings]
        headers = %w[id title severity cvss epss description poc impact recommendation]
        extra = rows.flat_map(&:keys).uniq - headers
        cols = (headers + extra).uniq
        ::CSV.open(out, 'w') do |csv|
          csv << cols
          if rows.empty?
            csv << cols.map { |col| col == 'title' ? payload[:title] : nil }
          else
            rows.each do |row|
              csv << cols.map { |col| row[col] }
            end
          end
        end
        out
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Run generate and return its result
          #{self}.generate

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
