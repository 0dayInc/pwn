# frozen_string_literal: true

module PWN
  module Reports
    # Generic Markdown report writer for pentest / findings payloads.
    module Markdown
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'md'))
        payload = PWN::Reports.report_payload(opts)
        lines = ["# #{payload[:title]}", '']
        lines += ['## Executive summary', '', payload[:executive_summary].to_s, ''] unless payload[:executive_summary].to_s.empty?
        lines += ['## Findings', '']
        if payload[:findings].empty?
          lines << '_No findings._'
        else
          payload[:findings].each do |row|
            lines << "### #{row['id'].to_s.empty? ? row['title'] : "#{row['id']}: #{row['title']}"}"
            lines << ''
            row.each do |key, val|
              next if %w[id title].include?(key.to_s)

              lines << "- **#{key}**: #{val}"
            end
            lines << ''
          end
        end
        File.write(out, "#{lines.join("\n").rstrip}\n")
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
