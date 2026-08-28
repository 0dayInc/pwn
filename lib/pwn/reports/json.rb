# frozen_string_literal: true

require 'json'

module PWN
  module Reports
    # Generic JSON report writer for pentest / findings payloads.
    module JSON
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'json'))
        payload = PWN::Reports.report_payload(opts)
        File.write(
          out,
          ::JSON.pretty_generate(
            'title' => payload[:title],
            'executive_summary' => payload[:executive_summary],
            'findings' => payload[:findings]
          )
        )
        out
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:\n  #{self}.generate(\n    path: '/tmp/report.json',\n    results_hash: {}\n  )\n\n  #{self}.authors\n"
      end
    end
  end
end
