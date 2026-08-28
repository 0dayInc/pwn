# frozen_string_literal: true

module PWN
  module Reports
    # Generic HTML report writer for pentest / findings payloads.
    module HTML
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'html'))
        payload = PWN::Reports.report_payload(opts)
        rows = payload[:findings].map do |row|
          "<tr><td>#{h(text: row['id'])}</td><td>#{h(text: row['title'])}</td><td>#{h(text: row['severity'])}</td><td>#{h(text: row['cvss'])}</td><td>#{h(text: row['description'])}</td><td>#{h(text: row['poc'])}</td><td>#{h(text: row['recommendation'])}</td></tr>"
        end
        body = <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <title>#{h(text: payload[:title])}</title>
          </head>
          <body>
            <h1>#{h(text: payload[:title])}</h1>
            #{summary_html(text: payload[:executive_summary])}
            <table>
              <thead>
                <tr><th>id</th><th>title</th><th>severity</th><th>cvss</th><th>description</th><th>poc</th><th>recommendation</th></tr>
              </thead>
              <tbody>
                #{rows.join("\n")}
              </tbody>
            </table>
          </body>
          </html>
        HTML
        File.write(out, body)
        out
      end

      private_class_method def self.summary_html(opts = {})
        text = opts[:text].to_s
        return if text.empty?

        "<p>#{h(text: text)}</p>"
      end

      private_class_method def self.h(opts = {})
        opts[:text].to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;').gsub('"', '&quot;')
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:\n  #{self}.generate(\n    path: '/tmp/report.html',\n    results_hash: {}\n  )\n\n  #{self}.authors\n"
      end
    end
  end
end
