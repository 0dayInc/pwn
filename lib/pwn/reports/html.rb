# frozen_string_literal: true

module PWN
  module Reports
    # Generic HTML report writer for pentest / findings payloads.
    module HTML
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'html'))
        payload = PWN::Reports.package_evidence(payload: PWN::Reports.report_payload(opts), path: out)
        rows = Array(payload[:priorities]).each_with_index.map do |priority, index|
          "<tr><td>#{index + 1}</td><td>#{h(text: priority[:title])}</td><td>#{h(text: priority[:combined_severity])}</td><td>#{h(text: priority[:kind])}</td><td>#{h(text: priority[:rationale])}</td></tr>"
        end
        details = payload[:findings].map do |row|
          fields = row.except('reproduction_steps', 'severity_justification', 'poc', 'evidence_artifacts', 'poc_export')
                      .map { |key, value| "<dt>#{h(text: key)}</dt><dd>#{h(text: value)}</dd>" }.join
          steps = Array(row['reproduction_steps']).map { |step| "<li>#{h(text: step)}</li>" }.join
          steps = steps.empty? ? '<p>Not supplied</p>' : "<ol>#{steps}</ol>"
          justification = row['severity_justification'].to_s
          code = PWN::Reports.poc_preview(text: row['poc'])
          evidence = (Array(row['evidence_artifacts']) + [row['poc_export']].compact).map do |artifact|
            link = "<a download href=\"#{h(text: artifact['attachment'])}\">#{h(text: artifact['label'])}</a>"
            image = artifact['inline_image'] ? "<img src=\"#{h(text: artifact['attachment'])}\" alt=\"#{h(text: artifact['label'])}\">" : ''
            "<li>#{link}#{image}<p>Kind: #{h(text: artifact['kind'])}; Handle: #{h(text: artifact['handle'])}; SHA-256: #{h(text: artifact['sha256'])}; Size: #{h(text: artifact['size'])} bytes</p></li>"
          end.join
          "<section><h2>#{h(text: row['title'])}</h2><dl>#{fields}</dl><h3>Reproduction steps</h3>#{steps}<h3>Severity justification</h3><p>#{h(text: justification.empty? ? 'Not supplied' : justification)}</p><h3>PoC command/code</h3><pre><code>#{h(text: code.empty? ? 'Not supplied' : code)}</code></pre><h3>Evidence</h3><ul>#{evidence}</ul></section>"
        end.join
        chains = payload[:attack_chains].map do |chain|
          steps = Array(chain[:reproduction_steps]).map { |step| "<li>#{h(text: step)}</li>" }.join
          links = Array(chain[:links]).map { |link| "<li>#{h(text: link[:from])} -&gt; #{h(text: link[:to])}</li>" }.join
          evidence = Array(chain[:evidence_artifacts]).map do |artifact|
            artifact = artifact.transform_keys(&:to_s)
            label = h(text: artifact['label'])
            label = "<a download href=\"#{h(text: artifact['attachment'])}\">#{label}</a>" if artifact['attachment']
            "<li>#{label}; Kind: #{h(text: artifact['kind'])}; Handle: #{h(text: artifact['handle'])}; SHA-256: #{h(text: artifact['sha256'])}; Size: #{h(text: artifact['size'])} bytes</li>"
          end.join
          "<section><h3>#{h(text: chain[:title])}</h3><p>Directed path: #{h(text: chain[:finding_ids].join(' -> '))}</p><p>Combined severity: #{h(text: chain[:combined_severity])}; Assessment: #{h(text: chain[:assessment_status])}</p><p>#{h(text: chain[:rationale])}</p><h4>Directed links</h4><ul>#{links}</ul><h4>PoC reproduction steps</h4><ol>#{steps}</ol><h4>Evidence</h4><ul>#{evidence}</ul></section>"
        end.join
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
            <h2>Ranked priorities</h2>
            <table>
              <thead>
                <tr><th>rank</th><th>title</th><th>severity</th><th>kind</th><th>rationale</th></tr>
              </thead>
              <tbody>
                #{rows.join("\n")}
              </tbody>
            </table>
            <h2>Attack chains</h2>#{chains}
            <h2>Finding technical details</h2>#{details}
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
