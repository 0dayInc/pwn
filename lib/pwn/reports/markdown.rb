# frozen_string_literal: true

module PWN
  module Reports
    # Generic Markdown report writer for pentest / findings payloads.
    module Markdown
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'md'))
        payload = PWN::Reports.package_evidence(payload: PWN::Reports.report_payload(opts), path: out)
        lines = ["# #{escape(text: payload[:title])}", '']
        lines += ['## Executive summary', '', escape(text: payload[:executive_summary]), ''] unless payload[:executive_summary].to_s.empty?
        lines += ['## Ranked priorities', '']
        Array(payload[:priorities]).each_with_index do |priority, index|
          lines << "#{index + 1}. **#{escape(text: priority[:combined_severity])}** — #{escape(text: priority[:title])} (#{escape(text: priority[:kind])}). #{escape(text: priority[:rationale])}"
        end
        lines += ['', '## Attack chains', '']
        payload[:attack_chains].each do |chain|
          lines += ["### #{escape(text: chain[:title])}", '',
                    "Directed path: #{escape(text: chain[:finding_ids].join(' -> '))}", '',
                    "Combined severity: **#{escape(text: chain[:combined_severity])}**; Assessment: #{escape(text: chain[:assessment_status])}", '',
                    escape(text: chain[:rationale]), '', '#### Directed links', '']
          Array(chain[:links]).each { |link| lines << "- #{escape(text: "#{link[:from]} -> #{link[:to]}")}" }
          lines += ['', '#### PoC reproduction steps', '']
          Array(chain[:reproduction_steps]).each_with_index { |step, index| lines << "#{index + 1}. #{escape(text: step)}" }
          lines += ['', '#### Evidence', '']
          Array(chain[:evidence_artifacts]).each do |artifact|
            artifact = artifact.transform_keys(&:to_s)
            label = escape(text: artifact['label'])
            lines << (artifact['attachment'] ? "[#{label}](#{artifact['attachment']})" : label)
            lines << "- Kind: #{escape(text: artifact['kind'])}; Handle: #{escape(text: artifact['handle'])}; SHA-256: #{escape(text: artifact['sha256'])}; Size: #{escape(text: artifact['size'])} bytes"
          end
          lines << ''
        end
        lines += ['## Findings', '']
        if payload[:findings].empty?
          lines << '_No findings._'
        else
          payload[:findings].each do |row|
            lines << "### #{escape(text: row['id'].to_s.empty? ? row['title'] : "#{row['id']}: #{row['title']}")}"
            lines << ''
            row.each do |key, val|
              next if %w[id title reproduction_steps severity_justification poc evidence_artifacts poc_export].include?(key.to_s)

              lines << "- **#{escape(text: key)}**: #{escape(text: val)}"
            end
            lines += ['', '#### Reproduction steps', '']
            steps = Array(row['reproduction_steps'])
            lines += steps.empty? ? ['Not supplied'] : steps.each_with_index.map { |step, index| "#{index + 1}. #{escape(text: step)}" }
            justification = row['severity_justification'].to_s
            lines += ['', '#### Severity justification', '', justification.empty? ? 'Not supplied' : escape(text: justification)]
            code = PWN::Reports.poc_preview(text: row['poc'])
            fence = '`' * [3, (code.scan(/`+/).map(&:length).max || 0) + 1].max
            lines += ['', '#### PoC command/code', '', fence, code.empty? ? 'Not supplied' : code, fence]
            lines += ['', '#### Evidence', '']
            (Array(row['evidence_artifacts']) + [row['poc_export']].compact).each do |artifact|
              label = escape(text: artifact['label'])
              link = "[#{label}](#{artifact['attachment']})"
              lines << "#{'!' if artifact['inline_image']}#{link}"
              lines << "- Kind: #{escape(text: artifact['kind'])}; Handle: #{escape(text: artifact['handle'])}; SHA-256: #{artifact['sha256']}; Size: #{artifact['size']} bytes"
            end
            lines << ''
          end
        end

        File.write(out, "#{lines.join("\n").rstrip}\n")
        out
      end

      private_class_method def self.escape(opts = {})
        opts[:text].to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;')
                   .gsub(/[\\`*_{}\[\]()#+.!|~-]/) { |char| "\\#{char}" }.gsub(/\r?\n/, ' ')
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
