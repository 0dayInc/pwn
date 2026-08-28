# frozen_string_literal: true

require 'rexml/document'

module PWN
  module Reports
    # Generic XML report writer for pentest / findings payloads.
    module XML
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'xml'))
        payload = PWN::Reports.report_payload(opts)
        doc = REXML::Document.new
        doc << REXML::XMLDecl.new('1.0', 'UTF-8')
        root = doc.add_element('report')
        root.add_element('title').text = payload[:title]
        root.add_element('executive_summary').text = payload[:executive_summary]
        findings = root.add_element('findings')
        payload[:findings].each do |row|
          node = findings.add_element('finding')
          row.each do |key, val|
            node.add_element(safe_tag(name: key)).text = val.to_s
          end
        end
        File.open(out, 'w') { |io| doc.write(io, 2) }
        out
      end

      private_class_method def self.safe_tag(opts = {})
        name = opts[:name].to_s
        name = 'field' if name.empty?
        name = "f_#{name}" unless name.match?(/\A[A-Za-z_]/)
        name.gsub(/[^A-Za-z0-9_\-.]/, '_')
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:\n  #{self}.generate(\n    path: '/tmp/report.xml',\n    results_hash: {}\n  )\n\n  #{self}.authors\n"
      end
    end
  end
end
