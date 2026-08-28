# frozen_string_literal: true

module PWN
  module Reports
    # Generic PDF report writer for pentest / findings payloads.
    # Emits a minimal PDF 1.4 document (no wkhtmltopdf).
    module PDF
      public_class_method def self.generate(opts = {})
        out = PWN::Reports.resolve_path(opts.merge(ext: 'pdf'))
        payload = PWN::Reports.report_payload(opts)
        File.binwrite(out, render_pdf(payload: payload))
        out
      end

      private_class_method def self.render_pdf(opts = {})
        payload = opts[:payload]
        lines = [payload[:title].to_s]
        lines << ''
        unless payload[:executive_summary].to_s.empty?
          lines << 'Executive summary'
          lines.concat(wrap_line(text: payload[:executive_summary].to_s))
          lines << ''
        end
        payload[:findings].each do |row|
          heading = [row['id'], row['title']].compact.map(&:to_s).reject(&:empty?).join(': ')
          lines.concat(wrap_line(text: heading))
          row.each do |key, val|
            next if %w[id title].include?(key.to_s)

            lines.concat(wrap_line(text: "#{key}: #{val}"))
          end
          lines << ''
        end
        content = pdf_stream(lines: lines)
        objects = [
          '<< /Type /Catalog /Pages 2 0 R >>',
          '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
          '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
          "<< /Length #{content.bytesize} >>\nstream\n#{content}\nendstream",
          '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
        ]
        assemble_pdf(objects: objects)
      end

      private_class_method def self.pdf_stream(opts = {})
        lines = Array(opts[:lines])
        chunks = ['BT', '/F1 11 Tf', '72 720 Td']
        lines.each_with_index do |line, idx|
          chunks << '0 -14 Td' unless idx.zero?
          chunks << "(#{pdf_escape(text: line)}) Tj"
        end
        chunks << 'ET'
        "#{chunks.join("\n")}\n"
      end

      private_class_method def self.pdf_escape(opts = {})
        opts[:text].to_s.encode('UTF-8', invalid: :replace, undef: :replace).gsub('\\', '\\\\').gsub('(', '\\(').gsub(')', '\\)')
      end

      private_class_method def self.wrap_line(opts = {})
        text = opts[:text].to_s.tr("\r", '')
        return [''] if text.empty?

        text.scan(/.{1,90}(?:\s+|$)|.{1,90}/).map(&:strip)
      end

      private_class_method def self.assemble_pdf(opts = {})
        objects = Array(opts[:objects])
        out = +"%PDF-1.4\n"
        offsets = [0]
        objects.each_with_index do |body, idx|
          offsets << out.bytesize
          out << "#{idx + 1} 0 obj\n#{body}\nendobj\n"
        end
        xref_at = out.bytesize
        out << "xref\n0 #{objects.length + 1}\n"
        out << "0000000000 65535 f \n"
        offsets[1..].each { |off| out << format("%010d 00000 n \n", off) }
        out << "trailer\n<< /Size #{objects.length + 1} /Root 1 0 R >>\n"
        out << "startxref\n#{xref_at}\n%%EOF\n"
        out
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:\n  #{self}.generate(\n    path: '/tmp/report.pdf',\n    results_hash: {}\n  )\n\n  #{self}.authors\n"
      end
    end
  end
end
