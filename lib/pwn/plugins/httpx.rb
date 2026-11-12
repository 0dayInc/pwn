# frozen_string_literal: true

require 'json'
require 'open3'

module PWN
  module Plugins
    # httpx JSONL probe: live URLs, status, title, and detected tech stack.
    module Httpx
      public_class_method def self.required_bins
        %w[httpx]
      end

      public_class_method def self.probe(opts = {})
        body = jsonl_body(opts)
        return { hosts: [], techs: [], error: 'missing jsonl file', stderr: nil, exit: nil } if body.is_a?(Hash) && body[:missing]

        stdout = body
        unless stdout
          PWN::Plugins::PreflightChecker.require_bin!(name: 'httpx')
          targets = Array(opts[:targets] || opts[:target] || opts[:urls]).map(&:to_s).reject(&:empty?)
          raise 'ERROR: target is required' if targets.empty?

          cmd = ['httpx', '-silent', '-json', '-title', '-tech-detect', '-status-code']
          cmd += ['-u', *targets] if targets.length == 1
          stdout, stderr, status = capture(cmd: cmd, stdin: targets.length > 1 ? "#{targets.join("\n")}\n" : nil)
        end
        parsed = parse_jsonl(text: stdout)
        rows = parsed[:rows]
        { hosts: rows, techs: techs(rows: rows), stderr: stderr, exit: status&.exitstatus, rejected: parsed[:rejected] }
      end

      public_class_method def self.techs(opts = {})
        names = Array(opts[:rows] || opts[:hosts]).flat_map do |row|
          row = row.transform_keys(&:to_s) if row.is_a?(Hash)
          Array(row['tech'] || row['technologies'] || row[:tech]) + [row['webserver'], row['title']].compact
        end
        names.map { |item| item.to_s.downcase }.uniq.reject(&:empty?)
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Probe URLs with httpx JSONL or ingest an existing JSONL file.
          #{self}.probe(
            target: 'optional - single URL or hostname (required unless jsonl or targets is set)',
            targets: 'optional - Array of URLs',
            urls: 'optional - alias for targets',
            jsonl: 'optional - httpx JSONL file path or raw JSONL text (skips the httpx binary); a missing path-like value returns an error and malformed lines increment rejected',
          )

          # Flatten tech/product names from parsed httpx JSONL rows.
          #{self}.techs(
            rows: 'optional - Array of parsed httpx JSON objects',
            hosts: 'optional - alias for rows'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.jsonl_body(opts = {})
        src = opts[:jsonl]
        return nil if src.nil?

        text = src.to_s
        if text.start_with?('/') || text.match?(/\.jsonl\z/i)
          return { missing: true } unless File.file?(text)

          return File.read(text)
        end
        text
      end

      private_class_method def self.parse_jsonl(opts = {})
        rows = []
        rejected = 0
        opts[:text].to_s.each_line do |line|
          next if line.strip.empty?

          row = JSON.parse(line)
          row.is_a?(Hash) ? rows << row : rejected += 1
        rescue JSON::ParserError
          rejected += 1
        end
        { rows: rows, rejected: rejected }
      end

      private_class_method def self.capture(opts = {})
        if opts[:stdin]
          Open3.capture3(*opts[:cmd], stdin_data: opts[:stdin])
        else
          Open3.capture3(*opts[:cmd])
        end
      rescue Errno::ENOENT
        stdout, status = Open3.capture2(*opts[:cmd])
        [stdout, '', status]
      end
    end
  end
end
