# frozen_string_literal: true

require 'fileutils'

module PWN
  # This file, using the autoload directive loads Report modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Reports
    autoload :AIRedTeam, 'pwn/reports/ai_red_team'
    autoload :CSV, 'pwn/reports/csv'
    autoload :Fuzz, 'pwn/reports/fuzz'
    autoload :HTML, 'pwn/reports/html'
    autoload :HTMLFooter, 'pwn/reports/html_footer'
    autoload :HTMLHeader, 'pwn/reports/html_header'
    autoload :JSON, 'pwn/reports/json'
    autoload :Markdown, 'pwn/reports/markdown'
    autoload :PDF, 'pwn/reports/pdf'
    autoload :Phone, 'pwn/reports/phone'
    autoload :SAST, 'pwn/reports/sast'
    autoload :URIBuster, 'pwn/reports/uri_buster'
    autoload :XML, 'pwn/reports/xml'

    public_class_method def self.resolve_path(opts = {})
      path = opts[:path].to_s
      ext = opts[:ext].to_s.sub(/\A\./, '')
      unless path.empty?
        FileUtils.mkdir_p(File.dirname(path)) unless File.dirname(path).to_s.empty? || File.dirname(path) == '.'
        return path
      end

      dir = opts[:dir_path].to_s
      dir = '.' if dir.empty?
      FileUtils.mkdir_p(dir)
      name = opts[:report_name].to_s
      name = File.basename(Dir.pwd) if name.empty?
      File.join(dir, "#{name}.#{ext}")
    end

    public_class_method def self.report_payload(opts = {})
      raw = opts[:results_hash]
      raw = {} unless raw.is_a?(Hash)
      title = (
        opts[:title] ||
        raw[:title] || raw['title'] ||
        raw[:report_name] || raw['report_name'] ||
        'PWN Report'
      ).to_s
      summary = (
        opts[:executive_summary] ||
        raw[:executive_summary] || raw['executive_summary']
      ).to_s
      findings = raw[:findings] || raw['findings'] || raw[:data] || raw['data'] || []
      findings = [] unless findings.is_a?(Array)
      {
        title: title,
        executive_summary: summary,
        findings: findings.map { |row| stringify_keys(hash: row) },
        raw: raw
      }
    end

    private_class_method def self.stringify_keys(opts = {})
      hash = opts[:hash]
      return { 'value' => hash.to_s } unless hash.is_a?(Hash)

      hash.each_with_object({}) do |(key, val), acc|
        acc[key.to_s] = val
      end
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      constants.sort
    end
  end
end
