# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze generic vulnerability descriptions and generate detailed security findings following the exact bug bounty writeup structure:
      # 1. Detailed finding description with technical depth and PoC when possible
      # 2. Business impact
      # 3. Remediation recommendations, including compensating controls / stop gaps
      # 4. CVSS score, vector string, and first.org calculator URI
      # 5. CWE category, brief description, and CWE URI
      # 6. Relevant NIST 800-53 control
      # It leverages the PWN::AI::Introspection.reflect_on method. Defaults to Markdown for bug bounty report readiness.
      module VulnGen
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::VulnGen.analyze(
        #   request: 'required - high level description of vulnerability discovered (e.g. "Discovered a SQLi vulnerability in /login"',
        #   markup_type: 'optional - specify the type of markup to generate :jira|:markdown|:html|:confluence|:xml (default: :markdown)',
        #   output_path: 'optional - path to save the generated markdown report'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          markup_type = opts[:markup_type] ||= :markdown

          markup = ''
          case markup_type
          when :jira
            markup = 'Jira Wiki Markup'
          when :markdown
            markup = 'Markdown'
          when :html
            markup = 'HTML'
          when :confluence
            markup = 'Confluence Wiki Markup'
          when :xml
            markup = 'XML'
          else
            raise "ERROR: Unsupported markup_type '#{markup_type}'. Supported types are :jira, :markdown, :html, :confluence, :xml."
          end

          system_role_content = "
          _ALWAYS_ Generate #{markup} security findings for the message provided using **EXACTLY** this structure and section headers:

          1. Detailed finding description with technical depth and PoC when possible
          2. Business impact
          3. Remediation recommendations, including compensating controls / stop gaps
          4. CVSS score, vector string, and first.org calculator URI
          5. CWE category, brief description, and CWE URI
          6. Relevant NIST 800-53 control

          Provide high technical depth in (1) with PoC code snippets where applicable. Make (2) focus on business/reputational/financial risk. In (3) include immediate compensating controls. Ensure CVSS in (4) is accurate with valid vector and calculator link. Use current CWE/NIST references.
          "

          analysis = PWN::AI::Introspection.reflect_on(
            system_role_content: system_role_content,
            request: request,
            suppress_pii_warning: true
          )

          if opts[:output_path]
            require 'fileutils'
            FileUtils.mkdir_p(File.dirname(opts[:output_path]))
            File.write(opts[:output_path], analysis.to_s)
            puts "\n✅ Vulnerability report written to: #{opts[:output_path]}"
          end

          analysis
        rescue StandardError => e
          raise e
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            ai_analysis = #{self}.analyze(
              request: 'required - high level description of vulnerability discovered (e.g. \"Discovered a SQLi vulnerability in /login\"',
              markup_type: 'optional - specify the type of markup to generate :jira|:markdown|:html|:confluence|:xml (default: :markdown)',
              output_path: 'optional - full path to save the generated report as .md (e.g. /home/claw/reports/sqli-finding.md)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
