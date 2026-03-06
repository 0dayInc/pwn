# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze generic vulnerability descriptions and generate detailed security findings, including business impact, remediation recommendations, CVSS scoring, CWE categorization, and relevant NIST 800-53 controls. It leverages the PWN::AI::Introspection.reflect_on method to process the input request and produce comprehensive markdown-formatted findings.
      module VulnGen
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::VulnGen.analyze(
        #   request: 'required - high level description of vulnerability discovered (e.g. "Discovered a SQLi vulnerability in /login"',
        #   markup_type: 'optional - specify the type of markup to generate :jira|:markdown|:html|:confluence|:xml (default: :jira)'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          markup_type = opts[:markup_type] ||= :jira

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
          _ALWAYS_ Generate #{markup} security findings for the message provided with the following content:

          1. Detailed Finding Description: This should be a deep, detailed technical description that should include exploit proof-of-concepts when possible.

          2. Business Impact: This should describe, in business terms, the importance of fixing the issue.  Reputational and/or financial impact should be considered for this section.

          3. Remediation Recommendations:  Targeted towards technical engineers that can ascertain a reasonable approach to fix the vulnerability based upon common security remediation patterns.  Be sure to consider compensating controls / stop gaps that can be implemented (e.g. WAF, additional logging, etc.) until such time the vulnerability can be fixed.  Provide examples in cases where code fixes may be required.

          4. CVSS Score (Severity), Base CVSS Vector string as /AV:`N|L|A|P`/AC:`L|H`/PR:`N|L|H`/UI:`N|R`/S:`U|C`/C:`N|L|H`/I:`N|L|H`/A:`N|L|H`, and first.org CVSS calculator URI as https://www.first.org/cvss/calculator/3-1#CVSS:3.1/AV:`N|L|A|P`/AC:`L|H`/PR:`N|L|H`/UI:`N|R`/S:`U|C`/C:`N|L|H`/I:`N|L|H`/A:`N|L|H`.  The Vector string must be formatted like: `/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s`.  Ensure the score and severity aligns with the vector string calculation.

          5. CWE Category, Brief CWE description, and CWE URI

          6. NIST 800-53 Security Control that is impacted by this vulnerability.
          "

          PWN::AI::Introspection.reflect_on(
            system_role_content: system_role_content,
            request: request,
            suppress_pii_warning: true
          )
        rescue StandardError => e
          raise e.backtrace
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
              markup_type: 'optional - specify the type of markup to generate :jira|:markdown|:html|:confluence|:xml (default: :jira)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
