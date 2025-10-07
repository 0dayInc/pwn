# frozen_string_literal: false

require 'json'
require 'socket'

module PWN
  module SAST
    # SAST Module used to identify portions of
    # code marked by developers as interesting for whatever reason.
    module Emoticon
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::SAST::Emoticon.scan(
      #   dir_path: 'optional path to dir defaults to .'
      #   git_repo_root_uri: 'optional http uri of git repo scanned'
      # )

      public_class_method def self.scan(opts = {})
        dir_path = opts[:dir_path]
        git_repo_root_uri = opts[:git_repo_root_uri].to_s.scrub

        test_case_filter = "
          grep -Fn \
          -e ':-)' \
          -e ';-)' \
          -e ':-P' \
          -e ':-D' \
          -e '\_o_/' \
          -e '\_O_/' \
          -e '\_0_/' \
          -e ':-O' {PWN_SAST_SRC_TARGET} 2> /dev/null
        "

        PWN::SAST::TestCaseEngine.execute(
          test_case_filter: test_case_filter,
          security_references: security_references,
          dir_path: dir_path,
          git_repo_root_uri: git_repo_root_uri
        )
      rescue StandardError => e
        raise e
      end

      # Used primarily to map NIST 800-53 Revision 4 Security Controls
      # https://web.nvd.nist.gov/view/800-53/Rev4/impact?impactName=HIGH
      # to PWN Exploit & Static Code Anti-Pattern Matching Modules to
      # Determine the level of Testing Coverage w/ PWN.

      public_class_method def self.security_references
        {
          sast_module: self,
          section: 'LEAST PRIVILEGE',
          nist_800_53_uri: 'https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-06',
          cwe_id: '546',
          cwe_uri: 'https://cwe.mitre.org/data/definitions/546.html'
        }
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
          sast_arr = #{self}.scan(
            :dir_path => 'optional path to dir defaults to .',
            :git_repo_root_uri => 'optional http uri of git repo scanned'
          )

          #{self}.authors
        "
      end
    end
  end
end
