# frozen_string_literal: false

require 'json'
require 'socket'

module PWN
  module SAST
    # SAST Module used to identify Base64 encoded strings
    # that may have sensitive artifacts when decoded.
    module Base64
      # Supported Method Parameters::
      # PWN::SAST::Base64.scan(
      #   dir_path: 'optional path to dir defaults to .'
      #   git_repo_root_uri: 'optional http uri of git repo scanned'
      # )

      public_class_method def self.scan(opts = {})
        dir_path = opts[:dir_path]
        git_repo_root_uri = opts[:git_repo_root_uri].to_s.scrub

        test_case_filter = "
          grep -Ein \
          -e 'BASE64' \
          -e '^[A-Za-z0-9+/]{12}([A-Za-z0-9+/]{4})*$|^[A-Za-z0-9+/]{8}([A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{2}==$|^[A-Za-z0-9+/]{8}([A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{3}=$' \
          {PWN_SAST_SRC_TARGET} 2> /dev/null
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

      # Used to dictate Security Control Requirements for a Given SAST module.

      public_class_method def self.security_references
        {
          sast_module: self,
          section: 'PROTECTION OF INFORMATION AT REST',
          nist_800_53_uri: 'https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SC-28',
          cwe_id: '95',
          cwe_uri: 'https://cwe.mitre.org/data/definitions/95.html'
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
            dir_path: 'optional path to dir defaults to .',
            git_repo_root_uri: 'optional http uri of git repo scanned'
          )

          #{self}.authors
        "
      end
    end
  end
end
