# frozen_string_literal: false

require 'json'
require 'socket'

module PWN
  module SAST
    # SAST Module used to identify banned function
    # calls in C & C++ code per:
    # https://msdn.microsoft.com/en-us/library/bb288454.aspx
    module BannedFunctionCallsC
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::SAST::BannedFunctionCallsC.scan(
      #   :dir_path => 'optional path to dir defaults to .'
      #   :git_repo_root_uri => 'optional http uri of git repo scanned'
      # )

      public_class_method def self.scan(opts = {})
        dir_path = opts[:dir_path]
        git_repo_root_uri = opts[:git_repo_root_uri].to_s.scrub

        test_case_filter = "
          grep -Fn \
          -e 'strcpy' \
          -e 'strcpyA' \
          -e 'strcpyW' \
          -e 'wcscpy' \
          -e '_tcscpy' \
          -e '_mbscpy' \
          -e 'StrCpy' \
          -e 'StrCpyA' \
          -e 'StrCpyW' \
          -e 'lstrcpy' \
          -e 'lstrcpyA' \
          -e 'lstrcpyW' \
          -e '_tccpy' \
          -e '_mbccpy' \
          -e '_ftcscpy' \
          -e 'strncpy' \
          -e 'wcsncpy' \
          -e '_tcsncpy' \
          -e '_mbsncpy' \
          -e '_mbsnbcpy' \
          -e 'StrCpyN' \
          -e 'StrCpyNA' \
          -e 'StrCpyNW' \
          -e 'StrNCpy' \
          -e 'strcpynA' \
          -e 'StrNCpyA' \
          -e 'StrNCpyW' \
          -e 'lstrcpyn' \
          -e 'lstrcpynA' \
          -e 'lstrcpynW' \
          -e 'strcat' \
          -e 'strcatA' \
          -e 'strcatW' \
          -e 'wcscat' \
          -e '_tcscat' \
          -e '_mbscat' \
          -e 'StrCat' \
          -e 'StrCatA' \
          -e 'StrCatW' \
          -e 'lstrcat' \
          -e 'lstrcatA' \
          -e 'lstrcatW' \
          -e 'StrCatBuff' \
          -e 'StrCatBuffA' \
          -e 'StrCatBuffW' \
          -e 'StrCatChainW' \
          -e '_tccat' \
          -e '_mbccat' \
          -e '_ftcscat' \
          -e 'strncat' \
          -e 'wcsncat' \
          -e '_tcsncat' \
          -e '_mbsncat' \
          -e '_mbsnbcat' \
          -e 'StrCatN' \
          -e 'StrCatNA' \
          -e 'StrCatNW' \
          -e 'StrNCat' \
          -e 'StrNCatA' \
          -e 'StrNCatW' \
          -e 'lstrncat' \
          -e 'lstrcatnA' \
          -e 'lstrcatnW' \
          -e 'lstrcatn' \
          -e 'sprintfW' \
          -e 'sprintfA' \
          -e 'wsprintf' \
          -e 'wsprintfW' \
          -e 'wsprintfA' \
          -e 'sprintf' \
          -e 'swprintf' \
          -e '_stprintf' \
          -e 'wvsprintf' \
          -e 'wvsprintfA' \
          -e 'wvsprintfW' \
          -e 'vsprintf' \
          -e '_vstprintf' \
          -e 'vswprintf' \
          -e 'wvsprintf' \
          -e 'wvsprintfA' \
          -e 'wvsprintfW' \
          -e 'vsprintf' \
          -e '_vstprintf' \
          -e 'vswprintf' \
          -e 'strncpy' \
          -e 'wcsncpy' \
          -e '_tcsncpy' \
          -e '_mbsncpy' \
          -e '_mbsnbcpy' \
          -e 'StrCpyN' \
          -e 'StrCpyNA' \
          -e 'StrCpyNW' \
          -e 'StrNCpy' \
          -e 'strcpynA' \
          -e 'StrNCpyA' \
          -e 'StrNCpyW' \
          -e 'lstrcpyn' \
          -e 'lstrcpynA' \
          -e 'lstrcpynW' \
          -e '_fstrncpy' \
          -e 'strncat' \
          -e 'wcsncat' \
          -e '_tcsncat' \
          -e '_mbsncat' \
          -e '_mbsnbcat' \
          -e 'StrCatN' \
          -e 'StrCatNA' \
          -e 'StrCatNW' \
          -e 'StrNCat' \
          -e 'StrNCatA' \
          -e 'StrNCatW' \
          -e 'lstrncat' \
          -e 'lstrcatnA' \
          -e 'lstrcatnW' \
          -e 'lstrcatn' \
          -e '_fstrncat' \
          -e 'gets' \
          -e '_getts' \
          -e '_gettws' \
          -e 'IsBadWritePtr' \
          -e 'IsBadHugeWritePtr' \
          -e 'IsBadReadPtr' \
          -e 'IsBadHugeReadPtr' \
          -e 'IsBadCodePtr' \
          -e 'IsBadStringPtr' \
          -e 'memcpy' \
          -e 'RtlCopyMemory' \
          -e 'CopyMemory' \
          -e 'wmemcpy' {PWN_SAST_SRC_TARGET} 2> /dev/null
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
          section: 'INFORMATION INPUT VALIDATION',
          nist_800_53_uri: 'https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SI-10',
          cwe_id: '676',
          cwe_uri: 'https://cwe.mitre.org/data/definitions/676.html'
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
