# frozen_string_literal: false

require 'json'
require 'socket'

module PWN
  module SAST
    # SAST Module used to identify banned function
    # calls in C & C++ code per:
    # https://msdn.microsoft.com/en-us/library/bb288454.aspx
    module UseAfterFree
      # Supported Method Parameters::
      # PWN::SAST::UseAfterFree.scan(
      #   :dir_path => 'optional path to dir defaults to .'
      #   :git_repo_root_uri => 'optional http uri of git repo scanned'
      # )

      public_class_method def self.scan(opts = {})
        dir_path = opts[:dir_path]
        git_repo_root_uri = opts[:git_repo_root_uri].to_s.scrub

        test_case_filter = "
          grep -Fn \
          -e 'calloc(' \
          -e 'free(' \
          -e 'malloc(' \
          -e 'realloc(' {PWN_SAST_SRC_TARGET} 2> /dev/null
        "

        include_extensions = %w[.c .cats .idc .cpp .cc .cxx .c++ .cp .CPP .C .cppm .ixx .h .hpp .hxx .hh .h++ .inc .inl .ipp .tcc .tpp .txx .i .s .asm .o .obj .a .so .lib .dll .exe .pdb .vcxproj .sln .dsp .dsw .cbp .cmake .make .mk]

        PWN::SAST::TestCaseEngine.execute(
          test_case_filter: test_case_filter,
          security_references: security_references,
          dir_path: dir_path,
          include_extensions: include_extensions,
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
          section: 'MEMORY PROTECTION',
          nist_800_53_uri: 'https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SI-16',
          cwe_id: '416',
          cwe_uri: 'https://cwe.mitre.org/data/definitions/416.html'
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
