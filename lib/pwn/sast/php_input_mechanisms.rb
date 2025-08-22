# frozen_string_literal: false

require 'socket'

module PWN
  module SAST
    # SAST Module used to identify HTTP input
    # mechanisms that exist in PHP code (e.g. $_REQUEST, $_GET, etc.)
    module PHPInputMechanisms
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::SAST::PHPInputMechanisms.scan(
      #   dir_path: 'optional path to dir defaults to .'
      #   git_repo_root_uri: 'optional http uri of git repo scanned'
      # )

      public_class_method def self.scan(opts = {})
        dir_path = opts[:dir_path]
        git_repo_root_uri = opts[:git_repo_root_uri].to_s.scrub
        result_arr = []
        logger_results = ''

        Dir.chdir(dir_path)
        PWN::Plugins::FileFu.recurse_in_dir(dir_path: dir_path) do |entry|
          if (File.file?(entry) && File.basename(entry) !~ /^pwn.+(html|json|db)$/ && File.basename(entry) !~ /\.JS-BEAUTIFIED$/) && File.extname(entry).include?('.php') && entry !~ /test/i
            line_no_and_contents_arr = []
            entry_beautified = false

            if File.extname(entry) == '.js' && (`wc -l #{entry}`.split.first.to_i < 20 || entry.include?('.min.js') || entry.include?('-all.js'))
              js_beautify = `js-beautify #{entry} > #{entry}.JS-BEAUTIFIED 2> /dev/null`.to_s.scrub
              entry = "#{entry}.JS-BEAUTIFIED"
              entry_beautified = true
            end

            test_case_filter = "
              grep -Fn \
              -e '$_COOKIE' \
              -e '$_FILES' \
              -e '$_GET' \
              -e '$_POST' \
              -e '$_REQUEST' \
              -e '$_SERVER' \
              -e '$_SESSION' #{entry} 2> /dev/null
            "

            str = `#{test_case_filter}`.to_s.scrub

            if str.to_s.empty?
              # If str length is >= 64 KB do not include results. (Due to Mongo Document Size Restrictions)
              logger_results = "#{logger_results}~" # Catching bugs is good :)
            else
              str = "1:Result larger than 64KB -> Size: #{str.to_s.length}.  Please click the \"Path\" link for more details." if str.to_s.length >= 64_000

              hash_line = {
                timestamp: Time.now.strftime('%Y-%m-%d %H:%M:%S.%9N %z').to_s,
                security_references: security_references,
                filename: { git_repo_root_uri: git_repo_root_uri, entry: entry },
                line_no_and_contents: '',
                raw_content: str,
                test_case_filter: test_case_filter
              }

              # COMMMENT: Must be a better way to implement this (regex is kinda funky)
              line_contents_split = str.split(/^(\d{1,}):|\n(\d{1,}):/)[1..-1]
              line_no_count = line_contents_split.length # This should always be an even number
              current_count = 0
              while line_no_count > current_count
                line_no = line_contents_split[current_count]
                contents = line_contents_split[current_count + 1]
                if Dir.exist?('.git')
                  repo_root = '.'

                  author = PWN::Plugins::Git.get_author(
                    repo_root: repo_root,
                    from_line: line_no,
                    to_line: line_no,
                    target_file: entry,
                    entry_beautified: entry_beautified
                  )
                end
                author ||= 'N/A'

                hash_line[:line_no_and_contents] = line_no_and_contents_arr.push(
                  line_no: line_no,
                  contents: contents,
                  author: author
                )

                current_count += 2
              end
              result_arr.push(hash_line)
              logger_results = "#{logger_results}x" # Seeing progress is good :)
            end
          end
        end
        logger_banner = "http://#{Socket.gethostname}:8808/doc_root/pwn-#{PWN::VERSION.to_s.scrub}/#{to_s.scrub.gsub('::', '/')}.html"
        if logger_results.empty?
          @@logger.info("#{logger_banner}: No files applicable to this test case.\n")
        else
          @@logger.info("#{logger_banner} => #{logger_results}complete.\n")
        end
        result_arr
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
          section: 'DEVELOPER SECURITY AND PRIVACY ARCHITECTURE AND DESIGN',
          nist_800_53_uri: 'https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=SA-17',
          cwe_id: '661',
          cwe_uri: 'https://cwe.mitre.org/data/definitions/661.html'
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
