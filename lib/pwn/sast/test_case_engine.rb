# frozen_string_literal: false

require 'json'
require 'socket'

module PWN
  module SAST
    # SAST Module used to execute PWN::SAST::* modules
    module TestCaseEngine
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::SAST::TestCaseEngine.execute(
      #   test_case_filter: 'required - grep command to filter results',
      #   security_references: 'required - Hash with keys :sast_module, :section, :nist_800_53_uri, :cwe_id, :cwe_uri',
      #   dir_path: 'optional - path to dir defaults to .',
      #   include_extensions: 'optional - array of file extensions to search for in scan (Defaults to all file types / i.e. [])',
      #   exclude_extensions: 'optional - array of file extensions to exclude from scan (Defaults to [.bin, .dat, .JS-BEAUTIFIED, .o, .test, .png, .jpg, .jpeg, .gif, .svg, .ico, .so, .spec, .zip, .tar, .gz, .tgz, .7z, .mp3, .mp4, .mov, .avi, .wmv, .flv, .mkv])',
      #   git_repo_root_uri: 'optional - http uri of git repo scanned'
      # )

      public_class_method def self.execute(opts = {})
        test_case_filter = opts[:test_case_filter]
        raise 'ERROR: test_case_filter must be nil' if test_case_filter.nil?

        security_references = opts[:security_references]
        raise 'ERROR: security_references must be a Hash' unless security_references.is_a?(Hash)

        dir_path = opts[:dir_path] ||= '.'
        include_extensions = opts[:include_extensions] ||= []
        exclude_extensions = opts[:exclude_extentions] ||= %w[
          .7z
          .avi
          .bin
          .dat
          .dll
          .flv
          .gif
          .gz
          .ico
          .jpg
          .jpeg
          .JS-BEAUTIFIED
          .markdown
          .md
          .mkv
          .mov
          .mp3
          .mp4
          .o
          .png
          .svg
          .test
          .so
          .spec
          .tar
          .tgz
          .webm
          .wmv
          .zip
        ]

        git_repo_root_uri = opts[:git_repo_root_uri].to_s.scrub

        result_arr = []
        ai_introspection = PWN::Env[:ai][:introspection]
        logger_results = "AI Introspection => #{ai_introspection} => "

        PWN::Plugins::FileFu.recurse_in_dir(
          dir_path: dir_path,
          include_extensions: include_extensions,
          exclude_extensions: exclude_extensions
        ) do |entry|
          if File.file?(entry) && File.basename(entry) !~ /^pwn.+(html|json|db)$/ && entry !~ /test/i
            line_no_and_contents_arr = []
            entry_beautified = false

            if File.extname(entry) == '.js' && (`wc -l #{entry}`.split.first.to_i < 20 || entry.include?('.min.js') || entry.include?('-all.js'))
              js_beautify = `js-beautify #{entry} > #{entry}.JS-BEAUTIFIED 2> /dev/null`.to_s.scrub
              entry = "#{entry}.JS-BEAUTIFIED"
              entry_beautified = true
            end

            # Replace tokenized test_case_filter, PWN_ENTRY with actual entry
            this_test_case_filter = test_case_filter.to_s.gsub('{PWN_SAST_SRC_TARGET}', entry.to_s.scrub).to_s.scrub
            str = `#{this_test_case_filter}`.to_s.scrub

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
                test_case_filter: this_test_case_filter
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

                ai_analysis = nil
                if ai_introspection
                  request = {
                    scm_uri: "#{hash_line[:filename][:git_repo_root_uri]}/#{hash_line[:filename][:entry]}",
                    line_no: line_no,
                    source_code_snippet: contents
                  }.to_json
                  response = PWN::AI::Introspection.reflect(request: request)
                  if response.is_a?(Hash)
                    ai_analysis = response[:choices].last[:text] if response[:choices].last.keys.include?(:text)
                    ai_analysis = response[:choices].last[:content] if response[:choices].last.keys.include?(:content)
                  end
                end

                hash_line[:line_no_and_contents] = line_no_and_contents_arr.push(
                  line_no: line_no,
                  contents: contents,
                  author: author,
                  ai_analysis: ai_analysis
                )

                current_count += 2
              end
              result_arr.push(hash_line)
              logger_results = "#{logger_results}x" # Seeing progress is good :)
            end
          end
        end
        sast_module = security_references[:sast_module].to_s.scrub.gsub('::', '/')
        logger_banner = "https://www.rubydoc.info/gems/pwn/#{sast_module}"

        if logger_results.empty?
          @@logger.info("#{logger_banner}: No files applicable to this test case.\n")
        else
          @@logger.info("#{logger_banner} => #{logger_results}complete.\n")
        end
        result_arr
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
          sast_arr = #{self}.execute(
            test_case_filter: 'required grep command to filter results',
            security_references: 'required Hash with keys :sast_module, :section, :nist_800_53_uri, :cwe_id, :cwe_uri',
            dir_path: 'optional path to dir defaults to .',
            include_extensions: 'optional array of file extensions to search for in scan (Defaults to all file types / i.e. [])',
            exclude_extensions: 'optional array of file extensions to exclude from scan (Defaults to [.bin, .dat, .JS-BEAUTIFIED, .o, .test, .png, .jpg, .jpeg, .gif, .svg, .ico, .so, .spec, .zip, .tar, .gz, .tgz, .7z, .mp3, .mp4, .mov, .avi, .wmv, .flv, .mkv])',
            git_repo_root_uri: 'optional http uri of git repo scanned'
          )

          #{self}.authors
        "
      end
    end
  end
end
