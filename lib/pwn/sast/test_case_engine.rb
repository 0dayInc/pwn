# frozen_string_literal: false

require 'json'
require 'open3'
require 'socket'
require 'shellwords'
require 'tempfile'

module PWN
  module SAST
    # SAST Module used to execute PWN::SAST::* modules
    module TestCaseEngine
      # Match relative components and deliberate test-file conventions only.
      TEST_PATH_PATTERN = %r{
        (?:\A|/)(?:tests?|specs?|__tests__)(?:/|\z) |
        (?:\A|/)(?:test_[^/]+|[^/]+_(?:test|spec))\.[^/]+\z |
        (?:\A|/)[^/]+\.(?:test|spec)\.[^/]+\z
      }ix

      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::SAST::TestCaseEngine.execute(
      #   test_case_filter: 'required - grep command to filter results',
      #   security_references: 'required - Hash with keys :sast_module, :section, :nist_800_53_uri, :cwe_id, :cwe_uri',
      #   dir_path: 'optional - path to dir defaults to .',
      #   exclude_test_paths: 'optional - defaults to true; exclude test/tests/spec/specs/__tests__ components and test_*, *_test, *_spec, *.test.*, *.spec.* files; false includes them',
      #   include_extensions: 'optional - array of file extensions to search for in scan (Defaults to all file types / i.e. [])',
      #   exclude_extensions: 'optional - array of file extensions to exclude from scan (Defaults to [.bin, .dat, .JS-BEAUTIFIED, .o, .test, .png, .jpg, .jpeg, .gif, .svg, .ico, .so, .spec, .zip, .tar, .gz, .tgz, .7z, .mp3, .mp4, .mov, .avi, .wmv, .flv, .mkv])',
      #   git_repo_root_uri: 'optional - http uri of git repo scanned'
      # )

      public_class_method def self.execute(opts = {})
        test_case_filter = opts[:test_case_filter]
        raise 'ERROR: test_case_filter must be nil' if test_case_filter.nil?

        security_references = opts[:security_references]
        raise 'ERROR: security_references must be a Hash' unless security_references.is_a?(Hash)

        dir_path = opts[:dir_path] || '.'
        exclude_test_paths = opts.fetch(:exclude_test_paths, true)
        include_extensions = opts[:include_extensions] || []
        exclude_extensions = opts[:exclude_extensions] || opts[:exclude_extentions] || %w[
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
        ai_module_reflection = PWN::Env.dig(:ai, :module_reflection)
        logger_results = "AI Module Reflection => #{ai_module_reflection} => "

        PWN::Plugins::FileFu.recurse_in_dir(
          dir_path: dir_path,
          include_extensions: include_extensions,
          exclude_extensions: exclude_extensions
        ) do |entry|
          # FileFu yields a shell-escaped word; filesystem APIs need its literal path.
          entry = Shellwords.split(entry).fetch(0)
          if File.file?(entry) && File.basename(entry) !~ /^pwn.+(html|json|db)$/ && (!exclude_test_paths || !entry.match?(TEST_PATH_PATTERN))
            line_no_and_contents_arr = []
            entry_beautified = false

            source_bytes = nil
            if File.extname(entry) == '.js'
              # Count newlines in-process. A shell wc would put the filename on a command line.
              source_bytes = File.binread(entry)
              if source_bytes.count("\n") < 20 || entry.include?('.min.js') || entry.include?('-all.js')
                beautified = begin
                  # The installed launcher reparses argv with a shell: send only a fixed
                  # stdin selector, never a repository-controlled filename or source text.
                  Open3.capture3('js-beautify', '-', stdin_data: source_bytes)
                rescue Errno::ENOENT
                  nil # Optional formatter absent: scan the original source, not an empty sidecar.
                end
                if beautified
                  output, error, status = beautified
                  raise "ERROR: js-beautify failed (#{status.exitstatus}): #{error}" unless status.success?

                  # Empty success is not evidence that nonempty input is clean.
                  entry_beautified = !output.strip.empty?
                end
              end
            end

            # Never write formatter output beside untrusted source, and never place a
            # JavaScript filename on a shell command line. Grep a private copy instead.
            formatted_source = nil
            begin
              scan_target = entry
              if source_bytes
                formatted_source = Tempfile.new(['pwn-sast-', '.js'])
                formatted_source.binmode
                formatted_source.write(entry_beautified ? output : source_bytes)
                formatted_source.close
                scan_target = formatted_source.path
              end
              this_test_case_filter = test_case_filter.to_s.gsub('{PWN_SAST_SRC_TARGET}') { Shellwords.escape(scan_target) }.to_s.scrub
              str = `#{this_test_case_filter}`.to_s.scrub
            ensure
              formatted_source&.close!
            end

            if str.to_s.empty?
              # If str length is >= 64 KB do not include results. (Due to Mongo Document Size Restrictions)
              logger_results = "#{logger_results}~" # Catching bugs is good :)
            else
              str = "1:Result larger than 64KB -> Size: #{str.to_s.length}.  Please click the \"Path\" link for more details." if str.to_s.length >= 64_000

              # Formatted line numbers refer to raw_content, not original lines;
              # the path remains the source path and no sidecar is published.
              hash_line = {
                timestamp: Time.now.strftime('%Y-%m-%d %H:%M:%S.%9N %z').to_s,
                security_references: security_references,
                filename: { git_repo_root_uri: git_repo_root_uri, entry: entry, entry_beautified: entry_beautified },
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

                request = {
                  scm_uri: "#{hash_line[:filename][:git_repo_root_uri]}/#{hash_line[:filename][:entry]}",
                  line_no: line_no,
                  source_code_snippet: contents
                }.to_json

                ai_analysis = (PWN::AI::Agent::SAST.analyze(request: request) if ai_module_reflection)
                ai_analysis ||= 'N/A'

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
          # Run execute and return its result
          #{self}.execute(
            test_case_filter: 'required - grep command to filter results',
            security_references: 'required - Hash with keys :sast_module, :section, :nist_800_53_uri, :cwe_id, :cwe_uri',
            dir_path: 'optional - path to dir defaults to .',
            exclude_test_paths: 'optional - defaults to true; exclude test/tests/spec/specs/__tests__ components and test_*, *_test, *_spec, *.test.*, *.spec.* files; false includes them',
            include_extensions: 'optional - array of file extensions to search for in scan (Defaults to all file types / i.e. [])',
            exclude_extensions: 'optional - array of file extensions to exclude from scan (Defaults to [.bin, .dat, .JS-BEAUTIFIED, .o, .test, .png, .jpg, .jpeg, .gif, .svg, .ico, .so, .spec, .zip, .tar, .gz, .tgz, .7z, .mp3, .mp4, .mov, .avi, .wmv, .flv, .mkv])',
            git_repo_root_uri: 'optional - http uri of git repo scanned',
            exclude_extentions: 'optional - exclude extentions value consumed by #execute'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
