# frozen_string_literal: true

require 'shellwords'

module PWN
  module Plugins
    # Used primarily in the past to clone local repos and generate an
    # html diff to be sent via email (deprecated).  In the future this
    # plugin may be used to expand upon capabilities required w/ Git.
    module Git
      @@logger = PWN::Plugins::PWNLogger.create
      # Supported Method Parameters::
      # PWN::Plugins::Git.gen_html_diff(
      #   repo: 'required git repo name',
      #   branch: 'required git repo branch (e.g. master, develop, etc)',
      #   since: 'optional date, otherwise default to last pull'
      # )

      public_class_method def self.gen_html_diff(opts = {})
        git_repo_name = opts[:repo].to_s
        git_repo_branch = opts[:branch].to_s
        since_date = opts[:since]

        git_pull_output = '<div style="background-color:#CCCCCC; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">'
        if since_date
          git_pull_output << "<h3>#{git_repo_name}->#{git_repo_branch} Diff Summary Since #{since_date}</h3>"
          git_entity = `git log --since #{since_date} --stat-width=65535 --graph`.to_s.scrub
        else
          git_pull_output << "<h3>#{git_repo_name}->#{git_repo_branch} Diff Summary Since Last Pull</h3>"
          git_entity = `git log ORIG_HEAD.. --stat-width=65535 --graph`.to_s.scrub
        end
        # For debugging purposes
        @@logger.info(git_entity)
        git_pull_output << git_entity.gsub("\n", '<br />')
        git_pull_output << '</div>'
        git_pull_output << '<br />'

        git_pull_output
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # get_author_by_line_range(
      #   repo_root: 'optional path to git repo root (defaults to ".")'
      #   from_line: 'required line number to start in range',
      #   to_line: 'required line number to stop in range',
      #   target_file: 'require file in which line range is queried'
      # )

      private_class_method def self.get_author_by_line_range(opts = {})
        repo_root = if opts[:repo_root].nil?
                      '.'
                    else
                      opts[:repo_root].to_s
                    end
        from_line = opts[:from_line].to_i
        to_line = opts[:to_line].to_i
        target_file = opts[:target_file].to_s
        target_file.gsub!(%r{^#{repo_root}/}, '')

        if File.directory?(repo_root) && File.file?("#{repo_root}/#{target_file}")
          `git --git-dir="#{Shellwords.escape(repo_root)}/.git" log -L #{from_line},#{to_line}:"#{Shellwords.escape(target_file)}" | grep Author | head -n 1`.to_s.scrub
        else
          -1
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Git.dump_all_repo_branches(
      #   git_url: 'required git repo url'
      # )

      public_class_method def self.dump_all_repo_branches(opts = {})
        git_url = opts[:git_url].to_s.scrub
        `git ls-remote #{git_url}`.to_s.scrub
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # get_author(
      #   repo_root: dir_path,
      #   from_line: line_no,
      #   to_line:line_no,
      #   target_file: entry,
      #   entry_beautified: entry_beautified
      # )

      public_class_method def self.get_author(opts = {})
        repo_root = opts[:repo_root]
        from_line = opts[:from_line]
        to_line = opts[:to_line]
        target_file = opts[:target_file]
        entry_beautified = opts[:entry_beautified]

        # In order to get the original author
        # we need to query the original file
        # instead of the .JS-BEAUTIFIED file
        if entry_beautified
          target_file.gsub!(/\.JS-BEAUTIFIED$/, '')
          target_file_line_length = `wc -l #{target_file}`.split.first.to_i
          target_file_line_length = 1 if target_file_line_length < 1 # wc -l doesn't count line is \n is missing

          author = get_author_by_line_range(
            repo_root: repo_root,
            from_line: 1,
            to_line: target_file_line_length,
            target_file: target_file
          )
        else
          if from_line.to_i && to_line.to_i < 1
            from_line = 1
            to_line = 1
          end
          author = get_author_by_line_range(
            repo_root: repo_root,
            from_line: from_line,
            to_line: to_line,
            target_file: target_file
          )
        end

        author
      rescue StandardError => e
        raise e
      end

      # Author(s):: Jacob Hoopes <jake.hoopes@gmail.com>

      public_class_method def self.authors
        "AUTHOR(S):
          Jacob Hoopes <jake.hoopes@gmail.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts %{USAGE:
          git_html_resp = #{self}.gen_html_diff(
            repo: 'required git repo name',
            branch: 'required git repo branch (e.g. master, develop, etc)',
            since: 'optional date, otherwise default to last pull'
          )

          author = #{self}.get_author(
            repo_root: 'optional path to git repo root (defaults to ".")'
            from_line: 'required line number to start in range',
            to_line: 'required line number to stop in range',
            target_file: 'required file in which line range is queried'
            entry_beautified: 'required boolean'
          )

          all_repo_branches = #{self}.dump_all_repo_branches(
            git_url: 'required git repo url'
          )

          #{self}.authors
        }
      end
    end
  end
end
