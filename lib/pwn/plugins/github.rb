# frozen_string_literal: true

require 'json'
require 'open3'

module PWN
  module Plugins
    # This plugin is used for interacting w/ Github's REST API using
    # the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    #
    # Credentials are sourced from PWN::Env[:plugins][:github]:
    #   plugins:
    #     github:
    #       username: your-gh-login
    #       personal_access_token: ghp_xxxxxxxxxxxxxxxxxxxx
    #
    # A PAT with `repo` + `workflow` scopes is sufficient for every method
    # here AND for the `gh` CLI (exported as GH_TOKEN by #{self}.gh).
    module Github
      @@logger = PWN::Plugins::PWNLogger.create

      # Resolve the Personal Access Token: explicit opt → PWN::Env → GH_TOKEN/GITHUB_TOKEN.
      private_class_method def self.resolve_token(opts = {})
        opts[:token] ||
          opts[:personal_access_token] ||
          PWN::Env.dig(:plugins, :github, :personal_access_token) ||
          ENV.fetch('GH_TOKEN', nil) ||
          ENV.fetch('GITHUB_TOKEN', nil)
      end

      # Resolve the default GitHub username / owner.
      private_class_method def self.resolve_username(opts = {})
        opts[:username] ||
          opts[:owner] ||
          PWN::Env.dig(:plugins, :github, :username) ||
          ENV.fetch('GH_USER', nil)
      end

      # Supported Method Parameters::
      # github_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   token: 'optional - PAT (default PWN::Env[:plugins][:github][:personal_access_token])',
      #   raw: 'optional - return raw RestClient::Response instead of parsed JSON (default false)'
      # )

      private_class_method def self.github_rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body]
        http_body = http_body.to_json if http_body.is_a?(Hash) || http_body.is_a?(Array)
        token = resolve_token(opts)
        raw = opts[:raw]
        base_api_uri = 'https://api.github.com'

        headers = {
          content_type: 'application/json; charset=UTF-8',
          accept: 'application/vnd.github+json',
          x_github_api_version: '2022-11-28'
        }
        headers[:authorization] = "Bearer #{token}" if token
        headers[:params] = params if params

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        response = rest_client.execute(
          method: http_method,
          url: "#{base_api_uri}/#{rest_call}",
          headers: headers,
          payload: http_body,
          verify_ssl: false
        )

        return response if raw

        JSON.parse(response.body, symbolize_names: true)
      rescue RestClient::Forbidden, RestClient::Unauthorized => e
        @@logger.error("GitHub #{e.class}: #{e.response&.body}")
        raise e
      rescue RestClient::BadRequest, RestClient::NotFound, StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response_json = PWN::Plugins::Github.download_all_gists(
      #   username: 'optional - username of gists to backup (default PWN::Env[:plugins][:github][:username])',
      #   target_dir: 'required - target directory to save respective gists'
      # )

      public_class_method def self.download_all_gists(opts = {})
        username = resolve_username(opts).to_s.scrub
        target_dir = opts[:target_dir].to_s.scrub

        raise "ERROR: #{target_dir} Does Not Exist." unless Dir.exist?(target_dir)

        page = 1
        response_json = [{}]
        while response_json.any?
          response_json = github_rest_call(
            rest_call: "users/#{username}/gists",
            params: { page: page }
          )

          Dir.chdir(target_dir)
          response_json.each do |gist_hash|
            clone_dir = gist_hash[:id]
            clone_uri = gist_hash[:git_pull_url]
            next if Dir.exist?(clone_dir)

            print "Cloning: #{clone_uri}..."
            system('git', 'clone', clone_uri)
            puts 'complete.'
          end

          page += 1
        end

        response_json
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # runs = PWN::Plugins::Github.workflow_runs(
      #   owner: 'required - repo owner (default PWN::Env[:plugins][:github][:username])',
      #   repo: 'required - repo name',
      #   workflow: 'optional - workflow file name or id (e.g. install-matrix.yml). Omit for all runs.',
      #   params: 'optional - {branch:, status:, per_page:, page:}'
      # )

      public_class_method def self.workflow_runs(opts = {})
        owner = resolve_username(opts)
        repo = opts[:repo]
        workflow = opts[:workflow]
        params = opts[:params] || { per_page: 30 }

        rest_call = if workflow
                      "repos/#{owner}/#{repo}/actions/workflows/#{workflow}/runs"
                    else
                      "repos/#{owner}/#{repo}/actions/runs"
                    end

        github_rest_call(rest_call: rest_call, params: params, token: opts[:token])
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # jobs = PWN::Plugins::Github.workflow_run_jobs(
      #   owner: 'required - repo owner (default PWN::Env[:plugins][:github][:username])',
      #   repo: 'required - repo name',
      #   run_id: 'required - workflow run id'
      # )

      public_class_method def self.workflow_run_jobs(opts = {})
        owner = resolve_username(opts)
        repo = opts[:repo]
        run_id = opts[:run_id]

        github_rest_call(
          rest_call: "repos/#{owner}/#{repo}/actions/runs/#{run_id}/jobs",
          params: opts[:params],
          token: opts[:token]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # log_text = PWN::Plugins::Github.job_log(
      #   owner: 'required - repo owner (default PWN::Env[:plugins][:github][:username])',
      #   repo: 'required - repo name',
      #   job_id: 'required - job id from workflow_run_jobs'
      # )
      # NOTE: log download REQUIRES an authenticated token — unauthenticated 403s.

      public_class_method def self.job_log(opts = {})
        owner = resolve_username(opts)
        repo = opts[:repo]
        job_id = opts[:job_id]

        github_rest_call(
          rest_call: "repos/#{owner}/#{repo}/actions/jobs/#{job_id}/logs",
          token: opts[:token],
          raw: true
        ).body
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::Github.api(
      #   path: 'required - REST path relative to https://api.github.com (e.g. "repos/0dayinc/pwn/releases/latest")',
      #   method: 'optional - :get|:post|:put|:patch|:delete (default :get)',
      #   params: 'optional - query params Hash',
      #   body: 'optional - request body Hash/Array/String for POST/PUT/PATCH',
      #   token: 'optional - PAT (default PWN::Env[:plugins][:github][:personal_access_token])',
      #   raw: 'optional - return raw RestClient::Response instead of parsed JSON (default false)'
      # )
      # Generic in-process escape hatch for any GitHub REST endpoint not yet
      # wrapped by a named method - parity with `gh api <path>` without needing
      # the gh binary.

      public_class_method def self.api(opts = {})
        github_rest_call(
          http_method: opts[:method] || :get,
          rest_call: opts[:path].to_s.delete_prefix('/'),
          params: opts[:params],
          http_body: opts[:body],
          token: opts[:token],
          raw: opts[:raw]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Github.gh(
      #   cmd: 'required - gh subcommand string, e.g. "run list -R 0dayinc/pwn -L 5 --json databaseId,status"',
      #   token: 'optional - PAT (default PWN::Env[:plugins][:github][:personal_access_token])'
      # )
      # Thin wrapper around the `gh` CLI with GH_TOKEN injected from PWN::Env so
      # `gh auth login` is never required.

      public_class_method def self.gh(opts = {})
        cmd = opts[:cmd].to_s
        gh_bin = ENV['PATH'].to_s.split(File::PATH_SEPARATOR)
                            .map { |d| File.join(d, 'gh') }
                            .find { |f| File.executable?(f) }
        raise "ERROR: gh CLI not found on PATH - use #{self}.api(path:) instead, or install gh (https://cli.github.com)" unless gh_bin

        token = resolve_token(opts)
        raise 'ERROR: no GitHub token - set plugins.github.personal_access_token in ~/.pwn/pwn.yaml' unless token

        env = { 'GH_TOKEN' => token, 'GH_PROMPT_DISABLED' => '1', 'NO_COLOR' => '1' }
        stdout, stderr, status = Open3.capture3(env, "#{gh_bin} #{cmd}")
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
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
          response_json = #{self}.download_all_gists(
            username: 'optional - username of gists to download (default PWN::Env[:plugins][:github][:username])',
            target_dir: 'required - target directory to save respective gists'
          )

          runs = #{self}.workflow_runs(
            owner: 'optional - default PWN::Env[:plugins][:github][:username]',
            repo: 'required - repo name',
            workflow: 'optional - e.g. install-matrix.yml',
            params: 'optional - {branch:, status:, per_page:}'
          )

          jobs = #{self}.workflow_run_jobs(
            owner: 'optional', repo: 'required', run_id: 'required'
          )

          log = #{self}.job_log(
            owner: 'optional', repo: 'required', job_id: 'required'
          )

          json = #{self}.api(
            path: 'required - e.g. repos/0dayinc/pwn/releases/latest',
            method: 'optional - :get|:post|:put|:patch|:delete',
            params: 'optional', body: 'optional', raw: 'optional'
          )

          #{self}.gh(cmd: 'run view <run_id> -R <owner>/<repo> --log-failed')

          #{self}.authors
        "
      end
    end
  end
end
