# frozen_string_literal: true

# Until jenkins_api_client is Updated
require 'jenkins_api_client2'

module PWN
  module Plugins
    # This plugin is used to interact w/ the Jenkins API and can be
    # used to carry out tasks when certain events occur w/in Jenkins.
    module Jenkins
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.connect(
      #   ip: 'required host/ip of Jenkins Server',
      #   port: 'optional tcp port (defaults to 8080),
      #   username: 'optional username (functionality will be limited if ommitted)',
      #   api_key: 'optional api_key (functionality will be limited if ommitted)'
      #   identity_file: 'optional ssh private key path to AuthN w/ Jenkins PREFERRED over username/api_key',
      #   ssl: 'optional connect over TLS (defaults to true),
      #   proxy: 'optional debug proxy rest api requests to jenkins (e.g. "http://127.0.0.1:8080")''
      # )

      public_class_method def self.connect(opts = {})
        ip = opts[:ip]
        port = opts[:port].to_i ||= 8888
        username = opts[:username].to_s.scrub
        base_jenkins_api_uri = "https://#{ip}/ase/services".to_s.scrub
        api_key = opts[:api_key].to_s.scrub
        identity_file = opts[:identity_file].to_s.scrub
        ssl_bool = true if opts[:ssl] ||= false

        if opts[:proxy]
          proxy = URI(opts[:proxy])
          proxy_protocol = proxy.scheme
          proxy_ip = proxy.host
          proxy_port = proxy.port
        end

        @@logger.info("Logging into Jenkins Server: #{ip}")
        if username == '' && api_key == ''
          if identity_file == ''
            jenkins_obj = JenkinsApi::Client.new(
              server_ip: ip,
              server_port: port,
              follow_redirects: true,
              ssl: ssl_bool,
              proxy_protocol: proxy_protocol,
              proxy_ip: proxy_ip,
              proxy_port: proxy_port
            )
          else
            jenkins_obj = JenkinsApi::Client.new(
              server_ip: ip,
              server_port: port,
              identity_file: identity_file,
              follow_redirects: true,
              ssl: ssl_bool,
              proxy_protocol: proxy_protocol,
              proxy_ip: proxy_ip,
              proxy_port: proxy_port
            )
          end
        else
          api_key = PWN::Plugins::AuthenticationHelper.mask_password if api_key == ''
          jenkins_obj = JenkinsApi::Client.new(
            server_ip: ip,
            server_port: port,
            username: username,
            password: api_key,
            follow_redirects: true,
            ssl: ssl_bool,
            proxy_protocol: proxy_protocol,
            proxy_ip: proxy_ip,
            proxy_port: proxy_port
          )
        end
        jenkins_obj.system.wait_for_ready
        jenkins_obj
      rescue StandardError => e
        raise e
      end

      # PWN::Plugins::Jenkins.create_user(
      #   jenkins_obj: 'required - jenkins_obj returned from #connect method',
      #   username: 'required - user to create',
      #   password: 'required - password for new user'
      #   fullname: 'required - full name of new user'
      #   email: 'required - email address of new user'
      # )

      public_class_method def self.create_user(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        username = opts[:username].to_s.scrub
        password = opts[:password].to_s.scrub
        password = PWN::Plugins::AuthenticationHelper.mask_password if password == ''
        fullname = opts[:fullname].to_s.scrub
        email = opts[:email].to_s.scrub

        post_body = {
          'username' => username,
          'password1' => password,
          'password2' => password,
          'fullname' => fullname,
          'email' => email,
          'json' => {
            'username' => username,
            'password1' => password,
            'password2' => password,
            'fullname' => fullname,
            'email' => email
          }.to_json
        }

        @@logger.info("Creating #{username}...")

        resp = jenkins_obj.api_post_request(
          '/securityRealm/createAccountByAdmin',
          post_body
        )

        resp == '302'
      # rescue JenkinsApi::Exceptions::UserAlreadyExists => e
      #   @@logger.warn("Jenkins view: #{view_name} already exists")
      #   return e.class
      rescue StandardError => e
        raise e
      end

      # PWN::Plugins::Jenkins.create_ssh_credential(
      #   jenkins_obj: 'required - jenkins_obj returned from #connect method',
      #   username: 'required - username for new credential'
      #   private_key_path: 'required - path of private ssh key for new credential'
      #   key_passphrase: 'optional - private key passphrase for new credential'
      #   credential_id: 'optional but recommended - useful when creating userland jobs',
      #   description: 'optional - description of new credential'
      #   domain: 'optional - defaults to GLOBAL',
      #   scope: 'optional - GLOBAL or SYSTEM (defaults to GLOBAL)'
      # )

      public_class_method def self.create_ssh_credential(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        username = opts[:username].to_s.scrub
        private_key_path = opts[:private_key_path].to_s.strip.chomp.scrub
        key_passphrase = opts[:key_passphrase].to_s.scrub
        credential_id = opts[:credential_id].to_s.scrub
        description = opts[:description].to_s.scrub

        if opts[:domain].to_s.strip.chomp.scrub == 'GLOBAL' || opts[:domain].nil?
          uri_path = '/credentials/store/system/domain/_/createCredentials'
        else
          domain = opts[:domain].to_s.strip.chomp.scrub
          uri_path = "/credentials/store/system/domain/#{domain}/createCredentials"
        end

        if opts[:scope].to_s.strip.chomp.scrub == 'SYSTEM'
          scope = 'SYSTEM'
        else
          scope = 'GLOBAL'
        end

        if credential_id == ''
          post_body = {
            'json' => {
              '' => '0',
              'credentials' => {
                'scope' => scope,
                'username' => username,
                'privateKeySource' => {
                  'stapler-class' => 'com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$DirectEntryPrivateKeySource',
                  'privateKey' => File.read(private_key_path)
                },
                'passphrase' => key_passphrase,
                'description' => description,
                'stapler-class' => 'com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey'
              }
            }.to_json
          }
        else
          post_body = {
            'json' => {
              '' => '0',
              'credentials' => {
                'scope' => scope,
                'username' => username,
                'privateKeySource' => {
                  'stapler-class' => 'com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$DirectEntryPrivateKeySource',
                  'privateKey' => File.read(private_key_path)
                },
                'passphrase' => key_passphrase,
                'id' => credential_id,
                'description' => description,
                'stapler-class' => 'com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey'
              }
            }.to_json
          }
        end

        resp = jenkins_obj.api_post_request(
          uri_path,
          post_body
        )

        resp == '302'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.get_all_job_git_repos(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method'
      # )

      public_class_method def self.get_all_job_git_repos(opts = {})
        jenkins_obj = opts[:jenkins_obj]

        @@logger.info('Retrieving a List of Git Repos from Every Job...')

        git_repo_arr = []

        jenkins_obj.job.list_all_with_details.each do |job|
          this_config = Nokogiri::XML(jenkins_obj.job.get_config(job['name']))
          this_git_repo = this_config.xpath('//scm/userRemoteConfigs/hudson.plugins.git.UserRemoteConfig/url').text
          this_git_branch = this_config.xpath('//scm/branches/hudson.plugins.git.BranchSpec/name').text
          next if this_git_repo == ''

          # Obtain all jobs' git repos
          job_git_repo = {}
          job_git_repo[:name] = job['name']
          job_git_repo[:url] = job['url']
          job_git_repo[:job_state] = job['color']
          job_git_repo[:git_repo] = this_git_repo
          job_git_repo[:git_branch] = this_git_branch
          job_git_repo[:config_xml_response] = this_config
          git_repo_arr.push(job_git_repo)
        end

        git_repo_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.list_nested_jobs(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      #   view_path: 'required view path to list jobs'
      # )

      public_class_method def self.list_nested_jobs(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        view_path = opts[:view_path].to_s.scrub
        nested_view_resp = jenkins_obj.api_get_request(view_path)
        nested_view_resp['jobs']
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.list_nested_views(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      #   view_path: 'required view path list sub-views'
      # )

      public_class_method def self.list_nested_views(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        view_path = opts[:view_path].to_s.scrub
        nested_view_resp = jenkins_obj.api_get_request(view_path)
        nested_view_resp['views']
      rescue StandardError => e
        raise e
      end

      # PWN::Plugins::Jenkins.create_nested_view(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      #   view_path: 'required view path create',
      #   create_in_view_path: 'optional creates nested view within an existing nested view, defaults to / views'
      # )

      public_class_method def self.create_nested_view(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        view_name = opts[:view_name].to_s.scrub
        create_in_view_path = opts[:create_in_view_path].to_s.scrub
        # TODO: pass parameter for modes and use case statement to build dynamically post_body
        # mode = 'hudson.plugins.nested_view.NestedView' # Requires Jenkins Nested View Plugin to Work Properly
        mode = 'hudson.model.ListView'

        post_body = {
          'name' => view_name,
          'mode' => mode,
          'json' => {
            'name' => view_name,
            'mode' => mode
          }.to_json
        }

        root_view_paths_arr = [
          '',
          '/'
        ]

        if root_view_paths_arr.include?(create_in_view_path)
          @@logger.info('Creating Nested View in /...')

          resp = jenkins_obj.api_post_request(
            '/createView',
            post_body
          )
        else
          @@logger.info("Creating Nested View in #{create_in_view_path}...")

          # Example view_path would be '/view/Projects/PROJECT_NAME/view/RELEASES'
          # This is taken out of the Jenkins URI when residing in the view in which
          # you want to create your view...simply drop the domain name.
          resp = jenkins_obj.api_post_request(
            "#{create_in_view_path}/createView",
            post_body
          )
        end
        resp == '302'
      rescue JenkinsApi::Exceptions::ViewAlreadyExists => e
        @@logger.warn("Jenkins view: #{view_name} already exists")
        e.class
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.add_job_to_nested_view(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      #   view_path: 'required view path associate job',
      #   job_name: 'required view path attach to a view',
      # )
      public_class_method def self.add_job_to_nested_view(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        view_path = opts[:view_path].to_s.scrub
        job_name = opts[:job_name].to_s.scrub
        jenkins_obj.api_post_request("#{view_path}/addJobToView?name=#{job_name}")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.copy_job_no_fail_on_exist(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      #   existing_job_name: 'required existing job to copt to new job',
      #   new_job_name: 'required name of new job'
      # )

      public_class_method def self.copy_job_no_fail_on_exist(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        existing_job_name = opts[:existing_job_name]
        new_job_name = opts[:new_job_name]

        copy_job_resp = jenkins_obj.job.copy(existing_job_name, new_job_name)
      rescue JenkinsApi::Exceptions::JobAlreadyExists => e
        @@logger.warn("Jenkins job: #{new_job_name} already exists")
        e.class
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.disable_jobs_by_regex(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      #   regex: 'required regex pattern for matching jobs to disable e.g. :regex => "^M[0-9]"',
      # )

      public_class_method def self.disable_jobs_by_regex(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        regex = opts[:regex].to_s.scrub

        jenkins_obj.job.list_all_with_details.each do |job|
          job_name = job['name']
          if job_name.match?(/#{regex}/)
            @@logger.info("Disabling #{job_name}")
            jenkins_obj.job.disable(job_name)
          end
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.delete_jobs_by_regex(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      #   regex: 'required regex pattern for matching jobs to disable e.g. :regex => "^M[0-9]"',
      # )

      public_class_method def self.delete_jobs_by_regex(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        regex = opts[:regex].to_s.scrub

        jenkins_obj.job.list_all_with_details.each do |job|
          job_name = job['name']
          if job_name.match?(/#{regex}/)
            @@logger.info("Deleting #{job_name}")
            jenkins_obj.job.delete(job_name)
          end
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.clear_build_queue(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method',
      # )

      public_class_method def self.clear_build_queue(opts = {})
        jenkins_obj = opts[:jenkins_obj]

        jenkins_obj.queue.list.each do |job_name|
          @@logger.info("Clearing #{job_name} Build from Queue")
          jenkins_obj.job.stop_build(job_name)
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Jenkins.disconnect(
      #   jenkins_obj: 'required jenkins_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        jenkins_obj = opts[:jenkins_obj]
        @@logger.info('Disconnecting from Jenkins...')
        jenkins_obj = nil
        'complete'
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
          # Run connect and return its result
          #{self}.connect(
            ip: 'required - required host/ip of Jenkins Server',
            port: 'optional - optional tcp port (defaults to 8080',
            username: 'optional - optional username (functionality will be limited if ommitted)',
            api_key: 'optional - optional api_key (functionality will be limited if ommitted)',
            identity_file: 'optional - optional ssh private key path to AuthN w/ Jenkins PREFERRED over username/api_key',
            ssl: 'optional - optional connect over TLS (defaults to true',
            proxy: 'optional - optional debug proxy rest api requests to jenkins (e.g. http://127.0.0.1:8080)'
          )

          # Run create user and return its result
          #{self}.create_user(
            jenkins_obj: 'optional - jenkins obj value consumed by #create_user',
            username: 'optional - username value consumed by #create_user',
            password: 'optional - password value consumed by #create_user',
            fullname: 'optional - fullname value consumed by #create_user',
            email: 'optional - email value consumed by #create_user'
          )

          # Run create ssh credential and return its result
          #{self}.create_ssh_credential(
            jenkins_obj: 'optional - jenkins obj value consumed by #create_ssh_credential',
            username: 'optional - username value consumed by #create_ssh_credential',
            private_key_path: 'optional - private key path value consumed by #create_ssh_credential',
            key_passphrase: 'optional - key passphrase value consumed by #create_ssh_credential',
            credential_id: 'optional - credential id value consumed by #create_ssh_credential',
            description: 'optional - description value consumed by #create_ssh_credential',
            domain: 'optional - FQDN to query (e.g. example.com)',
            scope: 'optional - scope value consumed by #create_ssh_credential'
          )

          # Run get all job git repos and return its result
          #{self}.get_all_job_git_repos(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method'
          )

          # Run list nested jobs and return its result
          #{self}.list_nested_jobs(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method',
            view_path: 'required - required view path to list jobs'
          )

          # Run list nested views and return its result
          #{self}.list_nested_views(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method',
            view_path: 'required - required view path list sub-views'
          )

          # Run create nested view and return its result
          #{self}.create_nested_view(
            jenkins_obj: 'optional - jenkins obj value consumed by #create_nested_view',
            view_name: 'optional - view name value consumed by #create_nested_view',
            create_in_view_path: 'optional - create in view path value consumed by #create_nested_view'
          )

          # Run add job to nested view and return its result
          #{self}.add_job_to_nested_view(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method',
            view_path: 'required - required view path associate job',
            job_name: 'required - required view path attach to a view'
          )

          # Run copy job no fail on exist and return its result
          #{self}.copy_job_no_fail_on_exist(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method',
            existing_job_name: 'required - required existing job to copt to new job',
            new_job_name: 'required - required name of new job'
          )

          # Run disable jobs by regex and return its result
          #{self}.disable_jobs_by_regex(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method',
            regex: 'required - required regex pattern for matching jobs to disable e.g. :regex => ^M[0-9]'
          )

          # Run delete jobs by regex and return its result
          #{self}.delete_jobs_by_regex(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method',
            regex: 'required - required regex pattern for matching jobs to disable e.g. :regex => ^M[0-9]'
          )

          # Run clear build queue and return its result
          #{self}.clear_build_queue(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method'
          )

          # Run disconnect and return its result
          #{self}.disconnect(
            jenkins_obj: 'required - required jenkins_obj returned from #connect method'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
