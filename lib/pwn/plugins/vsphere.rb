# frozen_string_literal: true

require 'rbvmomi'

module PWN
  module Plugins
    # This plugin is used for interacting w/ VMware ESXI's REST API
    module Vsphere
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # vsphere_obj = PWN::Plugins::Vsphere.login(
      #   host: 'required - vsphere host or ip',
      #   username: 'required - username',
      #   password: 'optional - password (will prompt if nil)',
      #   insecure: 'optional - ignore ssl checks (defaults to false)
      # )

      public_class_method def self.login(opts = {})
        host = opts[:host].to_s.scrub
        username = opts[:username].to_s.scrub
        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s.scrub
                   end
        insecure = opts[:insecure] ||= false

        @@logger.info("Logging into vSphere: #{host}")
        RbVmomi::VIM.connect(
          host: host,
          user: username,
          password: password,
          insecure: insecure
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::HackerOne.logout(
      #   vsphere_obj: 'required vsphere_obj returned from #login method'
      # )

      public_class_method def self.logout(opts = {})
        vsphere_obj = opts[:vsphere_obj]
        @@logger.info('Logging out...')
        vsphere_obj = nil
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
          vsphere_obj = #{self}.login(
            host: 'required - vsphere host or ip',
            username: 'required - username',
            password: 'optional - password (will prompt if nil)',
            insecure: 'optional - ignore ssl checks (defaults to false)
          )

          vsphere_obj = #{self}.logout(
            vsphere_obj: 'required vsphere_obj returned from #login method'
          )

          #{self}.authors
        "
      end
    end
  end
end
