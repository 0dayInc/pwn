# frozen_string_literal: true

require 'msfrpc-client'
require 'yaml'
require 'json'

module PWN
  module Plugins
    # Plugin used to integrate Metasploit into PWN leveraging a listening MSFRPCD daemon.
    module Metasploit
      # Supported Method Parameters::
      # console_obj = PWN::Plugins::Metasploit.connect(
      #   yaml_conf: 'optional -  path to userland yaml (defaults to /pwn/etc/userland/PWN_PROVIDEDR/metasploit/vagrant.yaml)'
      # )

      public_class_method def self.connect(opts = {})
        if opts[:yaml_conf] && File.exist?(opts[:yaml_conf])
          yaml_conf = YAML.load_file(opts[:yaml_conf].to_s.strip.chomp.scrub)
        else
          pwn_root = ENV['PWN_ROOT'] if ENV['PWN_ROOT']
          pwn_provider = ENV['PWN_PROVIDER'] if ENV['PWN_PROVIDER']
          yaml_conf = YAML.load_file("#{pwn_root}/etc/userland/#{pwn_provider}/metasploit/vagrant.yaml")
        end

        msfrpcd_host = yaml_conf['msfrpcd_host'].to_s
        port = yaml_conf['port'].to_i
        username = yaml_conf['username'].to_s
        password = yaml_conf['password'].to_s

        msfrpcd_conn = Msf::RPC::Client.new
        msfrpcd_conn.info[:host] = msfrpcd_host
        msfrpcd_conn.info[:port] = port
        msfrpcd_conn.login(username, password)

        console_obj = {}
        console_obj[:msfrpcd_conn] = msfrpcd_conn
        msfrpcd_resp = msfrpcd_conn.call('console.create')
        session = JSON.parse(msfrpcd_resp.to_json, symbolize_names: true)
        console_obj[:session] = session

        console_obj
      rescue StandardError => e
        raise "#{e}\nIs the msfrpcd daemon running on #{msfrpcd_host}?"
      end

      # Supported Method Parameters::
      # console_obj = PWN::Plugins::Metasploit.queue_console_cmd(
      #   console_obj: 'required - console_obj object returned from #connect method',
      #   cmd: 'required - msfconsole command string or array of strings'
      # )
      private_class_method def self.queue_console_cmd(opts = {})
        console_obj = opts[:console_obj]
        cmd = opts[:cmd].to_s.strip.chomp.scrub

        msfrpcd_conn = console_obj[:msfrpcd_conn]
        console_obj[:last_cmd] = cmd
        console_id = console_obj[:session][:id]
        msfrpcd_conn.call('console.read', console_id)
        msfrpcd_conn.call('console.write', console_id, "#{cmd}\n")

        loop do
          sleep(1)
          msfrpcd_resp = msfrpcd_conn.call('console.read', console_id)
          next unless msfrpcd_resp.instance_of?(Hash)

          last_cmd_result = JSON.parse(msfrpcd_resp.to_json, symbolize_names: true)
          console_obj[:last_cmd_result] = last_cmd_result

          if console_obj[:last_cmd_result][:busy] == true
            print '.'
            next
          end
          puts "\n#{console_obj[:last_cmd_result][:data]}" unless console_obj[:last_cmd_result][:data].nil?
          break
        end

        console_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # console_obj = PWN::Plugins::Metasploit.console_exec(
      #   console_obj: 'required - console_obj object returned from #connect method',
      #   cmd: 'required - msfconsole command string or array of strings'
      # )
      public_class_method def self.console_exec(opts = {})
        console_obj = opts[:console_obj]
        cmd = opts[:cmd]

        case cmd
        when String
          console_obj = queue_console_cmd(console_obj: console_obj, cmd: cmd)
        when Array
          cmd.each { |this_cmd| console_obj = queue_console_cmd(console_obj: console_obj, cmd: this_cmd) }
        else
          raise "ERROR: cmd parameter must be a String or Array object - object is currently #{cmd.class}"
        end

        console_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # console_obj = PWN::Plugins::Metasploit.disconnect(
      #   console_obj: 'required - console_obj returned from #console_exec method to terminate'
      # )
      public_class_method def self.disconnect(opts = {})
        console_obj = opts[:console_obj]
        msfrpcd_conn = console_obj[:msfrpcd_conn]
        console_id = console_obj[:session][:id]
        msfrpcd_conn.call('console.destroy', console_id)
        msfrpcd_conn.call('auth.logout', msfrpcd_conn.token)

        console_obj = nil
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
        puts "USAGE:
          console_obj = #{self}.connect(
            yaml_conf: 'optional -  path to userland yaml (defaults to $PWN_ROOT/etc/userland/$PWN_PROVIDER/metasploit/vagrant.yaml)'
          )

          console_obj = #{self}.console_exec(
            console_obj: 'required - msfrpcd_conn object returned from #connect method',
            cmd: 'required - msfconsole command string or array of strings'
          )

          console_obj = #{self}.disconnect(
            console_obj: 'required - msfrpcd_conn object returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
