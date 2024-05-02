# frozen_string_literal: true

require 'netaddr'
require 'pty'

module PWN
  module Plugins
    # This plugin processes images into readable text
    module Tor
      # Supported Method Parameters::
      # tor_ctrl_cmd(
      #   tor_obj: 'required - tor_obj returned from #start method'
      #   cmd: 'required - Tor control command to execute',
      #   response_timeout: 'optional - float in seconds to timeout (default: 3.0)'
      # )

      private_class_method def self.tor_control_cmd(opts = {})
        tor_obj = opts[:tor_obj]
        cmd = opts[:cmd]
        response_timeout = opts[:response_timeout]
        response_timeout ||= 3.0

        ctrl_ip = tor_obj[:ip]
        ctrl_port = tor_obj[:ctrl_port]
        cookie_authn = tor_obj[:cookie_authn]

        sock_obj = PWN::Plugins::Sock.connect(
          target: ctrl_ip,
          port: ctrl_port
        )

        cmd_hist_arr = []
        cmd_hash = { cmd: "AUTHENTICATE #{cookie_authn}\r\n" }
        sock_obj.write(cmd_hash[:cmd])
        does_respond = sock_obj.wait_readable(response_timeout)
        if does_respond
          response = sock_obj.readline.chomp
          cmd_hash[:resp] = response
          cmd_hist_arr.push(cmd_hash)
          if response == '250 OK'
            cmd_hash = { cmd: "#{cmd}\r\n" }
            sock_obj.write(cmd_hash[:cmd])
            does_respond = sock_obj.wait_readable(response_timeout)
            if does_respond
              response = sock_obj.readline.chomp
              cmd_hash[:resp] = response
              cmd_hist_arr.push(cmd_hash)
              if response == '250 OK'
                cmd_hash = { cmd: "QUIT\r\n" }
                sock_obj.write(cmd_hash[:cmd])
                does_respond = sock_obj.wait_readable(response_timeout)
                if does_respond
                  response = sock_obj.readline.chomp
                else
                  response = '900 NO CMD RESPONSE'
                end
              end
            else
              response = '900 NO CMD RESPONSE'
            end
            cmd_hash[:resp] = response
            cmd_hist_arr.push(cmd_hash)
          end
        else
          response = '700 NO AUTHENTICATE RESPONSE'
          cmd_hash[:resp] = response
          cmd_hist_arr.push(cmd_hash)
        end
        sock_obj = PWN::Plugins::Sock.disconnect(sock_obj: sock_obj)

        cmd_hist_arr
      rescue StandardError => e
        stop(tor_obj: tor_obj)
      end

      # Supported Method Parameters::
      # tor_obj = PWN::Plugins::Tor.start(
      #   ip: 'optional - IP address to listen (default: 127.0.0.1)',
      #   port: 'optional - socks port to listen (default: 1024-65535)',
      #   ctrl_port: 'optional - tor control port to listen (default: 1024-65535)',
      #   net: 'optional - CIDR notation to accept connections (default: 127.0.0.0.1/32)',
      #   data_dir: 'optional - directory to keep tor session data (default: /tmp/tor_pwn-TIMESTAMP)'
      # )

      public_class_method def self.start(opts = {})
        ip = opts[:ip]
        ip ||= '127.0.0.1'
        port = opts[:port].to_i
        port = PWN::Plugins::Sock.get_random_unused_port if port.zero?
        ctrl_port = opts[:ctrl_port].to_i
        if ctrl_port.zero?
          loop do
            ctrl_port = PWN::Plugins::Sock.get_random_unused_port
            break if ctrl_port != port
          end
        end

        net = opts[:net]
        net ||= "#{ip}/32"
        acl_net = NetAddr.parse_net(net)

        timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S.%N%z')
        data_dir = opts[:data_dir]
        data_dir ||= "/tmp/tor_pwn-#{timestamp}"
        FileUtils.mkdir_p(data_dir)

        socks_proxy = "#{ip}:#{port}"
        pid_file = "#{data_dir}/tor.pid"
        cookie_authn_file = "#{data_dir}/control_auth_cookie"
        session_log_path = "#{data_dir}/stdout-session.log"
        session_log = File.new(session_log_path, 'w')
        session_log.sync = true
        session_log.fsync

        fork_pid = Process.fork do
          pty = PTY.spawn(
            'tor',
            'DataDirectory',
            data_dir,
            'SocksPort',
            socks_proxy,
            'ControlPort',
            ctrl_port.to_s,
            'CookieAuthentication',
            '1',
            'SocksPolicy',
            "accept #{acl_net}",
            'SocksPolicy',
            'reject *'
          ) do |stdout, _stdin, pid|
            File.write(pid_file, pid)
            stdout.each do |line|
              session_log.puts line
            end
          end
        rescue StandardError => e
          puts 'Tor exiting with errors...'
          FileUtils.rm_rf(data_dir)
          raise e
        end
        Process.detach(fork_pid)

        loop do
          pid_ready = File.exist?(pid_file)
          cookie_authn_ready = File.exist?(cookie_authn_file)
          sleep 0.1
          break if pid_ready && cookie_authn_ready
        end

        cookie_authn = `hexdump -e '32/1 "%02x"' #{cookie_authn_file}`
        tor_obj = {
          parent_pid: fork_pid,
          child_pid: File.read(pid_file).to_i,
          ip: ip,
          port: port,
          ctrl_port: ctrl_port,
          data_dir: data_dir,
          cookie_authn: cookie_authn
        }
      rescue StandardError, SystemExit => e
        stop(tor_obj) unless tor_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Tor.switch_exit_node(
      #   tor_obj: 'required - tor_obj returned from #start method',
      #   response_timeout: 'optional - float in seconds to timeout (default: 3.0)'
      # )

      public_class_method def self.switch_exit_node(opts = {})
        tor_obj = opts[:tor_obj]
        response_timeout = opts[:response_timeout]
        tor_control_cmd(
          tor_obj: tor_obj,
          cmd: 'SIGNAL NEWNYM',
          response_timeout: response_timeout
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Tor.stop(
      #   tor_obj: 'required - tor_obj returned from #start method'
      # )

      public_class_method def self.stop(opts = {})
        tor_obj = opts[:tor_obj]
        unless tor_obj.nil?
          FileUtils.rm_rf(tor_obj[:data_dir])
          Process.kill('TERM', tor_obj[:child_pid])
          Process.kill('TERM', tor_obj[:parent_pid])
        end
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
          tor_obj = #{self}.start(
            ip: 'optional - IP address to listen (default: 127.0.0.1)',
            port: 'optional - socks port to listen (default: 9050)',
            ctrl_port: 'optional - tor control port to listen (default: 9051)',
            net: 'optional - CIDR notation to accept connections (default: 127.0.0.1/32)',
            data_dir: 'optional - directory to keep tor session data (default: /tmp/tor_pwn-TIMESTAMP)'
          )

          #{self}.switch_exit_node(
            tor_obj: 'required - tor_obj returned from #start method',
            response_timeout: 'optional - float in seconds to timeout (default: 3.0)'
          )

          #{self}.stop(
            tor_obj: 'required - tor_obj returned from #start method'
          )

          #{self}.authors
        "
      end
    end
  end
end
