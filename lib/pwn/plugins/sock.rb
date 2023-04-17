# frozen_string_literal: true

require 'socket'
require 'openssl'

module PWN
  module Plugins
    # This plugin was created to support fuzzing various networking protocols
    module Sock
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # sock_obj = PWN::Plugins::Sock.connect(
      #   target: 'required - target host or ip',
      #   port: 'required - target port',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)',
      #   tls: 'optional - boolean connect to target socket using TLS (defaults to false)'
      # )

      public_class_method def self.connect(opts = {})
        target = opts[:target].to_s.scrub
        port = opts[:port].to_i
        opts[:protocol].nil? ? protocol = :tcp : protocol = opts[:protocol].to_s.downcase.to_sym
        opts[:tls].nil? ? tls = false : tls = true

        case protocol
        when :tcp
          if tls
            sock = TCPSocket.open(target, port)
            tls_context = OpenSSL::SSL::SSLContext.new
            tls_context.set_params(verify_mode: OpenSSL::SSL::VERIFY_NONE)
            tls_sock = OpenSSL::SSL::SSLSocket.new(sock, tls_context)
            sock_obj = tls_sock.connect
          else
            sock_obj = TCPSocket.open(target, port)
          end
        when :udp
          sock_obj = UDPSocket.new
          sock_obj.connect(target, port)
        else
          raise "Unsupported protocol: #{protocol}"
        end

        sock_obj
      rescue StandardError => e
        sock_obj = disconnect(sock_obj: sock_obj) unless sock_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Sock.check_port_in_use(
      #   port: 'required - target port',
      #   server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)'
      # )

      public_class_method def self.check_port_in_use(opts = {})
        server_ip = opts[:server_ip]
        server_ip ||= '127.0.0.1'
        port = opts[:port]
        protocol = opts[:protocol]
        protocol ||= :tcp

        ct = 1
        s = Socket.tcp(server_ip, port, connect_timeout: ct) if protocol == :tcp
        s = Socket.udp(server_ip, port, connect_timeout: ct) if protocol == :udp
        s.close

        true
      rescue Errno::ECONNREFUSED,
             Errno::EHOSTUNREACH,
             Errno::ETIMEDOUT
        false
      end

      # Supported Method Parameters::
      # PWN::Plugins::Sock.listen(
      #   server_ip: 'required - target host or ip to listen',
      #   port: 'required - target port',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)',
      #   tls: 'optional - boolean listen on TLS-enabled socket (defaults to false)'
      # )

      public_class_method def self.listen(opts = {})
        server_ip = opts[:server_ip].to_s.scrub
        port = opts[:port].to_i
        opts[:protocol].nil? ? protocol = :tcp : protocol = opts[:protocol].to_s.downcase.to_sym
        opts[:tls].nil? ? tls = false : tls = true

        case protocol
        when :tcp
          if tls
            # Multi-threaded - Not working
            sock = TCPServer.open(server_ip, port)
            tls_context = OpenSSL::SSL::SSLContext.new
            tls_context.set_params(verify_mode: OpenSSL::SSL::VERIFY_NONE)
            listen_obj = OpenSSL::SSL::SSLServer.new(sock, tls_context)
            # loop do
            #   Thread.start(listen_obj.accept) do |client_thread|
            #     while (client_input = client_thread.gets)
            #       puts client_input
            #     end
            #     client_thread.close
            #   end
            # end
          else
            # Multi-threaded
            listen_obj = TCPServer.open(server_ip, port)
            loop do
              Thread.start(listen_obj.accept) do |client_thread|
                while (client_input = client_thread.gets)
                  puts client_input
                end
                client_thread.close
              end
            end
          end
        when :udp
          # Single Threaded
          listen_obj = UDPSocket.new
          listen_obj.bind(server_ip, port)
          while (client_input = listen_obj.recvmsg)
            puts client_input[0]
          end
        else
          raise "Unsupported protocol: #{protocol}"
        end
      rescue StandardError => e
        raise e
      ensure
        listen_obj = disconnect(sock_obj: listen_obj) unless listen_obj.nil?
      end

      # Supported Method Parameters::
      # sock_obj = PWN::Plugins::Sock.disconnect(
      #   sock_obj: 'required - sock_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        sock_obj = opts[:sock_obj]
        sock_obj.close
        sock_obj = nil
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          sock_obj = #{self}.connect(
            target: 'required - target host or ip',
            port: 'required - target port',
            protocol: 'optional - :tcp || :udp (defaults to tcp)',
            tls: 'optional - boolean connect to target socket using TLS (defaults to false)'
          )

          #{self}.check_port_availability(
            port: 'required - target port',
            server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
            protocol: 'optional - :tcp || :udp (defaults to tcp)'
          )

          #{self}.listen(
            server_ip: 'required - target host or ip to listen',
            port: 'required - target port',
            protocol: 'optional - :tcp || :udp (defaults to tcp)',
            tls: 'optional - boolean listen on TLS-enabled socket (defaults to false)'
          )

          sock_obj = PWN::Plugins::Sock.disconnect(
            sock_obj: 'required - sock_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
