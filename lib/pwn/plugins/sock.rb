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
      #   protocol: 'optional - :tcp || :udp (defaults to :tcp)',
      #   tls: 'optional - boolean connect to target socket using TLS (defaults to false)'
      # )

      public_class_method def self.connect(opts = {})
        target = opts[:target].to_s.scrub
        port = opts[:port].to_i

        protocol = opts[:protocol]
        protocol ||= :tcp

        # TODO: Add proxy support

        tls = true if opts[:tls]
        tls ||= false

        tls_min_version = OpenSSL::SSL::TLS1_VERSION if tls_min_version.nil?

        case protocol.to_s.to_sym
        when :tcp
          if tls
            sock = TCPSocket.open(target, port)
            tls_context = OpenSSL::SSL::SSLContext.new
            tls_context.set_params(verify_mode: OpenSSL::SSL::VERIFY_NONE)
            tls_context.min_version = tls_min_version
            # tls_context.ciphers = tls_context.ciphers.select do |cipher|
            #   cipher[1] == cipher_tls
            # end
            tls_sock = OpenSSL::SSL::SSLSocket.new(sock, tls_context)
            tls_sock.hostname = target
            sock_obj = tls_sock.connect
            sock_obj.sync_close = true
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
      rescue OpenSSL::SSL::SSLError => e
        case tls_min_version
        when OpenSSL::SSL::TLS1_VERSION
          puts 'Attempting OpenSSL::SSL::TLS1_1_VERSION...'
          # cipher_tls = 'TLSv1.0'
          tls_min_version = OpenSSL::SSL::TLS1_1_VERSION
        when OpenSSL::SSL::TLS1_1_VERSION
          puts 'Attempting OpenSSL::SSL::TLS1_2_VERSION...'
          # cipher_tls = 'TLSv1.2'
          tls_min_version = OpenSSL::SSL::TLS1_2_VERSION
        when OpenSSL::SSL::TLS1_2_VERSION
          puts 'Attempting OpenSSL::SSL::TLS1_3_VERSION...'
          # cipher_tls = 'TLSv1.3'
          tls_min_version = OpenSSL::SSL::TLS1_3_VERSION
        else
          tls_min_version = :abort
        end

        retry unless tls_min_version == :abort
        raise "\n#{e.inspect}" if tls_min_version == :abort
      rescue StandardError => e
        sock_obj = disconnect(sock_obj: sock_obj) unless sock_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Sock.get_random_unused_port(
      #   server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)'
      # )

      public_class_method def self.get_random_unused_port(opts = {})
        server_ip = opts[:server_ip]
        server_ip ||= '127.0.0.1'
        port = -1
        protocol = opts[:protocol]
        protocol ||= :tcp

        port_in_use = true
        while port_in_use
          port = Random.rand(1024..65_535)
          port_in_use = check_port_in_use(
            server_ip: server_ip,
            port: port,
            protocol: protocol
          )
        end

        port
      rescue Errno::ECONNREFUSED,
             Errno::EHOSTUNREACH,
             Errno::ETIMEDOUT
        false
      end

      # Supported Method Parameters::
      # PWN::Plugins::Sock.check_port_in_use(
      #   server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
      #   port: 'required - target port',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)'
      # )

      public_class_method def self.check_port_in_use(opts = {})
        server_ip = opts[:server_ip]
        server_ip ||= '127.0.0.1'
        port = opts[:port]
        protocol = opts[:protocol]
        protocol ||= :tcp

        # TODO: Add proxy support

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
        tls = true if opts[:tls]
        tls ||= false

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
      # cert_obj = PWN::Plugins::Sock.get_tls_cert(
      #   target: 'required - target host or ip',
      #   port: 'optional - target port (defaults to 443)'
      # )

      public_class_method def self.get_tls_cert(opts = {})
        target = opts[:target].to_s.scrub
        port = opts[:port]
        port ||= 443

        tls_sock_obj = connect(
          target: target,
          port: port,
          protocol: :tcp,
          tls: true
        )
        tls_sock_obj.peer_cert
      rescue StandardError => e
        raise e
      ensure
        tls_sock_obj = disconnect(sock_obj: tls_sock_obj) unless tls_sock_obj.nil?
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

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
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

          port = #{self}.get_random_unused_port(
            server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
            protocol: 'optional - :tcp || :udp (defaults to tcp)'
          )

          #{self}.check_port_in_use(
            server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
            port: 'required - target port',
            protocol: 'optional - :tcp || :udp (defaults to tcp)'
          )

          #{self}.listen(
            server_ip: 'required - target host or ip to listen',
            port: 'required - target port',
            protocol: 'optional - :tcp || :udp (defaults to tcp)',
            tls: 'optional - boolean listen on TLS-enabled socket (defaults to false)'
          )

          cert_obj = #{self}.get_tls_cert(
            target: 'required - target host or ip',
            port: 'optional - target port (defaults to 443)'
          )

          sock_obj = #{self}.disconnect(
            sock_obj: 'required - sock_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
