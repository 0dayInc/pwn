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
      #   port: 'required - target port',
      #   server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)'
      # )

      public_class_method def self.check_port_in_use(opts = {})
        server_ip = opts[:server_ip] ||= '127.0.0.1'
        port      = opts[:port]
        protocol  = (opts[:protocol] ||= :tcp).to_s.downcase.to_sym

        ct = 0.5 # connect timeout in seconds

        case protocol
        when :tcp
          # Use &:close intead of block
          Socket.tcp(server_ip, port, connect_timeout: ct, &:close)
          # Port is already in use (or no permission)
          true

        when :udp
          socket = UDPSocket.new
          socket.bind(server_ip, port)
          # Port is NOT in use (or at least we can use it)
          false
        else
          raise "Unsupported protocol: #{protocol}"
        end
      rescue Errno::EADDRINUSE, # address already in use
             Errno::EACCES # permission denied

        state = true if protocol == :udp
        state = false if protocol == :tcp

        state
      rescue Errno::ECONNREFUSED, # connection refused (usually means port exists but no listener)
             Errno::EHOSTUNREACH, # host unreachable
             Errno::ETIMEDOUT # connection timed out

        # Port is NOT in use (or at least we can use it)
        false
      rescue SocketError => e
        # Usually means invalid address / interface
        raise "Socket error while checking port #{port}: #{e.message}"
      rescue StandardError => e
        warn "[!] Unexpected error while checking port: #{e.class} – #{e.message}"
        false
      ensure
        socket.close if protocol == :udp && !socket.nil?
      end

      # Supported Method Parameters::
      # listen_obj = PWN::Plugins::Sock.listen(
      #   port: 'required - target port',
      #   server_ip: 'optional - target host or ip to listen (Defaults to 127.0.0.1')',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)',
      #   tls: 'optional - boolean listen on TLS-enabled socket (defaults to false)',
      #   detach: 'optional - boolean to detach listener to background (defaults to false)'
      # )

      public_class_method def self.listen(opts = {})
        port = opts[:port]
        raise 'ERROR: Missing required parameter: port' if port.nil?

        server_ip = opts[:server_ip] ||= '127.0.0.1'
        protocol = (opts[:protocol] ||= :tcp).to_s.downcase.to_sym
        tls = opts[:tls] || false
        detach = opts[:detach] || false

        listen_obj = nil

        case protocol
        when :tcp
          server = TCPServer.open(server_ip, port)

          if tls
            tls_context = OpenSSL::SSL::SSLContext.new
            tls_context.set_params(verify_mode: OpenSSL::SSL::VERIFY_NONE)
            # TODO: min_version, ciphers, etc.
            listen_obj = OpenSSL::SSL::SSLServer.new(server, tls_context)
          else
            listen_obj = server
          end

          unless detach
            # Default blocking mode - simple accept-and-handle loop
            # puts "[*] Listening on #{server_ip}:#{port} (#{tls ? 'TLS' : 'plain'} TCP)..."

            loop do
              client = listen_obj.accept
              Thread.new(client) do |c|
                peer = c.peeraddr
                puts "[+] Connection from #{peer}"

                while (data = c.gets)
                  puts "[#{peer}] #{data.strip}"
                  # Optional: echo back
                  # c.puts "ECHO: #{data}"
                end
              rescue Errno::ECONNRESET, Errno::EPIPE, IOError
                # Client disconnected
              ensure
                client.close unless client.nil?
              end
            end
          end

        when :udp
          listen_obj = UDPSocket.new
          listen_obj.bind(server_ip, port)

          # puts "[*] Listening on #{server_ip}:#{port} (UDP)..."

          unless detach
            # Simple single-threaded UDP receive loop
            loop do
              msg, addrinfo = listen_obj.recvmsg
              next unless msg && !msg.empty?

              peer = "#{addrinfo.ip_address}:#{addrinfo.ip_port}"
              puts "[#{peer}] #{msg.inspect}"
              # Optional: echo back
              # listen_obj.send("ECHO: #{msg}", 0, addrinfo.ip_address, addrinfo.ip_port)
            end
          end

        else
          raise "Unsupported protocol: #{protocol}"
        end

        loop do
          listening = check_port_in_use(
            server_ip: server_ip,
            port: port,
            protocol: protocol
          )
          break if listening
        end

        listen_obj
      rescue Interrupt
        puts "\n[!] Caught interrupt, shutting down listener..."
      rescue StandardError => e
        raise
      ensure
        listen_obj.close unless listen_obj.nil? || detach
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
        return unless sock_obj.respond_to?(:close)

        # Shutdown both directions to terminate flows immediately
        # sock_obj.shutdown(Socket::SHUT_RDWR)

        # Set SO_LINGER=0 to force RST (skips TIME_WAIT; ideal for fuzzing)
        # linger = [1, 0].pack('ii')
        # sock_obj.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, linger)

        sock_obj.close
      rescue StandardError => e
        raise e
      ensure
        sock_obj = nil
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
            target: 'required - target host or ip',
            port: 'required - target port',
            protocol: 'optional - :tcp || :udp (defaults to :tcp)',
            tls: 'optional - boolean connect to target socket using TLS (defaults to false)'
          )

          # Run get random unused port and return its result
          #{self}.get_random_unused_port(
            server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
            protocol: 'optional - :tcp || :udp (defaults to tcp)'
          )

          # Run check port in use and return its result
          #{self}.check_port_in_use(
            port: 'required - target port',
            server_ip: 'optional - target host or ip to check (Defaults to 127.0.0.1)',
            protocol: 'optional - :tcp || :udp (defaults to tcp)'
          )

          # Run listen and return its result
          #{self}.listen(
            port: 'required - target port',
            server_ip: 'optional - target host or ip to listen (Defaults to 127.0.0.1)',
            protocol: 'optional - :tcp || :udp (defaults to tcp)',
            tls: 'optional - boolean listen on TLS-enabled socket (defaults to false)',
            detach: 'optional - boolean to detach listener to background (defaults to false)'
          )

          # Run get tls cert and return its result
          #{self}.get_tls_cert(
            target: 'required - target host or ip',
            port: 'optional - target port (defaults to 443)'
          )

          # Run disconnect and return its result
          #{self}.disconnect(
            sock_obj: 'required - sock_obj returned from #connect method'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
