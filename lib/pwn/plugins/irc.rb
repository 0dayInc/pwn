# frozen_string_literal: true

require 'openssl'

module PWN
  module Plugins
    # This plugin was created to interact with IRC protocols
    module IRC
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # resp = PWN::Plugins::IRC.irc_cmd(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   cmd: 'required - cmd to send',
      # )
      private_class_method def self.irc_cmd(opts = {})
        irc_obj = opts[:irc_obj]
        frame = command_frame(cmd: opts[:cmd])
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + opts.fetch(:max_timeout, 0.009)
        irc_obj.write(frame)
        response = []
        loop do
          line = read_frame(irc_obj: irc_obj, deadline: deadline)
          break if line.nil? || line == :timeout

          response << line.chomp
          break if response.length >= 128
        end
        response
      end

      private_class_method def self.read_frame(opts = {})
        irc_obj = opts[:irc_obj]
        buffer = irc_obj.instance_variable_get(:@pwn_irc_buffer)
        unless buffer
          buffer = ''.b
          irc_obj.instance_variable_set(:@pwn_irc_buffer, buffer)
        end
        loop do
          newline = buffer.index("\n")
          return buffer.slice!(0, newline + 1) if newline && newline < 512
          raise IOError, 'Oversized IRC response frame' if buffer.bytesize >= 512

          remaining = opts[:deadline] - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return :timeout unless remaining.positive?

          chunk = irc_obj.read_nonblock(512 - buffer.bytesize, exception: false)
          case chunk
          when :wait_readable then return :timeout unless irc_obj.wait_readable(remaining)
          when :wait_writable then return :timeout unless irc_obj.wait_writable(remaining)
          when nil then return nil
          else buffer << chunk
          end
        end
      end

      private_class_method def self.command_frame(opts = {})
        cmd = opts[:cmd].to_s.scrub
        raise ArgumentError, 'Invalid IRC command frame' if cmd.match?(/[\r\n\x00]/) || cmd.bytesize > 510

        "#{cmd}\r\n"
      end

      private_class_method def self.parameter(opts = {})
        value = opts[:value].to_s.scrub
        raise ArgumentError, 'Invalid IRC parameter' if value.empty? || value.match?(/[\s\x00:]/)

        value
      end

      # Supported Method Parameters::
      # irc_obj = PWN::Plugins::IRC.connect(
      #   host: 'required - host or ip (defaults to "127.0.0.1")',
      #   port: 'required - host port (defaults to 6667)',
      #   nick: 'required - nickname',
      #   real: 'optional - real name (defaults to value of nick)',
      #   tls: 'optional - boolean connect to host socket using TLS (defaults to false)'
      # )

      public_class_method def self.connect(opts = {})
        host = opts[:host] ||= '127.0.0.1'
        port = opts[:port] ||= 6667
        nick = parameter(value: opts[:nick])
        real = opts[:real] ||= nick
        tls = opts[:tls] || false

        parameter(value: host)
        command_frame(cmd: "NICK #{nick}")
        command_frame(cmd: "USER #{nick} #{host} #{host} :#{real}")

        irc_obj = PWN::Plugins::Sock.connect(
          target: host,
          port: port,
          tls: tls
        )

        irc_cmd(irc_obj: irc_obj, cmd: "NICK #{nick}")
        irc_cmd(
          irc_obj: irc_obj,
          cmd: "USER #{nick} #{host} #{host} :#{real}",
          max_timeout: 0.1
        )

        irc_obj
      rescue StandardError => e
        irc_obj = disconnect(irc_obj: irc_obj) unless irc_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.join(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   nick: 'required - nickname',
      #   chan: 'required - channel to join'
      # )
      public_class_method def self.join(opts = {})
        irc_obj = opts[:irc_obj]
        nick = parameter(value: opts[:nick])
        chan = parameter(value: opts[:chan])
        command_frame(cmd: "PRIVMSG #{chan} :#{nick} joined.")

        irc_cmd(irc_obj: irc_obj, cmd: "JOIN #{chan}")
        privmsg(irc_obj: irc_obj, chan: chan, message: "#{nick} joined.")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.names(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   chan: 'required - channel to list names'
      # )
      public_class_method def self.names(opts = {})
        irc_obj = opts[:irc_obj]
        chan = parameter(value: opts[:chan])

        resp = irc_cmd(irc_obj: irc_obj, cmd: "NAMES #{chan}", max_timeout: 0.01)
        resp.flat_map do |line|
          fields, trailing = line.split(' :', 2)
          header = fields.split
          next [] unless header[1] == '353' && header[4] == chan && trailing

          trailing.split.map { |name| name.sub(/\A[~&@%+]+/, '') }
        end.uniq
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      #
      # PWN::Plugins::IRC.privmsg(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   chan: 'required - channel to send message',
      #   message: 'required - message to send',
      # )
      public_class_method def self.privmsg(opts = {})
        irc_obj = opts[:irc_obj]
        chan = parameter(value: opts[:chan])
        message = opts[:message].to_s.scrub
        nick = opts[:nick].to_s.scrub

        commands = message.split("\n").reject(&:empty?).map { |chunk| "PRIVMSG #{chan} :#{chunk}" }
        commands.each { |cmd| command_frame(cmd: cmd) }
        # Prevalidate the whole batch before the first frame leaves the socket.
        commands.each { |cmd| irc_cmd(irc_obj: irc_obj, cmd: cmd) } # rubocop:disable Style/CombinableLoops
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.ping(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   message: 'required - message to send'
      # )
      public_class_method def self.ping(opts = {})
        irc_obj = opts[:irc_obj]
        message = opts[:message].to_s.scrub

        irc_cmd(irc_obj: irc_obj, cmd: "PING :#{message}")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.pong(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   message: 'required - message to send'
      # )
      public_class_method def self.pong(opts = {})
        irc_obj = opts[:irc_obj]
        message = opts[:message].to_s.scrub

        irc_cmd(irc_obj: irc_obj, cmd: "PONG :#{message}")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.part(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   chan: 'required - channel to part',
      #   message: 'optional - message to send when parting'
      # )
      public_class_method def self.part(opts = {})
        irc_obj = opts[:irc_obj]
        chan = parameter(value: opts[:chan])
        message = opts[:message].to_s.scrub

        irc_cmd(irc_obj: irc_obj, cmd: "PART #{chan} :#{message}")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.quit(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   message: 'optional - message to send when quitting'
      # )
      public_class_method def self.quit(opts = {})
        irc_obj = opts[:irc_obj]
        message = opts[:message].to_s.scrub

        irc_cmd(irc_obj: irc_obj, cmd: "QUIT :#{message}")
      rescue StandardError => e
        raise e
      ensure
        disconnect(irc_obj: irc_obj) unless irc_obj.nil?
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.listen(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   verbose: 'optional - boolean to enable verbose output (defaults to false)'
      # )

      public_class_method def self.listen(opts = {})
        irc_obj = opts[:irc_obj]
        verbose = opts[:verbose] ||= false

        loop do
          message = read_frame(irc_obj: irc_obj, deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.1)
          break if message.nil?
          next if message == :timeout

          @@logger.info(message.to_s.chomp) if verbose
          next unless block_given?

          yield message
        end
      rescue StandardError => e
        raise e
      ensure
        disconnect(irc_obj: irc_obj)
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.disconnect(
      #   irc_obj: 'required - irc_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        irc_obj = opts[:irc_obj]
        PWN::Plugins::Sock.disconnect(sock_obj: irc_obj) unless irc_obj.nil?
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
            host: 'required - host or ip (defaults to 127.0.0.1)',
            port: 'required - host port (defaults to 6667)',
            nick: 'required - nick value consumed by #connect',
            real: 'optional - real name (defaults to value of nick)',
            tls: 'optional - boolean connect to host socket using TLS (defaults to false)'
          )

          # Run join and return its result
          #{self}.join(
            irc_obj: 'required - irc_obj returned from #connect method',
            nick: 'required - nick value consumed by #join',
            chan: 'required - channel to join'
          )

          # Run names and return its result
          #{self}.names(
            irc_obj: 'required - irc_obj returned from #connect method',
            chan: 'required - channel to list names'
          )

          # Run privmsg and return its result
          #{self}.privmsg(
            irc_obj: 'required - irc_obj returned from #connect method',
            chan: 'required - channel to send message',
            message: 'required - message to send',
            nick: 'optional - nick value consumed by #privmsg'
          )

          # Run ping and return its result
          #{self}.ping(
            irc_obj: 'required - irc_obj returned from #connect method',
            message: 'required - message to send'
          )

          # Run pong and return its result
          #{self}.pong(
            irc_obj: 'required - irc_obj returned from #connect method',
            message: 'required - message to send'
          )

          # Run part and return its result
          #{self}.part(
            irc_obj: 'required - irc_obj returned from #connect method',
            chan: 'required - channel to part',
            message: 'optional - message to send when parting'
          )

          # Run quit and return its result
          #{self}.quit(
            irc_obj: 'required - irc_obj returned from #connect method',
            message: 'optional - message to send when quitting'
          )

          # Run listen and return its result
          #{self}.listen(
            irc_obj: 'required - irc_obj returned from #connect method',
            verbose: 'optional - boolean to enable verbose output (defaults to false)'
          )

          # Run disconnect and return its result
          #{self}.disconnect(
            irc_obj: 'required - irc_obj returned from #connect method'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
