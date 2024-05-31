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
        cmd = opts[:cmd].to_s.scrub
        max_timeout = opts[:max_timeout] ||= 0.009

        readl_timeout = 0.001
        irc_obj.puts(cmd)
        response = []

        begin
          response.push(irc_obj.readline.chomp) while irc_obj.wait_readable(readl_timeout) && irc_obj.ready? && !irc_obj.eof?
          raise IOError if response.empty?
        rescue IOError
          readl_timeout += 0.001
          retry if readl_timeout < max_timeout
          return response if readl_timeout >= max_timeout
        end

        response
      rescue StandardError => e
        raise e
      ensure
        irc_obj.flush
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
        nick = opts[:nick].to_s.scrub
        real = opts[:real] ||= nick
        tls = opts[:tls] || false

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
        nick = opts[:nick].to_s.scrub
        chan = opts[:chan].to_s.scrub

        irc_cmd(irc_obj: irc_obj, cmd: "JOIN #{chan}")
        privmsg(irc_obj: irc_obj, message: "#{nick} joined.")
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
        chan = opts[:chan].to_s.scrub

        resp = irc_cmd(irc_obj: irc_obj, cmd: "NAMES #{chan}", max_timeout: 0.01)
        names = []
        raw_names = resp.first.to_s.split[5..-1]
        # Strip out colons and @ from names
        names = raw_names.map { |name| name.gsub(/[@:]/, '') } if raw_names.is_a?(Array)

        names
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
        chan = opts[:chan].to_s.scrub
        message = opts[:message].to_s.scrub
        nick = opts[:nick].to_s.scrub

        message_newline_tot = message.split("\n").length
        if message_newline_tot.positive?
          message.split("\n") do |message_chunk|
            this_message = "PRIVMSG #{chan} :#{message_chunk}"
            if message_chunk.length.positive?
              irc_cmd(
                irc_obj: irc_obj,
                cmd: this_message
              )
            end
          end
        else
          irc_cmd(irc_obj: irc_obj, cmd: "PRIVMSG #{chan} :#{message}")
        end
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
        chan = opts[:chan].to_s.scrub
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
          message = irc_obj.gets
          @@logger.info(message.to_s.chomp) if verbose
          irc_obj.flush
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
          irc_obj = #{self}.connect(
            host: 'required - host or ip',
            port: 'required - host port',
            nick: 'required - nickname',
            real: 'optional - real name (defaults to value of nick)',
            tls: 'optional - boolean connect to host socket using TLS (defaults to false)'
          )

          #{self}.ping(
            irc_obj: 'required - irc_obj returned from #connect method',
            message: 'required - message to send'
          )

          #{self}.pong(
            irc_obj: 'required - irc_obj returned from #connect method',
            message: 'required - message to send'
          )

          #{self}.privmsg(
            irc_obj: 'required - irc_obj returned from #connect method',
            chan: 'required - channel to send message',
            message: 'required - message to send'
          )

          #{self}.join(
            irc_obj: 'required - irc_obj returned from #connect method',
            nick: 'required - nickname',
            chan: 'required - channel to join'
          )

          #{self}.names(
            irc_obj: 'required - irc_obj returned from #connect method',
            chan: 'required - channel to list names'
          )

          #{self}.part(
            irc_obj: 'required - irc_obj returned from #connect method',
            chan: 'required - channel to part',
            message: 'optional - message to send when parting'
          )

          #{self}.quit(
            irc_obj: 'required - irc_obj returned from #connect method',
            message: 'optional - message to send when quitting'
          )

          #{self}.listen(
            irc_obj: 'required - irc_obj returned from #connect method',
            verbose: 'optional - boolean to enable verbose output (defaults to false)'
          )

          irc_obj = #{self}.disconnect(
            irc_obj: 'required - irc_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
