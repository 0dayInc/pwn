# frozen_string_literal: true

require 'openssl'

module PWN
  module Plugins
    # This plugin was created to interact with IRC protocols
    module IRC
      @@logger = PWN::Plugins::PWNLogger.create

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

        send(irc_obj: irc_obj, message: "NICK #{nick}")
        irc_obj.gets
        irc_obj.flush

        send(irc_obj: irc_obj, message: "USER #{nick} #{host} #{host} :#{real}")
        irc_obj.gets
        irc_obj.flush

        irc_obj
      rescue StandardError => e
        irc_obj = disconnect(irc_obj: irc_obj) unless irc_obj.nil?
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

        send(irc_obj: irc_obj, message: "PING :#{message}")
        irc_obj.gets
        irc_obj.flush
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

        send(irc_obj: irc_obj, message: "PONG :#{message}")
        irc_obj.gets
        irc_obj.flush
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
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
              send(
                irc_obj: irc_obj,
                message: this_message
              )
            end
          end
        else
          send(irc_obj: irc_obj, message: "PRIVMSG #{chan} :#{message}")
        end
      rescue StandardError => e
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

        send(irc_obj: irc_obj, message: "JOIN #{chan}")
        irc_obj.gets
        irc_obj.flush

        privmsg(irc_obj: irc_obj, message: "#{nick} joined.")
        irc_obj.gets
        irc_obj.flush
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

        send(irc_obj: irc_obj, message: "PART #{chan} :#{message}")
        irc_obj.gets
        irc_obj.flush
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

        send(irc_obj: irc_obj, message: "QUIT :#{message}")
        irc_obj.gets
        irc_obj.flush
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
        verbose = opts[:verbose] || false

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
      # PWN::Plugins::IRC.send(
      #   irc_obj: 'required - irc_obj returned from #connect method',
      #   message: 'required - message to send',
      # )
      private_class_method def self.send(opts = {})
        irc_obj = opts[:irc_obj]
        message = opts[:message].to_s.scrub

        irc_obj.puts(message)
        irc_obj.flush
      rescue StandardError => e
        raise e
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
            chan: 'required - channel',
            tls: 'optional - boolean connect to host socket using TLS (defaults to false)'
          )

          #{self}.join(
            irc_obj: 'required - irc_obj returned from #connect method',
            nick: 'required - nickname',
            chan: 'required - channel to join'
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
