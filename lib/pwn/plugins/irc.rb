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
      #   chan: 'required - channel',
      #   tls: 'optional - boolean connect to host socket using TLS (defaults to false)'
      # )

      public_class_method def self.connect(opts = {})
        host = opts[:host] ||= '127.0.0.1'
        port = opts[:port] ||= 6667
        nick = opts[:nick].to_s.scrub
        real = opts[:real] ||= nick
        chan = opts[:chan].to_s.scrub
        tls = opts[:tls] || false

        irc_obj = PWN::Plugins::Sock.connect(
          target: host,
          port: port,
          tls: tls
        )

        send(irc_obj: irc_obj, message: "NICK #{nick}")
        send(irc_obj: irc_obj, message: "USER #{nick} #{host} #{host} :#{real}")
        send(irc_obj: irc_obj, message: "JOIN #{chan}")
        send(irc_obj: irc_obj, message: "PRIVMSG #{chan} :#{nick} joined.")

        irc_obj
      rescue StandardError => e
        irc_obj = disconnect(irc_obj: irc_obj) unless irc_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IRC.listen(
      #   irc_obj: 'required - irc_obj returned from #connect method'
      # )

      public_class_method def self.listen(opts = {})
        irc_obj = opts[:irc_obj]

        loop do
          message = irc_obj.gets
          @@logger.info(message.to_s.chomp)
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
      #   response_timeout: 'optional - response timeout in seconds (defaults to 3)'
      # )
      public_class_method def self.send(opts = {})
        irc_obj = opts[:irc_obj]
        message = opts[:message].to_s.scrub
        response_timeout = opts[:response_timeout] || 3

        irc_obj.puts(message)
        # Wait for a response from the server
        does_respond = irc_obj.wait_readable(response_timeout)
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

          #{self}.listen(
            irc_obj: 'required - irc_obj returned from #connect method'
          )

          #{self}.send(
            irc_obj: 'required - irc_obj returned from #connect method',
            message: 'required - message to send',
            response_timeout: 'optional - response timeout in seconds (defaults to 3)'
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
