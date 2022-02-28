# frozen_string_literal: true

require 'base64'
require 'cgi'
require 'htmlentities'

module PWN
  module Plugins
    # This plugin was created to support fuzzing various networking protocols
    module Fuzz
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # socket_fuzz_results_arr = PWN::Plugins::Fuzz.socket(
      #   target: 'required - target host or ip',
      #   port: 'required - target port',
      #   protocol: 'optional - :tcp || :udp (defaults to tcp)',
      #   tls: 'optional - boolean connect to target socket using TLS (defaults to false)',
      #   fuzz_delimeter: 'optional - fuzz delimeter used in request to specify where payloads should reside (defaults to \u2665)',
      #   request: 'required - String object of socket request w/ \u001A as fuzz delimeter (e.g. "GET /\u001A\u001A HTTP/1.1\r\nHost: \u001A127..0.0.1\u001A\r\n\r\n")',
      #   payload: 'required - payload string',
      #   encoding: 'optional - :base64 || :hex || :html_entity || :url (Defaults to nil)',
      #   encoding_depth: 'optional - number of times to encode payload (defaults to 1)',
      #   char_encoding: 'optional - character encoding returned by PWN::Plugins::Char.list_encoders (defaults to UTF-8)',
      #   response_timeout: 'optional - float (defaults to 0.9)',
      #   request_rate_limit: 'optional - float (defaults to 0.3)'
      # )

      public_class_method def self.socket(opts = {})
        target = opts[:target].to_s.scrub
        port = opts[:port].to_i
        protocol = opts[:protocol]
        tls = opts[:tls]
        opts[:encoding].nil? ? encoding = nil : encoding = opts[:encoding].to_s.strip.chomp.scrub.downcase.to_sym
        opts[:encoding_depth].nil? ? encoding_depth = 1 : encoding_depth = opts[:encoding_depth].to_i
        opts[:char_encoding].nil? ? char_encoding = 'UTF-8' : char_encoding = opts[:char_encoding].to_s
        opts[:fuzz_delimeter].nil? ? fuzz_delimeter = "\u2665" : fuzz_delimeter = opts[:fuzz_delimeter]
        request = opts[:request].to_s.encode(char_encoding, 'UTF-8')
        payload = opts[:payload].to_s.encode(char_encoding, 'UTF-8')

        if encoding
          case encoding
          when :base64
            if encoding_depth > 1
              (1..encoding_depth).each do
                payload = Base64.strict_encode64(payload)
              end
            else
              payload = Base64.strict_encode64(payload)
            end
          when :hex
            if encoding_depth > 1
              (1..encoding_depth).each do
                hex_payload = ''
                payload.each_byte { |b| hex_payload = "#{hex_payload}#{format('\x%02x', b)}" }
                payload = hex_payload
              end
            else
              hex_payload = ''
              payload.each_byte { |b| hex_payload = "#{hex_payload}#{format('\x%02x', b)}" }
              payload = hex_payload
            end
          when :html_entity
            if encoding_depth > 1
              (1..encoding_depth).each do
                payload = HTMLEntities.new.encode(payload)
              end
            else
              payload = HTMLEntities.new.encode(payload)
            end
          when :url
            if encoding_depth > 1
              (1..encoding_depth).each do
                payload = CGI.escape(payload)
              end
            else
              payload = CGI.escape(payload)
            end
          else
            raise "Encoding type: #{encoding} not supported."
          end
        end

        opts[:response_timeout].nil? ? response_timeout = 0.9 : response_timeout = opts[:response_timeout].to_f
        opts[:request_rate_limit].nil? ? request_rate_limit = 0.3 : request_rate_limit = opts[:request_rate_limit].to_f
        socket_fuzz_results_arr = []

        # Find fuzz delimeter index numbers in request
        request_delim_index_arr = []
        request.each_char.with_index do |char, char_index|
          request_delim_index_arr.push(char_index) if char == fuzz_delimeter
        end

        # request_delim_index_arr should always return an even length,
        # otherwise the request is missing a fuzz delimeter.
        request_delim_index_arr.each_slice(2).with_index do |placeholder_slice, placeholder_slice_index|
          this_socket_fuzz_result = {}
          begin_delim_char_index_shift_width = placeholder_slice_index * 2
          begin_delim_char_index = placeholder_slice[0].to_i - begin_delim_char_index_shift_width

          end_delim_char_index_shift_width = (placeholder_slice_index * 2) + 2
          end_delim_char_index = placeholder_slice[1].to_i - end_delim_char_index_shift_width

          this_request = request.dup.delete(fuzz_delimeter).encode(char_encoding, 'UTF-8')

          if end_delim_char_index.positive?
            this_request[begin_delim_char_index..end_delim_char_index] = payload
          else
            # begin_delim_char_index should always be 0
            this_request[begin_delim_char_index] = payload
          end

          sock_obj = PWN::Plugins::Sock.connect(
            target: target,
            port: port,
            protocol: protocol,
            tls: tls
          )

          this_socket_fuzz_result[:timestamp] = Time.now.strftime('%Y-%m-%d %H:%M:%S.%9N %z').to_s

          this_socket_fuzz_result[:request] = this_request
          this_socket_fuzz_result[:request_encoding] = this_request.encoding.name
          this_socket_fuzz_result[:request_len] = this_request.length

          # Send Fuzz Payload in its rawest form (as long as it will undump first)
          sock_obj.write(this_request.encode('ASCII-8BIT', undef: :replace).undump)

          does_respond = sock_obj.wait_readable(response_timeout)
          if does_respond
            response = sock_obj.read
            response_len = response.length
            this_socket_fuzz_result[:response] = response.to_s.inspect
            this_socket_fuzz_result[:response_len] = response_len
          else
            this_socket_fuzz_result[:response] = ''
            this_socket_fuzz_result[:response_len] = 0
          end
          sleep request_rate_limit
          sock_obj = PWN::Plugins::Sock.disconnect(sock_obj: sock_obj)
          # TODO: dump into file once array reaches max length (avoid memory consumption issues)
          socket_fuzz_results_arr.push(this_socket_fuzz_result)
        rescue Errno::ECONNRESET => e
          response = e.message
          this_socket_fuzz_result[:response] = response
          this_socket_fuzz_result[:response_len] = response.length

          sleep request_rate_limit
          sock_obj = PWN::Plugins::Sock.disconnect(sock_obj: sock_obj) unless sock_obj.nil?
          # TODO: dump into file once array reaches max length (avoid memory consumption issues)
          socket_fuzz_results_arr.push(this_socket_fuzz_result)

          next
        rescue StandardError => e
          response = "#{e.class}: #{e.message} #{e.backtrace}"
          this_socket_fuzz_result[:response] = response
          this_socket_fuzz_result[:response_len] = response.length

          sleep request_rate_limit
          sock_obj = PWN::Plugins::Sock.disconnect(sock_obj: sock_obj) unless sock_obj.nil?
          # TODO: dump into file once array reaches max length (avoid memory consumption issues)
          socket_fuzz_results_arr.push(this_socket_fuzz_result)

          next
        end

        socket_fuzz_results_arr
      rescue StandardError => e
        raise e
      ensure
        sock_obj = PWN::Plugins::Sock.disconnect(sock_obj: sock_obj) unless sock_obj.nil?
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
          socket_fuzz_results_arr = #{self}.socket(
            target: 'required = target host or ip',
            port: 'required => target port',
            protocol: 'optional => :tcp || :udp (defaults to tcp)',
            tls: 'optional - boolean connect to target socket using TLS (defaults to false)',
            fuzz_delimeter: \"optional - fuzz delimeter used in request to specify where payloads should reside (defaults to \u2665)\",
            request: \"required - String object of socket request w/ \u2665 as fuzz delimeter (e.g. '\"GET /\u2665\u2665 HTTP/1.1\\r\\nHost: \u2665127.0.0.1\u2665\\r\\n\\r\\n\"')\",
            payload: 'required - payload string',
            encoding: 'optional - :base64 || :hex || :html_entity || :url (Defaults to nil)',
            encoding_depth: 'optional - number of times to encode payload (defaults to 1)',
            char_encoding: 'optional - character encoding returned by PWN::Plugins::Char.list_encoders (defaults to UTF-8)',
            response_timeout: 'optional - float (defaults to 0.9)',
            request_rate_limit: 'optional - float (defaults to 0.3)'
          )

          #{self}.authors
        "
      end
    end
  end
end
