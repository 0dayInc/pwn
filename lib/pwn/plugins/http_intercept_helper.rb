# frozen_string_literal: true

module PWN
  module Plugins
    # This plugin was created to generate UTF-8 characters for fuzzing
    module HTTPInterceptHelper
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # request_hash = PWN::Plugins::HTTPInterceptHelper.raw_to_hash(
      #   request_raw: 'required => raw http request string to convert to hash'
      # )

      public_class_method def self.raw_to_hash(opts = {})
        request_raw = opts[:request_raw].to_s
        request_hash = {}

        # Basic Parsing Begins
        raw_intercepted_request_arr = request_raw.split("\r\n")

        # Parse HTTP Protocol Request Line
        raw_request_line_arr = raw_intercepted_request_arr[0].split
        request_hash[:http_method] = raw_request_line_arr[0].to_s.upcase.to_sym
        request_hash[:http_resource_path] = URI.parse(raw_request_line_arr[1])
        request_hash[:http_version] = raw_request_line_arr[-1]

        # Begin Parsing HTTP Headers & Body (If Applicable)
        request_hash[:http_headers] = {}

        case request_hash[:http_method]
        when :CONNECT,
             :DELETE,
             :GET,
             :HEAD,
             :OPTIONS,
             :PATCH,
             :PUT,
             :TRACE
          puts request_hash[:http_method]
        when :POST
          # Parse HTTP Headers
          raw_intercepted_request_arr[1..-1].each do |val|
            break if val == '' # This may cause issues

            key = ''
            val.each_char do |char|
              break if char == ':'

              key = "#{key}#{char}"
            end

            header_val = val.gsub(/^#{key}:/, '').strip

            request_hash[:http_headers][key.to_sym] = header_val
          end

          # Parse HTTP Body
          raw_request_body = []
          raw_intercepted_request_arr[1..-1].each_with_index do |val, index|
            next if val != '' # This may cause issues

            break_index = index + 2
            request_hash[:http_body] = raw_intercepted_request_arr[break_index..-1].join(',')
          end
        else
          raise "HTTP Method: #{request_hash[:http_method]} Currently Unsupported>"
        end

        request_hash
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # request_raw = PWN::Plugins::HTTPInterceptHelper.hash_to_raw(
      #   request_hash: 'required => request_hash object returned by #raw_to_hash method'
      # )

      public_class_method def self.hash_to_raw(opts = {})
        request_hash = opts[:request_hash]

        # Populate HTTP Request Line
        request_raw = "#{request_hash[:http_method]} "
        request_raw = "#{request_raw}#{request_hash[:http_resource_path]} "
        request_raw = "#{request_raw}#{request_hash[:http_version]}\r\n"

        # Populate HTTP Headers
        request_hash[:http_headers].each do |key, header_val|
          request_raw = "#{request_raw}#{key}: #{header_val}\r\n"
        end

        # Populate HTTP Body (If Applicable)
        request_raw = "#{request_raw}\r\n"
        request_raw = "#{request_raw}#{request_hash[:http_body]}" unless request_hash[:http_body] == ''
      rescue StandardError => e
        raise e
      end

      # Author(s):: Jacob Hoopes <jake.hoopes@gmail.com>

      public_class_method def self.authors
        "AUTHOR(S):
          Jacob Hoopes <jake.hoopes@gmail.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          request_hash = PWN::Plugins::HTTPInterceptHelper.raw_to_hash(
            request_raw: 'required => raw http request string to convert to hash'
          )

          request_raw = PWN::Plugins::HTTPInterceptHelper.hash_to_raw(
            request_hash: 'required => request_hash object returned by #raw_to_hash method'
          )
        "
      end
    end
  end
end
