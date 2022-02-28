# frozen_string_literal: true

require 'mongo'

module PWN
  module Plugins
    # This plugin needs additional development, however, its intent is to be
    # used as a data access object for interacting w/ MongoDB
    module DAOMongo
      # Supported Method Parameters::
      # PWN::Plugins::DAOMongo.connect(
      #   host: 'optional host or IP defaults to 127.0.0.1',
      #   port: 'optional port defaults to 27017',
      #   database: 'optional database name'
      # )

      public_class_method def self.connect(opts = {})
        # Set host
        host = if opts[:host].nil?
                 '127.0.0.1' # Defaults to localhost
               else
                 opts[:host].to_s
               end

        # Set port
        port = if opts[:port].nil?
                 27_017 # Defaults to TCP port 27017
               else
                 opts[:port].to_i
               end

        database = opts[:database].to_s.scrub

        if opts[:database].nil?
          mongo_conn = Mongo::Client.new(["#{host}:#{port}"])
        else
          mongo_conn = Mongo::Client.new(["#{host}:#{port}"], database: database)
        end

        validate_mongo_conn(mongo_conn: mongo_conn)
        mongo_conn
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DAOMongo.disconnect(
      #   mongo_conn: mongo_conn
      # )

      public_class_method def self.disconnect(opts = {})
        mongo_conn = opts[:mongo_conn]
        validate_mongo_conn(mongo_conn: mongo_conn)
        mongo_conn.close
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # validate_mongo_conn(
      #   :mongo_conn => mongo_conn
      # )

      private_class_method def self.validate_mongo_conn(opts = {})
        mongo_conn = opts[:mongo_conn]
        raise "Error: Invalid mongo_conn Object #{mongo_conn}" unless mongo_conn.instance_of?(Mongo::Client)
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
          mongo_conn = #{self}.connect(
            host: 'optional host or IP defaults to 127.0.0.1',
            port: 'optional port defaults to 27017',
            database: 'optional database name'
          )

          #{self}.disconnect(mongo_conn: mongo_conn)

          #{self}.authors
        "
      end
    end
  end
end
