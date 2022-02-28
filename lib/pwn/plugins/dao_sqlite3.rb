# frozen_string_literal: true

require 'sqlite3'

module PWN
  module Plugins
    # This plugin is a data access object used for interacting w/ SQLite3
    # databases.
    module DAOSQLite3
      # Supported Method Parameters::
      # PWN::Plugins::DAOSQLite3.connect(
      #   db_path: 'Required - Path of SQLite3 DB File'
      # )

      public_class_method def self.connect(opts = {})
        db_path = opts[:db_path]

        sqlite3_conn = SQLite3::Database.new(db_path)
        sqlite3_conn.results_as_hash = true
        # Be sure to enable foreign key support for each connection
        sql_enable_fk = 'PRAGMA foreign_keys = ON;'
        res = sql_statement(
          sqlite3_conn: sqlite3_conn,
          prepared_statement: sql_enable_fk
        )
        # TODO: better handling since sqlite3 gem always returns SQLite3::Database
        # whether DB exists or not
        unless sqlite3_conn.instance_of?(SQLite3::Database)
          raise "
            Connection Error - class should be SQLite3::Database...received:
            sqlite3_conn = #{sqlite3_conn.inspect}
            sqlite3_conn.class = #{sqlite3_conn.class}
          "
        end

        sqlite3_conn
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # validate_sqlite3_conn(
      #   sqlite3_conn: sqlite3_conn
      # )

      private_class_method def self.validate_sqlite3_conn(opts = {})
        sqlite3_conn = opts[:sqlite3_conn]
        raise "Error: Invalid sqlite3_conn Object #{sqlite3_conn}" unless sqlite3_conn.instance_of?(SQLite3::Database)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DAOSQLite3.sql_statement(
      #   sqlite3_conn: sqlite3_conn,
      #   prepared_statement: 'SELECT * FROM tn_users WHERE state = ?;',
      #   statement_params: ['Active']
      # )

      public_class_method def self.sql_statement(opts = {})
        sqlite3_conn = opts[:sqlite3_conn]
        validate_sqlite3_conn(sqlite3_conn: sqlite3_conn)
        prepared_statement = opts[:prepared_statement] # Can also be leveraged for 'select * from user;'
        statement_params = opts[:statement_params] # << Array of Params
        raise "Error: :statement_params => #{statement_params.class}. Pass as an Array object" unless statement_params.instance_of?(Array) || statement_params.nil?

        begin
          if statement_params.nil?
            res = sqlite3_conn.execute(prepared_statement)
          else
            res = sqlite3_conn.execute(prepared_statement, statement_params)
          end
        rescue SQLite3::BusyException
          puts 'Database In Use - Retrying...'
          sleep 0.3
          retry
        end

        res
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DAOSQLite3.disconnect(
      #   sqlite3_conn: sqlite3_conn
      # )

      public_class_method def self.disconnect(opts = {})
        sqlite3_conn = opts[:sqlite3_conn]
        validate_sqlite3_conn(sqlite3_conn: sqlite3_conn)

        sqlite3_conn.close
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
          sqlite3_conn = #{self}.connect(db_path: 'Required - Path of SQLite3 DB File')

          res = #{self}.sql_statement(
            sqlite3_conn: sqlite3_conn,
            prepared_statement: 'SELECT * FROM tn_users WHERE state = ?;',
            statement_params: ['Active']
          )

          #{self}.disconnect(:sqlite3_conn => sqlite3_conn)

          #{self}.authors
        "
      end
    end
  end
end
