# frozen_string_literal: true

require 'pg'

module PWN
  module Plugins
    # This plugin is a data access object used for interacting w/ PostgreSQL databases.
    module DAOPostgres
      # Supported Method Parameters::
      # PWN::Plugins::DAOPostgres.connect(
      #   host: 'required host or IP',
      #   port: 'optional port (defaults to 5432)',
      #   dbname: 'required database name',
      #   user: 'required username',
      #   password: 'optional (prompts if left blank)',
      #   connect_timeout: 'optional (defaults to 60 seconds)',
      #   options: 'optional postgres options',
      #   tty: 'optional tty',
      #   sslmode: :disable|:allow|:prefer|:require
      # )

      public_class_method def self.connect(opts = {})
        host = opts[:host].to_s

        port = if opts[:port].nil? || opts[:port].zero?
                 5432
               else
                 opts[:port].to_i
               end

        dbname = opts[:dbname].to_s
        user = opts[:user].to_s

        password = if opts[:password].nil?
                     PWN::Plugins::AuthenticationHelper.mask_password
                   else
                     opts[:password].to_s
                   end

        connect_timeout = if opts[:connect_timeout].nil?
                            60
                          else
                            opts[:connect_timeout].to_i
                          end

        options = opts[:options]
        tty = opts[:tty]

        case opts[:sslmode]
        when :disable
          sslmode = 'disable'
        when :allow
          sslmode = 'allow'
        when :prefer
          sslmode = 'prefer'
        when :require
          sslmode = 'require'
        else
          raise "Error: Invalid :sslmode => #{opts[:sslmode]}. Valid params are :disable, :allow, :prefer, or :require"
        end

        pg_conn = PG::Connection.new(
          host: host,
          port: port,
          dbname: dbname,
          user: user,
          password: password,
          connect_timeout: connect_timeout,
          options: options,
          tty: tty,
          sslmode: sslmode
        )

        validate_pg_conn(pg_conn: pg_conn)
        pg_conn
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DAOPostgres.sql_statement(
      #   pg_conn: pg_conn,
      #   prepared_statement: 'SELECT * FROM tn_users WHERE state = $1',
      #   statement_params: ['Active']
      # )

      public_class_method def self.sql_statement(opts = {})
        pg_conn = opts[:pg_conn]
        validate_pg_conn(pg_conn: pg_conn)
        prepared_statement = opts[:prepared_statement] # Can also be leveraged for 'select * from user;'
        statement_params = opts[:statement_params] # << Array of Params
        raise "Error: :statement_params => #{statement_params.class}. Pass as an Array object" unless statement_params.instance_of?(Array) || statement_params.nil?

        if statement_params.nil?
          pg_conn.exec(prepared_statement)
        else
          pg_conn.exec(prepared_statement, statement_params)
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # Method Parameters Not Implemented

      # public

      # def self.list_all_schemas_by_host(opts = {})
      # end

      # Supported Method Parameters::
      # Method Parameters Not Implemented

      # public

      # def self.list_all_databases_by_schema(opts = {})
      # end

      # Supported Method Parameters::
      # Method Parameters Not Implemented

      # public

      # def self.list_all_tables_by_database(opts = {})
      # end

      # Supported Method Parameters::
      # PWN::Plugins::DAOPostgres.list_all_columns_by_table(
      #   pg_conn: pg_conn,
      #   schema: 'required schema name',
      #   table_name: 'required table name'
      # )

      public_class_method def self.list_all_columns_by_table(opts = {})
        pg_conn = opts[:pg_conn]
        validate_pg_conn(pg_conn: pg_conn)

        table_schema = opts[:table_schema].to_s
        table_name = opts[:table_name].to_s

        prep_sql = "
          SELECT * FROM information_schema.columns
          WHERE table_schema = $1
          AND table_name = $2
        "

        sql_statement(
          pg_conn: pg_conn,
          prepared_statement: prep_sql,
          statement_params: [table_schema, table_name]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::DAOPostgres.disconnect(
      #   pg_conn: pg_conn
      # )

      public_class_method def self.disconnect(opts = {})
        pg_conn = opts[:pg_conn]
        validate_pg_conn(pg_conn: pg_conn)
        pg_conn.close
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # validate_pg_conn(
      #   pg_conn: pg_conn
      # )

      private_class_method def self.validate_pg_conn(opts = {})
        pg_conn = opts[:pg_conn]
        raise "Error: Invalid pg_conn Object #{pg_conn}" unless pg_conn.instance_of?(PG::Connection)
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
          pg_conn = #{self}.connect(
            host: 'required host or IP',
            port: 'optional port (defaults to 5432)',
            dbname: 'required database name',
            user: 'required username',
            password: 'optional (prompts if left blank)',
            connect_timeout: 'optional (defaults to 60 seconds)',
            options: 'optional postgres options',
            tty: 'optional tty',
            sslmode: :disable|:allow|:prefer|:require
          )

          res = #{self}.sql_statement(
            pg_conn: pg_conn,
            prepared_statement: 'SELECT * FROM tn_users WHERE state = $1',
            statement_params: ['Active']
          )

          res = #{self}.list_all_columns_by_table(
            pg_conn: pg_conn,
            schema: 'required schema name',
            table_name: 'required table name'
          )

          #{self}.disconnect(pg_conn: pg_conn)

          #{self}.authors
        "
      end
    end
  end
end
